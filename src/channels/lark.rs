//! Lark/Feishu channel — HTTP webhook mode (event subscription)
//!
//! This channel operates in webhook mode (push-based) like WhatsApp.
//! Messages are received via the gateway's `/lark` webhook endpoint
//! when Feishu/Lark sends event callbacks.

use super::traits::{Channel, ChannelMessage};
use async_trait::async_trait;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

/// Base URL for Feishu (China) API
const FEISHU_BASE: &str = "https://open.feishu.cn";
/// Base URL for Lark (international) API
const LARK_BASE: &str = "https://open.larksuite.com";

/// Lark/Feishu channel — uses HTTP event subscription (webhook)
///
/// Configure event subscription in Feishu Open Platform with:
/// - Request URL: https://your-domain/lark
/// - Event: im.message.receive_v1 (or P2MessageReceiveV1)
/// - Encryption: optional (not implemented yet; disable in console for plain JSON)
pub struct LarkChannel {
    app_id: String,
    app_secret: String,
    verify_token: String,
    domain: String,
    allowed_users: Vec<String>,
    client: reqwest::Client,
    /// Cached tenant_access_token
    token: tokio::sync::RwLock<Option<(String, Instant)>>,
}

impl LarkChannel {
    pub fn new(
        app_id: String,
        app_secret: String,
        verify_token: String,
        domain: String,
        allowed_users: Vec<String>,
    ) -> Self {
        Self {
            app_id,
            app_secret,
            verify_token,
            domain,
            allowed_users,
            client: reqwest::Client::new(),
            token: tokio::sync::RwLock::new(None),
        }
    }

    fn base_url(&self) -> &str {
        if self.domain.eq_ignore_ascii_case("lark") {
            LARK_BASE
        } else {
            FEISHU_BASE
        }
    }

    fn is_user_allowed(&self, open_id: &str) -> bool {
        self.allowed_users
            .iter()
            .any(|u| u == "*" || u == open_id)
    }

    /// Get verify token for webhook verification
    pub fn verify_token(&self) -> &str {
        &self.verify_token
    }

    /// Obtain tenant_access_token, refreshing if expired (with ~5min buffer)
    async fn get_tenant_access_token(&self) -> anyhow::Result<String> {
        {
            let guard = self.token.read().await;
            if let Some((token, expires_at)) = guard.as_ref() {
                if expires_at.saturating_duration_since(Instant::now()).as_secs() > 300 {
                    return Ok(token.clone());
                }
            }
        }

        let mut guard = self.token.write().await;
        // Double-check after acquiring write lock
        if let Some((token, expires_at)) = guard.as_ref() {
            if expires_at.saturating_duration_since(Instant::now()).as_secs() > 300 {
                return Ok(token.clone());
            }
        }

        let url = format!("{}/open-apis/auth/v3/tenant_access_token/internal", self.base_url());
        let body = serde_json::json!({
            "app_id": self.app_id,
            "app_secret": self.app_secret
        });

        let resp = self
            .client
            .post(&url)
            .json(&body)
            .send()
            .await?;

        let data: serde_json::Value = resp.json().await?;
        let token = data
            .get("tenant_access_token")
            .and_then(|t| t.as_str())
            .ok_or_else(|| anyhow::anyhow!("Lark auth response missing tenant_access_token"))?;
        let expire_secs = data
            .get("expire")
            .and_then(|e| e.as_u64())
            .unwrap_or(7200);

        let expires_at = Instant::now() + Duration::from_secs(expire_secs);
        *guard = Some((token.to_string(), expires_at));
        Ok(token.to_string())
    }

    /// Parse URL verification request — returns Some(challenge) if it's a verification
    pub fn parse_url_verification(payload: &serde_json::Value) -> Option<String> {
        payload
            .get("type")
            .and_then(|t| t.as_str())
            .filter(|t| *t == "url_verification")
            .and_then(|_| payload.get("challenge").and_then(|c| c.as_str()))
            .map(String::from)
    }

    /// Parse event payload and extract messages
    pub fn parse_webhook_payload(&self, payload: &serde_json::Value) -> Vec<ChannelMessage> {
        let mut messages = Vec::new();

        // Event subscription payload (Feishu schema 2.0)
        // { "schema": "2.0", "header": { "event_type": "im.message.receive_v1", ... }, "event": { ... } }
        let Some(header) = payload.get("header") else {
            return messages;
        };
        let Some(event_type) = header.get("event_type").and_then(|e| e.as_str()) else {
            return messages;
        };
        if event_type != "im.message.receive_v1" && event_type != "p2p_im.message.receive_v1" {
            return messages;
        }

        let Some(event) = payload.get("event") else {
            return messages;
        };
        let Some(msg_obj) = event.get("message") else {
            return messages;
        };
        let sender_obj = event.get("sender").and_then(|s| s.get("sender_id"));
        let open_id = sender_obj
            .and_then(|s| s.get("open_id"))
            .and_then(|o| o.as_str())
            .unwrap_or("");

        if !self.is_user_allowed(open_id) {
            tracing::warn!(
                "Lark: ignoring message from unauthorized user: open_id={}. \
                Add to allowed_users in config.toml (ou_xxx format), or use '*' for all.",
                open_id
            );
            return messages;
        }

        let chat_id = msg_obj.get("chat_id").and_then(|c| c.as_str()).unwrap_or("");
        let message_type = msg_obj
            .get("message_type")
            .and_then(|m| m.as_str())
            .unwrap_or("");
        let content_raw = msg_obj.get("content").and_then(|c| c.as_str()).unwrap_or("");

        let content = if message_type == "text" {
            // content is JSON: {"text":"hello"}
            serde_json::from_str::<serde_json::Value>(content_raw)
                .ok()
                .and_then(|c| c.get("text").and_then(|t| t.as_str()).map(String::from))
                .unwrap_or_default()
        } else {
            tracing::debug!("Lark: skipping non-text message type: {}", message_type);
            return messages;
        };

        if content.is_empty() {
            return messages;
        }

        let timestamp = msg_obj
            .get("create_time")
            .and_then(|t| t.as_str())
            .and_then(|t| t.parse::<u64>().ok())
            .unwrap_or_else(|| {
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
            });

        messages.push(ChannelMessage {
            id: Uuid::new_v4().to_string(),
            sender: chat_id.to_string(),
            content,
            channel: "lark".to_string(),
            timestamp,
        });

        messages
    }
}

#[async_trait]
impl Channel for LarkChannel {
    fn name(&self) -> &str {
        "lark"
    }

    async fn send(&self, message: &str, recipient: &str) -> anyhow::Result<()> {
        let token = self.get_tenant_access_token().await?;
        let url = format!(
            "{}/open-apis/im/v1/messages?receive_id_type=chat_id",
            self.base_url()
        );

        let content_json = serde_json::json!({"text": message}).to_string();
        let body = serde_json::json!({
            "receive_id": recipient,
            "msg_type": "text",
            "content": content_json
        });

        let resp = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", token))
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let error_body = resp.text().await.unwrap_or_default();
            tracing::error!("Lark send failed: {} — {}", status, error_body);
            anyhow::bail!("Lark API error: {}", status);
        }

        Ok(())
    }

    async fn listen(&self, _tx: tokio::sync::mpsc::Sender<ChannelMessage>) -> anyhow::Result<()> {
        tracing::info!(
            "Lark channel active (webhook mode). \
            Configure Feishu event subscription to POST to your gateway's /lark endpoint."
        );

        loop {
            tokio::time::sleep(Duration::from_secs(3600)).await;
        }
    }

    async fn health_check(&self) -> bool {
        self.get_tenant_access_token().await.is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_channel() -> LarkChannel {
        LarkChannel::new(
            "cli_test".into(),
            "secret".into(),
            "verify-token".into(),
            "feishu".into(),
            vec!["ou_123".into(), "*".into()],
        )
    }

    #[test]
    fn lark_channel_name() {
        let ch = LarkChannel::new(
            "cli_a".into(),
            "s".into(),
            "v".into(),
            "feishu".into(),
            vec![],
        );
        assert_eq!(ch.name(), "lark");
    }

    #[test]
    fn url_verification_parsed() {
        let payload = serde_json::json!({
            "type": "url_verification",
            "challenge": "ajls384kdjx98XX"
        });
        let ch = LarkChannel::parse_url_verification(&payload);
        assert_eq!(ch, Some("ajls384kdjx98XX".into()));
    }

    #[test]
    fn url_verification_ignores_event() {
        let payload = serde_json::json!({
            "schema": "2.0",
            "header": {"event_type": "im.message.receive_v1"}
        });
        assert!(LarkChannel::parse_url_verification(&payload).is_none());
    }

    #[test]
    fn parse_text_message() {
        let ch = LarkChannel::new(
            "cli_a".into(),
            "s".into(),
            "v".into(),
            "feishu".into(),
            vec!["ou_abc123".into()],
        );
        let payload = serde_json::json!({
            "schema": "2.0",
            "header": {
                "event_type": "im.message.receive_v1",
                "event_id": "evt_xxx"
            },
            "event": {
                "sender": {
                    "sender_id": {
                        "open_id": "ou_abc123",
                        "user_id": "user_xxx"
                    },
                    "sender_type": "user"
                },
                "message": {
                    "message_id": "om_xxx",
                    "chat_id": "oc_yyy",
                    "chat_type": "p2p",
                    "message_type": "text",
                    "content": "{\"text\":\"hello world\"}",
                    "create_time": "1234567890"
                }
            }
        });
        let msgs = ch.parse_webhook_payload(&payload);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].content, "hello world");
        assert_eq!(msgs[0].sender, "oc_yyy");
        assert_eq!(msgs[0].channel, "lark");
    }

    #[test]
    fn parse_unauthorized_user_skipped() {
        let ch = LarkChannel::new(
            "cli_a".into(),
            "s".into(),
            "v".into(),
            "feishu".into(),
            vec!["ou_allowed".into()],
        );
        let payload = serde_json::json!({
            "schema": "2.0",
            "header": {"event_type": "im.message.receive_v1"},
            "event": {
                "sender": {"sender_id": {"open_id": "ou_other"}},
                "message": {
                    "chat_id": "oc_yyy",
                    "message_type": "text",
                    "content": "{\"text\":\"hi\"}"
                }
            }
        });
        let msgs = ch.parse_webhook_payload(&payload);
        assert!(msgs.is_empty());
    }

    #[test]
    fn base_url_feishu() {
        let ch = LarkChannel::new(
            "a".into(),
            "s".into(),
            "v".into(),
            "feishu".into(),
            vec![],
        );
        assert_eq!(ch.base_url(), FEISHU_BASE);
    }

    #[test]
    fn base_url_lark() {
        let ch = LarkChannel::new(
            "a".into(),
            "s".into(),
            "v".into(),
            "lark".into(),
            vec![],
        );
        assert_eq!(ch.base_url(), LARK_BASE);
    }
}
