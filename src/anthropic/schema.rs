use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessagesRequest {
    pub model: Option<String>,
    #[serde(default)]
    pub max_tokens: Option<u32>,
    #[serde(default)]
    pub messages: Vec<Message>,
    #[serde(default)]
    pub stream: bool,
    #[serde(skip)]
    pub bypass_provider_model_override: bool,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl MessagesRequest {
    /// True when Claude Code fast mode is on. Claude Code then sends
    /// `speed: "fast"` in the request body, and only for Opus model names.
    pub fn wants_fast_speed(&self) -> bool {
        self.extra.get("speed").and_then(serde_json::Value::as_str) == Some("fast")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub role: String,
    pub content: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CountTokensResponse {
    pub input_tokens: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(extra: serde_json::Value) -> MessagesRequest {
        let mut body = serde_json::json!({"model":"claude-opus-5-5","messages":[]});
        body.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        serde_json::from_value(body).unwrap()
    }

    #[test]
    fn wants_fast_speed_only_for_speed_fast() {
        assert!(request(serde_json::json!({"speed":"fast"})).wants_fast_speed());
        assert!(!request(serde_json::json!({})).wants_fast_speed());
        assert!(!request(serde_json::json!({"speed":"standard"})).wants_fast_speed());
        assert!(!request(serde_json::json!({"speed":true})).wants_fast_speed());
    }
}
