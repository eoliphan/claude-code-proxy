use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KiroAuthMethod {
    Idc,
    Desktop,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KiroCredentials {
    pub access: String,
    pub refresh: String,
    pub expires: u64, // ms since epoch
    pub region: String,
    pub auth_method: KiroAuthMethod,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub client_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub client_secret: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_arn: Option<String>,
    /// How many ms were already subtracted from the real AWS expiry to
    /// produce `expires`, at whichever source constructed this credential:
    /// 0 for kiro-cli-sourced credentials (which store the raw, un-buffered
    /// expiry), 2 minutes for Kiro IDE-sourced tokens, 5 minutes for this
    /// proxy's own direct refresh and device-code login. `KiroAuthManager`'s
    /// Layer 5 graceful-degradation fallback uses this to reconstruct each
    /// credential's true AWS expiry (`expires + expiry_buffer_ms`) instead
    /// of assuming a single universal buffer applies to every source.
    /// `#[serde(default)]` so credentials persisted before this field
    /// existed deserialize to 0 (the safe, no-buffer-assumed value).
    #[serde(default)]
    pub expiry_buffer_ms: u64,
}

impl KiroCredentials {
    pub fn is_expired(&self, now_ms: u64) -> bool {
        self.expires <= now_ms
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_expired_true_when_now_past_expiry() {
        let creds = KiroCredentials {
            access: "a".into(),
            refresh: "r".into(),
            expires: 1000,
            region: "us-east-1".into(),
            auth_method: KiroAuthMethod::Idc,
            client_id: String::new(),
            client_secret: String::new(),
            profile_arn: None,
            expiry_buffer_ms: 0,
        };
        assert!(creds.is_expired(1000));
        assert!(creds.is_expired(1001));
        assert!(!creds.is_expired(999));
    }

    #[test]
    fn serializes_auth_method_lowercase() {
        let creds = KiroCredentials {
            access: "a".into(),
            refresh: "r".into(),
            expires: 1000,
            region: "us-east-1".into(),
            auth_method: KiroAuthMethod::Desktop,
            client_id: String::new(),
            client_secret: String::new(),
            profile_arn: None,
            expiry_buffer_ms: 0,
        };
        let json = serde_json::to_value(&creds).unwrap();
        assert_eq!(json["authMethod"].as_str(), None); // no rename on the field itself
        assert_eq!(json["auth_method"], "desktop");
    }

    #[test]
    fn expiry_buffer_ms_defaults_to_zero_for_pre_existing_persisted_json() {
        // Backward compat: credentials persisted before `expiry_buffer_ms`
        // existed must still deserialize, defaulting to 0 -- the safe value
        // that makes KiroAuthManager's Layer 5 assume no hidden buffer
        // rather than falsely claiming one.
        let legacy_json = r#"{
            "access": "a",
            "refresh": "r",
            "expires": 1000,
            "region": "us-east-1",
            "auth_method": "idc"
        }"#;
        let creds: KiroCredentials = serde_json::from_str(legacy_json).unwrap();
        assert_eq!(creds.expiry_buffer_ms, 0);
    }
}
