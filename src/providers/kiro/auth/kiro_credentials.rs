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
    pub expires: u64,           // ms since epoch
    pub region: String,
    pub auth_method: KiroAuthMethod,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub client_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub client_secret: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_arn: Option<String>,
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
        };
        let json = serde_json::to_value(&creds).unwrap();
        assert_eq!(json["authMethod"].as_str(), None); // no rename on the field itself
        assert_eq!(json["auth_method"], "desktop");
    }
}
