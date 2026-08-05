//! Wires [`FileAuthStore`] to Kiro's provider auth file paths. Mirrors
//! Kimi's `file_store()` (Task-2-research item 3), but uses the **generic**
//! path helpers (`crate::paths::provider_auth_file`/`provider_legacy_auth_file`)
//! instead of dedicated `kiro_auth_file()`/legacy functions, per the plan's
//! Global Constraints.

use super::kiro_credentials::KiroCredentials;
use crate::auth::FileAuthStore;

pub fn file_store() -> FileAuthStore<KiroCredentials> {
    let primary = crate::paths::provider_auth_file("kiro");
    let legacy = crate::paths::provider_legacy_auth_file("kiro");
    FileAuthStore::new(
        primary.to_string_lossy().to_string(),
        legacy.to_string_lossy().to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::AuthStorage;

    #[test]
    fn file_store_paths_are_scoped_to_kiro() {
        let store = file_store();
        assert!(store.path().contains("kiro"));
    }
}
