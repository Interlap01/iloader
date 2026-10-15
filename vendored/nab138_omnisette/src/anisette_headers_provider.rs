use std::collections::HashMap;

use crate::AnisetteError;

#[async_trait::async_trait]
pub trait AnisetteHeadersProvider: Send + Sync {
    async fn get_anisette_headers(
        &mut self,
        skip_provisioning: bool,
    ) -> Result<HashMap<String, String>, AnisetteError>;

    async fn get_authentication_headers(
        &mut self,
    ) -> Result<HashMap<String, String>, AnisetteError> {
        let headers = self.get_anisette_headers(false).await?;
        Ok(self.normalize_headers(headers))
    }

    /// Headers after a resync with `sim`, the X-Apple-I-MD-DATA Apple sends
    /// with hsc 434. A provider without resync support returns fresh headers.
    async fn resync_authentication_headers(
        &mut self,
        _sim: &str,
    ) -> Result<HashMap<String, String>, AnisetteError> {
        self.get_authentication_headers().await
    }

    /// Normalizes headers to ensure that all the required headers are given.
    fn normalize_headers(
        &mut self,
        mut headers: HashMap<String, String>,
    ) -> HashMap<String, String> {
        if let Some(client_info) = headers.remove("X-MMe-Client-Info") {
            headers.insert("X-Mme-Client-Info".to_string(), client_info);
        }

        headers
    }
}
