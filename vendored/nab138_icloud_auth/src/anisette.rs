use crate::Error;
use omnisette::{obf, AnisetteConfiguration, AnisetteHeaders};
use std::{collections::HashMap, time::SystemTime};

#[derive(Debug, Clone)]
pub struct AnisetteData {
    pub base_headers: HashMap<String, String>,
    pub generated_at: SystemTime,
    pub config: AnisetteConfiguration,
}

impl AnisetteData {
    /// Fetches the data at an anisette server
    pub async fn new(config: AnisetteConfiguration) -> Result<Self, crate::Error> {
        let mut b = AnisetteHeaders::get_anisette_headers_provider(config.clone())?;
        let base_headers = b.provider.get_authentication_headers().await?;

        Ok(AnisetteData {
            base_headers,
            generated_at: SystemTime::now(),
            config,
        })
    }

    /// Fresh data after the anisette server resyncs the machine with `sim`,
    /// the X-Apple-I-MD-DATA Apple sends with hsc 434.
    pub async fn resync(&self, sim: &str) -> Result<Self, crate::Error> {
        let mut b = AnisetteHeaders::get_anisette_headers_provider(self.config.clone())?;
        let base_headers = b.provider.resync_authentication_headers(sim).await?;

        Ok(AnisetteData {
            base_headers,
            generated_at: SystemTime::now(),
            config: self.config.clone(),
        })
    }

    pub fn needs_refresh(&self) -> bool {
        let elapsed = self.generated_at.elapsed().unwrap();
        elapsed.as_secs() > 60
    }

    pub fn is_valid(&self) -> bool {
        let elapsed = self.generated_at.elapsed().unwrap();
        elapsed.as_secs() < 90
    }

    pub async fn refresh(&self) -> Result<Self, crate::Error> {
        Self::new(self.config.clone()).await
    }

    pub fn generate_headers(
        &self,
        cpd: bool,
        client_info: bool,
        app_info: bool,
    ) -> HashMap<String, String> {
        if !self.is_valid() {
            panic!("Invalid data!")
        }
        let mut headers = self.base_headers.clone();
        let old_client_info = headers.remove("X-Mme-Client-Info");
        if client_info {
            let client_info = match old_client_info {
                // Apple's GSA edge returns HTTP 503 for any client info
                // containing com.apple.dt.Xcode (since September 2026), so
                // that one is reported as akd, the daemon that really sends
                // this request. Any other identity goes out as the anisette
                // server reported it.
                Some(v) if v.contains("com.apple.dt.Xcode") => {
                    let temp = v.as_str();
                    temp.replace(
                        temp.split('<').nth(3).unwrap().split('>').nth(0).unwrap(),
                        obf!("com.apple.AuthKit/1 (com.apple.akd/1.0)"),
                    )
                }
                Some(v) => v,
                None => {
                    return headers;
                }
            };
            headers.insert(
                obf!("X-Mme-Client-Info").to_string(),
                client_info.to_owned(),
            );
        }

        if app_info {
            headers.insert(
                obf!("X-Apple-App-Info").to_string(),
                obf!("com.apple.gs.xcode.auth").to_string(),
            );
            headers.insert(
                obf!("X-Xcode-Version").to_string(),
                obf!("11.2 (11B41)").to_string(),
            );
        }

        if cpd {
            headers.insert(obf!("bootstrap").to_string(), obf!("true").to_string());
            headers.insert(obf!("icscrec").to_string(), obf!("true").to_string());
            headers.insert(obf!("loc").to_string(), obf!("en_GB").to_string());
            headers.insert(obf!("pbe").to_string(), obf!("false").to_string());
            headers.insert(obf!("prkgen").to_string(), obf!("true").to_string());
            headers.insert(obf!("svct").to_string(), obf!("iCloud").to_string());
        }

        headers
    }

    pub fn to_plist(&self, cpd: bool, client_info: bool, app_info: bool) -> plist::Dictionary {
        let mut plist = plist::Dictionary::new();
        for (key, value) in self.generate_headers(cpd, client_info, app_info).iter() {
            plist.insert(key.to_owned(), plist::Value::String(value.to_owned()));
        }

        plist
    }

    pub fn get_header(&self, header: &str) -> Result<String, Error> {
        let headers = self
            .generate_headers(true, true, true)
            .iter()
            .map(|(k, v)| (k.to_lowercase(), v.to_lowercase()))
            .collect::<HashMap<String, String>>();

        match headers.get(&header.to_lowercase()) {
            Some(v) => Ok(v.to_string()),
            None => Err(Error::Parse),
        }
    }
}
