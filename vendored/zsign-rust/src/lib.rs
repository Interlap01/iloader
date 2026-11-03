#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr;

use thiserror::Error;

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

#[derive(Debug, Default)]
pub struct ZSignOptions {
    pub input_path: String,

    pub cert_file: Option<String>,
    pub pkey_file: Option<String>,
    pub prov_file: Option<String>,
    pub password: Option<String>,
    pub adhoc: bool,
    pub sha256_only: bool,

    pub bundle_id: Option<String>,
    pub bundle_name: Option<String>,
    pub bundle_version: Option<String>,
    pub entitlements_file: Option<String>,

    pub dylib_files: Vec<String>,
    pub weak_inject: bool,

    pub force: bool,
    pub check_signature: bool,
    pub temp_folder: Option<String>,

    pub debug: bool,
    pub quiet: bool,
    pub enable_cache: bool,

    /// Nested bundles (app extensions) signed with their own profile and
    /// entitlements instead of the app's; empty signs every bundle with the
    /// app's, as before.
    pub bundles: Vec<ZSignBundle>,
}

/// ZSignBundle is a nested bundle's own signing: its CFBundleIdentifier, its
/// profile, and an entitlements file (None for the profile's).
#[derive(Debug, Clone, Default)]
pub struct ZSignBundle {
    pub bundle_id: String,
    pub prov_file: String,
    pub entitlements_file: Option<String>,
}

#[derive(Debug, Clone, Error)]
pub enum ZSignError {
    #[error("Invalid input parameters")]
    InvalidInput,
    #[error("Signing operation failed")]
    SigningFailed,
    #[error("File is not signed")]
    NotSigned,
    #[error("Unknown error, code {0}")]
    Unknown(i32),
}

impl ZSignOptions {
    pub fn new<S: Into<String>>(input_path: S) -> Self {
        Self {
            input_path: input_path.into(),
            enable_cache: true,
            ..Default::default()
        }
    }

    pub fn with_adhoc_signing(mut self) -> Self {
        self.adhoc = true;
        self
    }

    pub fn with_cert_file<S: Into<String>>(mut self, cert_file: S) -> Self {
        self.cert_file = Some(cert_file.into());
        self
    }

    pub fn with_pkey_file<S: Into<String>>(mut self, pkey_file: S) -> Self {
        self.pkey_file = Some(pkey_file.into());
        self
    }

    pub fn with_prov_file<S: Into<String>>(mut self, prov_file: S) -> Self {
        self.prov_file = Some(prov_file.into());
        self
    }

    pub fn with_password<S: Into<String>>(mut self, password: S) -> Self {
        self.password = Some(password.into());
        self
    }

    pub fn with_bundle_id<S: Into<String>>(mut self, bundle_id: S) -> Self {
        self.bundle_id = Some(bundle_id.into());
        self
    }

    pub fn with_bundle_name<S: Into<String>>(mut self, bundle_name: S) -> Self {
        self.bundle_name = Some(bundle_name.into());
        self
    }

    pub fn with_bundle_version<S: Into<String>>(mut self, bundle_version: S) -> Self {
        self.bundle_version = Some(bundle_version.into());
        self
    }

    pub fn with_entitlements_file<S: Into<String>>(mut self, entitlements_file: S) -> Self {
        self.entitlements_file = Some(entitlements_file.into());
        self
    }

    pub fn with_temp_folder<S: Into<String>>(mut self, temp_folder: S) -> Self {
        self.temp_folder = Some(temp_folder.into());
        self
    }

    pub fn with_weak_inject(mut self) -> Self {
        self.weak_inject = true;
        self
    }

    pub fn with_force(mut self) -> Self {
        self.force = true;
        self
    }

    pub fn with_check_signature(mut self) -> Self {
        self.check_signature = true;
        self
    }

    pub fn with_quiet(mut self) -> Self {
        self.quiet = true;
        self
    }

    pub fn with_debug(mut self) -> Self {
        self.debug = true;
        self
    }

    pub fn with_disable_cache(mut self) -> Self {
        self.enable_cache = false;
        self
    }

    pub fn add_dylib<S: Into<String>>(mut self, dylib_path: S) -> Self {
        self.dylib_files.push(dylib_path.into());
        self
    }

    /// with_bundle signs the nested bundle bundle_id (an app extension) with
    /// its own profile and entitlements (None for the profile's), with the
    /// app's certificate and key, and puts that profile in it.
    pub fn with_bundle<S: Into<String>>(mut self, bundle_id: S, prov_file: S, entitlements_file: Option<S>) -> Self {
        self.bundles.push(ZSignBundle {
            bundle_id: bundle_id.into(),
            prov_file: prov_file.into(),
            entitlements_file: entitlements_file.map(Into::into),
        });
        self
    }

    pub fn sign(&self) -> Result<(), ZSignError> {
        let input_path = CString::new(self.input_path.clone()).unwrap();
        let cert_file = self
            .cert_file
            .as_ref()
            .map(|s| CString::new(s.clone()).unwrap());
        let pkey_file = self
            .pkey_file
            .as_ref()
            .map(|s| CString::new(s.clone()).unwrap());
        let prov_file = self
            .prov_file
            .as_ref()
            .map(|s| CString::new(s.clone()).unwrap());
        let password = self
            .password
            .as_ref()
            .map(|s| CString::new(s.clone()).unwrap());
        let bundle_id = self
            .bundle_id
            .as_ref()
            .map(|s| CString::new(s.clone()).unwrap());
        let bundle_name = self
            .bundle_name
            .as_ref()
            .map(|s| CString::new(s.clone()).unwrap());
        let bundle_version = self
            .bundle_version
            .as_ref()
            .map(|s| CString::new(s.clone()).unwrap());
        let entitlements_file = self
            .entitlements_file
            .as_ref()
            .map(|s| CString::new(s.clone()).unwrap());
        let temp_folder = self
            .temp_folder
            .as_ref()
            .map(|s| CString::new(s.clone()).unwrap());

        let dylib_cstrings: Vec<CString> = self
            .dylib_files
            .iter()
            .map(|s| CString::new(s.clone()).unwrap())
            .collect();
        let mut dylib_ptrs: Vec<*const c_char> =
            dylib_cstrings.iter().map(|cs| cs.as_ptr()).collect();

        let bundle_ids: Vec<CString> = self.bundles.iter().map(|b| CString::new(b.bundle_id.clone()).unwrap()).collect();
        let bundle_provs: Vec<CString> = self.bundles.iter().map(|b| CString::new(b.prov_file.clone()).unwrap()).collect();
        let bundle_ents: Vec<Option<CString>> = self
            .bundles
            .iter()
            .map(|b| b.entitlements_file.as_ref().map(|s| CString::new(s.clone()).unwrap()))
            .collect();
        let mut bundle_id_ptrs: Vec<*const c_char> = bundle_ids.iter().map(|cs| cs.as_ptr()).collect();
        let mut bundle_prov_ptrs: Vec<*const c_char> = bundle_provs.iter().map(|cs| cs.as_ptr()).collect();
        let mut bundle_ent_ptrs: Vec<*const c_char> = bundle_ents
            .iter()
            .map(|cs| cs.as_ref().map_or(ptr::null(), |s| s.as_ptr()))
            .collect();
        let or_null = |v: &mut Vec<*const c_char>| if v.is_empty() { ptr::null_mut() } else { v.as_mut_ptr() };

        unsafe {
            let result = sign_ipa_with_bundles(
                input_path.as_ptr(),
                cert_file.as_ref().map_or(ptr::null(), |s| s.as_ptr()),
                pkey_file.as_ref().map_or(ptr::null(), |s| s.as_ptr()),
                prov_file.as_ref().map_or(ptr::null(), |s| s.as_ptr()),
                password.as_ref().map_or(ptr::null(), |s| s.as_ptr()),
                if self.adhoc { 1 } else { 0 },
                if self.sha256_only { 1 } else { 0 },
                bundle_id.as_ref().map_or(ptr::null(), |s| s.as_ptr()),
                bundle_name.as_ref().map_or(ptr::null(), |s| s.as_ptr()),
                bundle_version.as_ref().map_or(ptr::null(), |s| s.as_ptr()),
                entitlements_file
                    .as_ref()
                    .map_or(ptr::null(), |s| s.as_ptr()),
                if dylib_ptrs.is_empty() {
                    ptr::null_mut()
                } else {
                    dylib_ptrs.as_mut_ptr()
                },
                dylib_ptrs.len() as i32,
                if self.weak_inject { 1 } else { 0 },
                if self.force { 1 } else { 0 },
                if self.check_signature { 1 } else { 0 },
                temp_folder.as_ref().map_or(ptr::null(), |s| s.as_ptr()),
                if self.debug { 1 } else { 0 },
                if self.quiet { 1 } else { 0 },
                if self.enable_cache { 1 } else { 0 },
                or_null(&mut bundle_id_ptrs),
                or_null(&mut bundle_prov_ptrs),
                or_null(&mut bundle_ent_ptrs),
                self.bundles.len() as i32,
            );

            match result {
                0 => Ok(()),
                -1 => Err(ZSignError::SigningFailed),
                -2 => Err(ZSignError::NotSigned),
                code => Err(ZSignError::Unknown(code)),
            }
        }
    }
}

pub fn get_version() -> String {
    unsafe {
        let version_ptr = get_zsign_version();
        let version_cstr = CStr::from_ptr(version_ptr);
        version_cstr.to_str().unwrap().to_string()
    }
}
