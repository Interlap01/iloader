#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int sign_ipa(
    const char* input_path,
    
    const char* cert_file,
    const char* pkey_file,
    const char* prov_file,
    const char* password,
    int adhoc,
    int sha256_only,
    
    const char* bundle_id,
    const char* bundle_name,
    const char* bundle_version,
    const char* entitlements_file, 
    
    const char** dylib_files,
    int dylib_count,
    int weak_inject,
    
    int force,
    int check_signature,
    const char* temp_folder,
    
    int debug,
    int quiet,
    int enable_cache
);

// sign_ipa_with_bundles is sign_ipa, and signs each nested bundle named in
// bundle_ids (an app extension) with its own profile and entitlements (NULL
// or "" for the profile's) instead of the app's, putting that profile in it.
int sign_ipa_with_bundles(
    const char* input_path,

    const char* cert_file,
    const char* pkey_file,
    const char* prov_file,
    const char* password,
    int adhoc,
    int sha256_only,

    const char* bundle_id,
    const char* bundle_name,
    const char* bundle_version,
    const char* entitlements_file,

    const char** dylib_files,
    int dylib_count,
    int weak_inject,

    int force,
    int check_signature,
    const char* temp_folder,

    int debug,
    int quiet,
    int enable_cache,

    const char** bundle_ids,
    const char** bundle_prov_files,
    const char** bundle_entitlements_files,
    int bundle_count
);

const char* get_zsign_version();

#ifdef __cplusplus
}
#endif
