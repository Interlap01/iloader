fn main() {
    // The CLI's release number, set by the release build (ILOADER_CLI_BUILD=N
    // for tag cli-vN). A host compares it with the build it carries to decide
    // whether a downloaded iloader-cli is newer. Local builds report 0.
    let build = std::env::var("ILOADER_CLI_BUILD").unwrap_or_else(|_| "0".to_string());
    println!("cargo:rustc-env=ILOADER_CLI_BUILD={build}");
    println!("cargo:rerun-if-env-changed=ILOADER_CLI_BUILD");

    #[cfg(feature = "gui")]
    tauri_build::build();
}
