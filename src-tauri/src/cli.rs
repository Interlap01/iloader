//! CLI interface for iloader - sideload iOS apps with your Apple ID
//!
//! This is a standalone CLI that reuses the isideload library.

use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use idevice::{
    lockdown::LockdownClient,
    provider::UsbmuxdProvider,
    usbmuxd::{Connection, UsbmuxdAddr, UsbmuxdConnection},
    IdeviceService,
};
use isideload::{
    developer_session::{DeveloperDeviceType, DeveloperSession},
    sideload::sideload_app,
    AnisetteConfiguration, AppleAccount, SideloadConfiguration,
};
use keyring::Entry;
use serde::Serialize;
use zip::write::SimpleFileOptions;
use zsign_rust::ZSignOptions;

const KEYRING_SERVICE: &str = "iloader-cli";
const KEYRING_DEFAULT_EMAIL: &str = "default_email";

// ============================================================================
// JSON Output Types
// ============================================================================

#[derive(Serialize)]
struct JsonOutput {
    #[serde(rename = "type")]
    output_type: String,
    step: Option<u32>,
    total_steps: Option<u32>,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    bundle_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    output_ipa: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    team_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    profile_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cert_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    key_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl JsonOutput {
    fn progress(step: u32, total: u32, message: &str) -> Self {
        Self {
            output_type: "progress".to_string(),
            step: Some(step),
            total_steps: Some(total),
            message: message.to_string(),
            bundle_id: None,
            output_ipa: None,
            team_id: None,
            profile_path: None,
            cert_path: None,
            key_path: None,
            error: None,
        }
    }

    fn tfa_required() -> Self {
        Self {
            output_type: "2fa_required".to_string(),
            step: None,
            total_steps: None,
            message: "Two-factor authentication required. Enter code on stdin.".to_string(),
            bundle_id: None,
            output_ipa: None,
            team_id: None,
            profile_path: None,
            cert_path: None,
            key_path: None,
            error: None,
        }
    }

    fn complete(
        bundle_id: &str,
        output_ipa: &str,
        team_id: &str,
        profile_path: Option<&str>,
        cert_path: Option<&str>,
        key_path: Option<&str>,
    ) -> Self {
        Self {
            output_type: "complete".to_string(),
            step: Some(7),
            total_steps: Some(7),
            message: "Signing complete".to_string(),
            bundle_id: Some(bundle_id.to_string()),
            output_ipa: Some(output_ipa.to_string()),
            team_id: Some(team_id.to_string()),
            profile_path: profile_path.map(str::to_string),
            cert_path: cert_path.map(str::to_string),
            key_path: key_path.map(str::to_string),
            error: None,
        }
    }

    fn error(message: &str) -> Self {
        Self {
            output_type: "error".to_string(),
            step: None,
            total_steps: None,
            message: message.to_string(),
            bundle_id: None,
            output_ipa: None,
            team_id: None,
            profile_path: None,
            cert_path: None,
            key_path: None,
            error: Some(message.to_string()),
        }
    }

    fn print(&self) {
        if let Ok(json) = serde_json::to_string(self) {
            println!("{}", json);
        }
    }
}

/// Output helper that switches between text and JSON modes
struct Output {
    json_mode: bool,
}

impl Output {
    fn new(json_mode: bool) -> Self {
        Self { json_mode }
    }

    fn progress(&self, step: u32, total: u32, message: &str) {
        if self.json_mode {
            JsonOutput::progress(step, total, message).print();
        } else {
            println!("\n[{}/{}] {}...", step, total, message);
        }
    }

    fn success(&self, message: &str) {
        if !self.json_mode {
            println!("✓ {}", message);
        }
    }

    fn info(&self, message: &str) {
        if !self.json_mode {
            println!("  {}", message);
        }
    }

    fn complete(
        &self,
        bundle_id: &str,
        output_ipa: &str,
        team_id: &str,
        profile_path: Option<&str>,
        cert_path: Option<&str>,
        key_path: Option<&str>,
    ) {
        if self.json_mode {
            JsonOutput::complete(bundle_id, output_ipa, team_id, profile_path, cert_path, key_path)
                .print();
        } else {
            println!("\n✓ Signed output saved to: {}", output_ipa);
            if !bundle_id.is_empty() {
                println!("\nNote: Bundle ID changed to: {}", bundle_id);
            }
            if let Some(p) = profile_path {
                println!("Provisioning profile: {}", p);
            }
            println!("This signature is valid for 7 days and must be renewed after expiration.");
        }
    }

    fn error(&self, message: &str) {
        if self.json_mode {
            JsonOutput::error(message).print();
        } else {
            eprintln!("Error: {}", message);
        }
    }

}

/// `iloader-cli --version` prints "iloader-cli build N protocol P (iloader X)".
/// Hosts parse the build and the protocol from it. The protocol is the
/// contract with the host that runs the CLI (arguments and the JSON lines on
/// stdout): bump it on any change a host would have to know about, since a
/// host only runs a downloaded CLI whose protocol it speaks.
const CLI_VERSION: &str = concat!(
    "build ",
    env!("ILOADER_CLI_BUILD"),
    " protocol 1 (iloader ",
    env!("CARGO_PKG_VERSION"),
    ")"
);

#[derive(Parser)]
#[command(name = "iloader-cli")]
#[command(about = "Sideload iOS apps with your Apple ID", long_about = None)]
#[command(version = CLI_VERSION)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// List connected iOS devices
    Devices,

    /// Login to Apple ID and save credentials
    Login {
        /// Apple ID email
        #[arg(short, long)]
        email: String,

        /// Anisette server URL (without https://)
        #[arg(long, default_value = "ani.sidestore.io")]
        anisette_server: String,
    },

    /// Logout and clear saved credentials
    Logout {
        /// Apple ID email to logout (or all if not specified)
        #[arg(short, long)]
        email: Option<String>,
    },

    /// Sideload an IPA to a device
    Sideload {
        /// Path to the IPA file
        #[arg(short, long)]
        ipa: PathBuf,

        /// Apple ID email
        #[arg(short, long)]
        email: String,

        /// Device UUID (use 'devices' command to list)
        #[arg(short, long)]
        device: String,

        /// Anisette server URL (without https://)
        #[arg(long, default_value = "ani.sidestore.io")]
        anisette_server: String,
    },

    /// List development certificates
    Certificates {
        /// Apple ID email (uses cached if not provided)
        #[arg(short, long)]
        email: Option<String>,

        /// Apple ID password (uses cached or prompts if not provided)
        #[arg(short, long)]
        password: Option<String>,

        /// Anisette server URL (without https://)
        #[arg(long, default_value = "ani.sidestore.io")]
        anisette_server: String,
    },

    /// Revoke a development certificate
    RevokeCert {
        /// Apple ID email (uses cached if not provided)
        #[arg(short, long)]
        email: Option<String>,

        /// Apple ID password (uses cached or prompts if not provided)
        #[arg(short = 'P', long)]
        password: Option<String>,

        /// Certificate serial number to revoke
        #[arg(short, long)]
        serial: String,

        /// Anisette server URL (without https://)
        #[arg(long, default_value = "ani.sidestore.io")]
        anisette_server: String,
    },

    /// Sign an IPA file (without installing)
    Sign {
        /// Path to the IPA file (omit when using --file)
        #[arg(short, long, conflicts_with = "file")]
        ipa: Option<PathBuf>,

        /// Path to a standalone Mach-O / dylib to sign in place (instead of an IPA).
        /// Requires --cert, --key and --profile (or use online IPA signing instead).
        #[arg(long, conflicts_with = "ipa")]
        file: Option<PathBuf>,

        /// Apple ID email (uses saved email if not provided)
        #[arg(short, long)]
        email: Option<String>,

        /// Apple ID password (uses cached or prompts if not provided)
        #[arg(short, long)]
        password: Option<String>,

        /// Device UUID(s) to include in provisioning profile (comma-separated).
        /// Required for online signing; ignored when reusing a profile or signing a file.
        #[arg(short, long, value_delimiter = ',')]
        devices: Vec<String>,

        /// Output path for signed IPA (defaults to <original>-signed.ipa)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Reuse an existing provisioning profile (offline mode, skips all Apple calls).
        /// Pair with --cert and --key.
        #[arg(long)]
        profile: Option<PathBuf>,

        /// Certificate PEM to sign with (offline mode / --file)
        #[arg(long)]
        cert: Option<PathBuf>,

        /// Private key PEM to sign with (offline mode / --file)
        #[arg(long)]
        key: Option<PathBuf>,

        /// Anisette server URL (without https://)
        #[arg(long, default_value = "ani.sidestore.io")]
        anisette_server: String,

        /// Output JSON instead of text (for integration with other tools)
        #[arg(long)]
        json: bool,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Devices => {
            list_devices().await?;
        }
        Commands::Login {
            email,
            anisette_server,
        } => {
            let account = login_interactive(&email, &anisette_server, true).await?;
            // Save as default email
            if let Err(e) = save_default_email(&email) {
                eprintln!("Warning: Could not save default email: {}", e);
            }
            println!("✓ Successfully logged in as {}", account.apple_id);
            println!("  Credentials saved to keyring for future use.");
        }
        Commands::Logout { email } => {
            logout(email.as_deref())?;
        }
        Commands::Sideload {
            ipa,
            email,
            device,
            anisette_server,
        } => {
            sideload(&ipa, &email, &device, &anisette_server).await?;
        }
        Commands::Certificates {
            email,
            password,
            anisette_server,
        } => {
            list_certificates(email.as_deref(), password.as_deref(), &anisette_server).await?;
        }
        Commands::RevokeCert {
            email,
            password,
            serial,
            anisette_server,
        } => {
            revoke_certificate(email.as_deref(), password.as_deref(), &serial, &anisette_server).await?;
        }
        Commands::Sign {
            ipa,
            file,
            email,
            password,
            devices,
            output,
            profile,
            cert,
            key,
            anisette_server,
            json,
        } => {
            if let Some(file) = file {
                sign_file(&file, cert.as_ref(), key.as_ref(), profile.as_ref(), output.as_ref(), json)?;
            } else if let Some(ipa) = ipa {
                sign_ipa(
                    &ipa,
                    email.as_deref(),
                    password.as_deref(),
                    &devices,
                    output.as_ref(),
                    &anisette_server,
                    json,
                    profile.as_ref(),
                    cert.as_ref(),
                    key.as_ref(),
                )
                .await?;
            } else {
                let out = Output::new(json);
                out.error("Either --ipa or --file must be provided");
                return Err("Either --ipa or --file must be provided".into());
            }
        }
    }

    Ok(())
}

// ============================================================================
// Keyring helpers
// ============================================================================

fn get_keyring_entry(email: &str) -> Result<Entry, keyring::Error> {
    Entry::new(KEYRING_SERVICE, &email.to_lowercase())
}

fn save_password(email: &str, password: &str) -> Result<(), Box<dyn std::error::Error>> {
    let entry = get_keyring_entry(email)?;
    entry.set_password(password)?;
    Ok(())
}

fn get_cached_password(email: &str) -> Option<String> {
    get_keyring_entry(email)
        .ok()
        .and_then(|e| e.get_password().ok())
}

fn delete_password(email: &str) -> Result<(), Box<dyn std::error::Error>> {
    let entry = get_keyring_entry(email)?;
    entry.delete_credential()?;
    Ok(())
}

fn save_default_email(email: &str) -> Result<(), Box<dyn std::error::Error>> {
    let entry = Entry::new(KEYRING_SERVICE, KEYRING_DEFAULT_EMAIL)?;
    entry.set_password(email)?;
    Ok(())
}

fn get_default_email() -> Option<String> {
    Entry::new(KEYRING_SERVICE, KEYRING_DEFAULT_EMAIL)
        .ok()
        .and_then(|e| e.get_password().ok())
}

fn delete_default_email() -> Result<(), Box<dyn std::error::Error>> {
    let entry = Entry::new(KEYRING_SERVICE, KEYRING_DEFAULT_EMAIL)?;
    entry.delete_credential()?;
    Ok(())
}

// ============================================================================
// Login functions
// ============================================================================

fn get_config_dir() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("iloader-cli")
}

/// Try to login with cached credentials, fall back to interactive if needed
async fn login_cached_or_interactive(
    email: &str,
    anisette_server: &str,
) -> Result<Arc<AppleAccount>, Box<dyn std::error::Error>> {
    // First, try cached password
    if let Some(cached_password) = get_cached_password(email) {
        println!("Using cached credentials for {}...", email);
        match do_login(email, &cached_password, anisette_server).await {
            Ok(account) => {
                println!("✓ Logged in as {}", email);
                return Ok(account);
            }
            Err(e) => {
                let err_str = e.to_string();
                // Check if it's a credentials error vs other error
                if err_str.contains("password") || err_str.contains("credentials") || err_str.contains("authentication") {
                    println!("Cached credentials expired or invalid. Please login again.");
                    // Delete invalid cached password
                    let _ = delete_password(email);
                } else {
                    // Non-auth error, propagate it
                    return Err(e);
                }
            }
        }
    }

    // No cached password or it was invalid, do interactive login
    login_interactive(email, anisette_server, true).await
}

/// Login with optional email/password - uses provided creds or cached, NO interactive prompts
async fn login_with_optional_creds(
    email: Option<&str>,
    password: Option<&str>,
    anisette_server: &str,
) -> Result<Arc<AppleAccount>, Box<dyn std::error::Error>> {
    // If both email and password provided, use them directly
    if let (Some(email), Some(password)) = (email, password) {
        println!("Using provided credentials...");
        let account = do_login(email, password, anisette_server).await?;
        println!("✓ Logged in as {}", email);
        return Ok(account);
    }

    // No credentials provided - use cached from keychain
    let default_email = get_default_email()
        .ok_or("No cached email found. Run 'sign' command first to cache credentials.")?;

    let cached_password = get_cached_password(&default_email)
        .ok_or("No cached password found. Run 'sign' command first to cache credentials.")?;

    println!("Using cached credentials for {}...", default_email);
    let account = do_login(&default_email, &cached_password, anisette_server).await?;
    println!("✓ Logged in as {}", default_email);
    Ok(account)
}

/// Interactive login that prompts for password
async fn login_interactive(
    email: &str,
    anisette_server: &str,
    save_credentials: bool,
) -> Result<Arc<AppleAccount>, Box<dyn std::error::Error>> {
    let password = rpassword::prompt_password(format!("Password for {}: ", email))?;

    let account = do_login(email, &password, anisette_server).await?;

    if save_credentials {
        if let Err(e) = save_password(email, &password) {
            eprintln!("Warning: Could not save credentials to keyring: {}", e);
        }
    }

    Ok(account)
}

/// Core login function
async fn do_login(
    email: &str,
    password: &str,
    anisette_server: &str,
) -> Result<Arc<AppleAccount>, Box<dyn std::error::Error>> {
    do_login_with_json(email, password, anisette_server, false).await
}

/// Core login function with optional JSON mode for 2FA
async fn do_login_with_json(
    email: &str,
    password: &str,
    anisette_server: &str,
    json_mode: bool,
) -> Result<Arc<AppleAccount>, Box<dyn std::error::Error>> {
    let tfa_closure = move || -> Result<String, String> {
        if json_mode {
            // In JSON mode, output JSON and read code from stdin
            JsonOutput::tfa_required().print();
            std::io::stdout().flush().map_err(|e| e.to_string())?;

            let mut code = String::new();
            std::io::stdin()
                .lock()
                .read_line(&mut code)
                .map_err(|e| format!("Failed to read 2FA code from stdin: {}", e))?;
            Ok(code.trim().to_string())
        } else {
            println!("\n2FA required. Check your trusted devices for the verification code.");
            rpassword::prompt_password("Enter 2FA code: ")
                .map_err(|e| format!("Failed to read 2FA code: {}", e))
        }
    };

    let config_dir = get_config_dir();
    std::fs::create_dir_all(&config_dir)?;

    let config = AnisetteConfiguration::default()
        .set_configuration_path(config_dir)
        .set_anisette_url_v3(format!("https://{}", anisette_server));

    let email_clone = email.to_lowercase();
    let password_clone = password.to_string();

    let account = AppleAccount::login(
        move || Ok((email_clone.clone(), password_clone.clone())),
        tfa_closure,
        config,
    )
    .await
    .map_err(|e| format!("Login failed: {}", e))?;

    Ok(Arc::new(account))
}

// ============================================================================
// Commands
// ============================================================================

fn logout(email: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    match email {
        Some(e) => {
            match delete_password(e) {
                Ok(_) => {
                    println!("✓ Logged out {}", e);
                    // Also clear default email if it matches
                    if let Some(default) = get_default_email() {
                        if default.to_lowercase() == e.to_lowercase() {
                            let _ = delete_default_email();
                            println!("  Cleared default email");
                        }
                    }
                }
                Err(_) => println!("No saved credentials found for {}", e),
            }
        }
        None => {
            // Logout from default email if exists
            if let Some(default_email) = get_default_email() {
                let _ = delete_password(&default_email);
                let _ = delete_default_email();
                println!("✓ Logged out {} (default account)", default_email);
            } else {
                println!("No default account saved. Specify email with --email to logout a specific account.");
                println!("Example: iloader-cli logout --email user@example.com");
            }
        }
    }
    Ok(())
}

async fn list_devices() -> Result<(), Box<dyn std::error::Error>> {
    let mut usbmuxd = UsbmuxdConnection::default().await?;
    let devices = usbmuxd.get_devices().await?;

    if devices.is_empty() {
        println!("No devices connected");
        return Ok(());
    }

    println!("Connected devices:");
    println!("{:<40} {:<30} {}", "UUID", "Name", "Connection");
    println!("{}", "-".repeat(80));

    for device in devices {
        let provider = device.to_provider(UsbmuxdAddr::from_env_var().unwrap(), "iloader-cli");
        let connection_type = match device.connection_type {
            Connection::Usb => "USB",
            Connection::Network(_) => "Network",
            Connection::Unknown(_) => "Unknown",
        };

        let name = match LockdownClient::connect(&provider).await {
            Ok(mut lockdown) => lockdown
                .get_value(Some("DeviceName"), None)
                .await
                .ok()
                .and_then(|v| v.as_string().map(|s| s.to_string()))
                .unwrap_or_else(|| "Unknown".to_string()),
            Err(_) => "Unknown".to_string(),
        };

        println!("{:<40} {:<30} {}", device.udid, name, connection_type);
    }

    Ok(())
}

async fn get_device_provider(uuid: &str) -> Result<UsbmuxdProvider, Box<dyn std::error::Error>> {
    let mut usbmuxd = UsbmuxdConnection::default().await?;
    let device = usbmuxd.get_device(uuid).await?;
    let provider = device.to_provider(UsbmuxdAddr::from_env_var().unwrap(), "iloader-cli");
    Ok(provider)
}

async fn sideload(
    ipa_path: &PathBuf,
    email: &str,
    device_uuid: &str,
    anisette_server: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if !ipa_path.exists() {
        return Err(format!("IPA file not found: {}", ipa_path.display()).into());
    }

    println!("Logging in...");
    let account = login_cached_or_interactive(email, anisette_server).await?;

    println!("Getting developer session...");
    let mut dev_session = DeveloperSession::new(account);
    let teams = dev_session.list_teams().await?;
    if teams.is_empty() {
        return Err("No developer teams found".into());
    }
    dev_session.set_team(teams[0].clone());
    println!("✓ Using team: {}", teams[0]._name);

    println!("Connecting to device {}...", device_uuid);
    let provider = get_device_provider(device_uuid).await?;
    println!("✓ Connected to device");

    let config_dir = get_config_dir();

    let config = SideloadConfiguration::default()
        .set_machine_name("iloader-cli".to_string())
        .set_store_dir(config_dir);

    println!("Sideloading {}...", ipa_path.display());
    sideload_app(&provider, &dev_session, ipa_path.clone(), config)
        .await
        .map_err(|e| match e {
            isideload::Error::Certificate(s) if s == "You have too many certificates!" => {
                "You have too many certificates. Use 'certificates' command to list and 'revoke-cert' to revoke one.".to_string()
            }
            _ => e.to_string(),
        })?;

    println!("✓ Successfully sideloaded {}", ipa_path.display());
    Ok(())
}

async fn list_certificates(
    email: Option<&str>,
    password: Option<&str>,
    anisette_server: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Logging in...");
    let account = login_with_optional_creds(email, password, anisette_server).await?;

    let mut dev_session = DeveloperSession::new(account);
    let teams = dev_session.list_teams().await?;
    if teams.is_empty() {
        return Err("No developer teams found".into());
    }
    dev_session.set_team(teams[0].clone());

    let team = dev_session.get_team().await?;
    let certs = dev_session
        .list_all_development_certs(DeveloperDeviceType::Ios, &team)
        .await?;

    if certs.is_empty() {
        println!("No development certificates found");
        return Ok(());
    }

    println!("\nDevelopment certificates:");
    println!(
        "{:<20} {:<40} {:<20}",
        "Serial Number", "Name", "Machine"
    );
    println!("{}", "-".repeat(80));

    for cert in certs {
        println!(
            "{:<20} {:<40} {:<20}",
            cert.serial_number, cert.name, cert.machine_name
        );
    }

    Ok(())
}

async fn revoke_certificate(
    email: Option<&str>,
    password: Option<&str>,
    serial: &str,
    anisette_server: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Logging in...");
    let account = login_with_optional_creds(email, password, anisette_server).await?;

    let mut dev_session = DeveloperSession::new(account);
    let teams = dev_session.list_teams().await?;
    if teams.is_empty() {
        return Err("No developer teams found".into());
    }
    dev_session.set_team(teams[0].clone());

    let team = dev_session.get_team().await?;
    dev_session
        .revoke_development_cert(DeveloperDeviceType::Ios, &team, serial)
        .await?;

    println!("✓ Revoked certificate with serial number: {}", serial);
    Ok(())
}

/// Login for signing - tries cached credentials first, prompts if needed
/// Returns (account, email) on success
async fn login_for_signing(
    email: Option<&str>,
    password: Option<&str>,
    anisette_server: &str,
    json_mode: bool,
    out: &Output,
) -> Result<(Arc<AppleAccount>, String), Box<dyn std::error::Error>> {
    // Determine which email to use
    let email_to_use = match email {
        Some(e) => Some(e.to_string()),
        None => get_default_email(),
    };

    // If we have an email (provided or saved), try cached credentials first
    if let Some(ref email_str) = email_to_use {
        // If password explicitly provided, use it
        if let Some(pwd) = password {
            match do_login_with_json(email_str, pwd, anisette_server, json_mode).await {
                Ok(account) => {
                    // Save credentials for future use
                    let _ = save_password(email_str, pwd);
                    let _ = save_default_email(email_str);
                    return Ok((account, email_str.clone()));
                }
                Err(e) => {
                    out.error(&format!("Login failed: {}", e));
                    return Err(e);
                }
            }
        }

        // Try cached password
        if let Some(cached_pwd) = get_cached_password(email_str) {
            if !json_mode {
                println!("Using cached credentials for {}...", email_str);
            }
            match do_login_with_json(email_str, &cached_pwd, anisette_server, json_mode).await {
                Ok(account) => {
                    // Update default email
                    let _ = save_default_email(email_str);
                    return Ok((account, email_str.clone()));
                }
                Err(e) => {
                    let err_str = e.to_string();
                    if err_str.contains("password") || err_str.contains("credentials") || err_str.contains("authentication") {
                        if !json_mode {
                            println!("Cached credentials invalid or expired.");
                        }
                        let _ = delete_password(email_str);
                    } else {
                        // Non-auth error, propagate
                        out.error(&format!("Login failed: {}", e));
                        return Err(e);
                    }
                }
            }
        }
    }

    // No cached credentials or they failed - need to prompt
    if json_mode {
        // In JSON mode, we can't prompt interactively
        out.error("No valid cached credentials. Please provide --email and --password flags, or run 'iloader-cli login' first.");
        return Err("No valid cached credentials".into());
    }

    // Interactive login
    let email_str = match email_to_use {
        Some(e) => e,
        None => {
            print!("Apple ID email: ");
            std::io::stdout().flush()?;
            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;
            input.trim().to_string()
        }
    };

    let pwd = rpassword::prompt_password(format!("Password for {}: ", email_str))?;

    let account = do_login_with_json(&email_str, &pwd, anisette_server, false).await?;

    // Save credentials for future use
    if let Err(e) = save_password(&email_str, &pwd) {
        eprintln!("Warning: Could not save password to keyring: {}", e);
    }
    if let Err(e) = save_default_email(&email_str) {
        eprintln!("Warning: Could not save email to keyring: {}", e);
    }

    Ok((account, email_str))
}

#[allow(clippy::too_many_arguments)]
async fn sign_ipa(
    ipa_path: &PathBuf,
    email: Option<&str>,
    password: Option<&str>,
    device_uuids: &[String],
    output_path: Option<&PathBuf>,
    anisette_server: &str,
    json_mode: bool,
    reuse_profile: Option<&PathBuf>,
    reuse_cert: Option<&PathBuf>,
    reuse_key: Option<&PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    use isideload::certificate::CertificateIdentity;
    use std::fs::File;
    use zip::ZipArchive;

    let out = Output::new(json_mode);

    validate_ipa_file(ipa_path, &out)?;

    // Offline fast-path: a provisioning profile + cert + key were supplied, so
    // re-sign locally with zsign and skip every Apple round-trip. The caller is
    // responsible for having checked the profile is still valid for the device.
    if let (Some(profile), Some(cert), Some(key)) = (reuse_profile, reuse_cert, reuse_key) {
        return sign_ipa_offline(ipa_path, output_path, profile, cert, key, &out);
    }

    if device_uuids.is_empty() {
        out.error("At least one device UUID is required for signing");
        return Err("At least one device UUID is required for signing".into());
    }

    // Determine output path
    let output = match output_path {
        Some(p) => p.clone(),
        None => {
            let stem = ipa_path.file_stem().unwrap_or_default().to_string_lossy();
            ipa_path.with_file_name(format!("{}-signed.ipa", stem))
        }
    };

    out.info(&format!("Signing {} for {} device(s)...", ipa_path.display(), device_uuids.len()));

    // Step 1: Login - try cached credentials first, then prompt if needed
    out.progress(1, 7, "Logging in");
    let (account, used_email) = login_for_signing(email, password, anisette_server, json_mode, &out).await?;
    out.success(&format!("Logged in as {}", used_email));

    // Step 2: Get developer session and team
    out.progress(2, 7, "Getting developer session");
    let mut dev_session = DeveloperSession::new(account.clone());
    let teams = match dev_session.list_teams().await {
        Ok(t) => t,
        Err(e) => {
            out.error(&format!("Failed to list teams: {}", e));
            return Err(e.into());
        }
    };
    if teams.is_empty() {
        out.error("No developer teams found");
        return Err("No developer teams found".into());
    }
    dev_session.set_team(teams[0].clone());
    let team = dev_session.get_team().await?;
    out.success(&format!("Using team: {} ({})", team._name, team.team_id));

    // Step 3: Register devices
    out.progress(3, 7, "Registering devices");
    let existing_devices = match dev_session
        .list_devices(DeveloperDeviceType::Ios, &team)
        .await {
        Ok(d) => d,
        Err(e) => {
            out.error(&format!("Failed to list devices: {}", e));
            return Err(e.into());
        }
    };

    for uuid in device_uuids {
        let uuid_trimmed = uuid.trim();
        if !existing_devices.iter().any(|d| d.device_number == uuid_trimmed) {
            out.info(&format!("Registering device {}...", uuid_trimmed));
            if let Err(e) = dev_session
                .add_device(DeveloperDeviceType::Ios, &team, &format!("Device-{}", &uuid_trimmed[..8.min(uuid_trimmed.len())]), uuid_trimmed)
                .await {
                out.error(&format!("Failed to register device {}: {}", uuid_trimmed, e));
                return Err(e.into());
            }
        } else {
            out.info(&format!("Device {} already registered", uuid_trimmed));
        }
    }
    out.success("All devices registered");

    // Step 4: Get/create certificate
    out.progress(4, 7, "Getting certificate");
    let config_dir = get_config_dir();
    std::fs::create_dir_all(&config_dir)?;

    let cert = match CertificateIdentity::new(
        &config_dir,
        &dev_session,
        account.apple_id.clone(),
        "iloader-cli".to_string(),
    )
    .await {
        Ok(c) => c,
        Err(e) => {
            let err_msg = if e.to_string().contains("too many certificates") {
                "You have too many certificates. Use 'certificates' command to list and 'revoke-cert' to revoke one.".to_string()
            } else {
                e.to_string()
            };
            out.error(&err_msg);
            return Err(err_msg.into());
        }
    };
    out.success(&format!("Certificate ready (serial: {})", cert.get_serial_number()?));

    // Step 5: Extract and prepare IPA
    out.progress(5, 7, "Extracting IPA");
    let temp_dir = std::env::temp_dir().join(format!(
        "iloader-sign-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs()
    ));
    if temp_dir.exists() {
        std::fs::remove_dir_all(&temp_dir)?;
    }
    std::fs::create_dir_all(&temp_dir)?;

    let file = File::open(ipa_path)?;
    let mut archive = ZipArchive::new(file)?;
    archive.extract(&temp_dir)?;

    // Find the .app directory
    let payload_dir = temp_dir.join("Payload");
    let app_dirs: Vec<_> = std::fs::read_dir(&payload_dir)?
        .filter_map(Result::ok)
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "app"))
        .collect();

    if app_dirs.is_empty() {
        std::fs::remove_dir_all(&temp_dir)?;
        out.error("No .app directory found in IPA");
        return Err("No .app directory found in IPA".into());
    }

    let app_dir = app_dirs[0].path();
    out.info(&format!("Extracted to {}", app_dir.display()));

    // Read bundle info
    let info_plist_path = app_dir.join("Info.plist");
    let info_plist: plist::Value = plist::from_file(&info_plist_path)?;
    let bundle_id = info_plist
        .as_dictionary()
        .and_then(|d| d.get("CFBundleIdentifier"))
        .and_then(|v| v.as_string())
        .ok_or("Failed to read bundle identifier")?;
    let bundle_name = info_plist
        .as_dictionary()
        .and_then(|d| d.get("CFBundleName").or(d.get("CFBundleDisplayName")))
        .and_then(|v| v.as_string())
        .unwrap_or("App");

    // Create the new bundle ID with team suffix (if not already present)
    let new_bundle_id = if bundle_id.ends_with(&format!(".{}", team.team_id)) {
        bundle_id.to_string()
    } else {
        format!("{}.{}", bundle_id, team.team_id)
    };
    out.info(&format!("Bundle: {} -> {}", bundle_id, new_bundle_id));

    // Step 6: Register App ID and get provisioning profile
    out.progress(6, 7, "Getting provisioning profile");

    // Check if app ID exists
    let app_ids_response = dev_session
        .list_app_ids(DeveloperDeviceType::Ios, &team)
        .await?;

    let app_id_exists = app_ids_response
        .app_ids
        .iter()
        .any(|a| a.identifier == new_bundle_id);

    if !app_id_exists {
        out.info(&format!("Registering App ID: {}", new_bundle_id));
        dev_session
            .add_app_id(DeveloperDeviceType::Ios, &team, bundle_name, &new_bundle_id)
            .await?;
    }

    // Get the app ID object
    let app_ids_response = dev_session
        .list_app_ids(DeveloperDeviceType::Ios, &team)
        .await?;
    let app_id = app_ids_response
        .app_ids
        .iter()
        .find(|a| a.identifier == new_bundle_id)
        .ok_or("Failed to find registered App ID")?;

    // Download provisioning profile
    let provisioning_profile = dev_session
        .download_team_provisioning_profile(DeveloperDeviceType::Ios, &team, app_id)
        .await?;

    let profile_path = config_dir.join(format!("{}.mobileprovision", new_bundle_id));
    std::fs::write(&profile_path, &provisioning_profile.encoded_profile)?;
    out.success("Provisioning profile saved");

    // Update Info.plist with new bundle ID
    let mut info_dict = info_plist.into_dictionary().unwrap();
    info_dict.insert(
        "CFBundleIdentifier".to_string(),
        plist::Value::String(new_bundle_id.clone()),
    );
    plist::to_file_xml(&info_plist_path, &plist::Value::Dictionary(info_dict))?;

    // Step 7: Sign with zsign
    out.progress(7, 7, "Signing app");
    if let Err(e) = ZSignOptions::new(app_dir.to_str().unwrap())
        .with_cert_file(cert.get_certificate_file_path().to_str().unwrap())
        .with_pkey_file(cert.get_private_key_file_path().to_str().unwrap())
        .with_prov_file(profile_path.to_str().unwrap())
        .with_force()
        .with_disable_cache()
        .with_quiet()
        .sign() {
        out.error(&format!("Signing failed: {}", e));
        std::fs::remove_dir_all(&temp_dir)?;
        return Err(format!("Signing failed: {}", e).into());
    }
    out.success("App signed");

    // Repack IPA
    out.info("Repacking IPA...");
    repack_ipa(&temp_dir, &output)?;

    // Cleanup
    std::fs::remove_dir_all(&temp_dir)?;

    // Output completion. Surface the cached cert/key/profile paths so callers can
    // copy them next to the IPA and reuse them for an offline re-sign later.
    let output_str = output.to_string_lossy().to_string();
    let cert_str = cert.get_certificate_file_path().to_string_lossy().to_string();
    let key_str = cert.get_private_key_file_path().to_string_lossy().to_string();
    let profile_str = profile_path.to_string_lossy().to_string();
    out.complete(
        &new_bundle_id,
        &output_str,
        &team.team_id,
        Some(&profile_str),
        Some(&cert_str),
        Some(&key_str),
    );

    Ok(())
}

/// Repacks a prepared Payload temp dir into a zipped IPA at `output`.
/// Shared by the online and offline signing paths.
fn repack_ipa(
    temp_dir: &std::path::Path,
    output: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::fs::File;
    use walkdir::WalkDir;

    let output_file = File::create(output)?;
    let mut zip_writer = zip::ZipWriter::new(output_file);
    let options =
        SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);

    // Collect all entries first, then sort so directories precede their contents.
    let mut entries: Vec<_> = WalkDir::new(temp_dir)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
        .collect();
    entries.sort_by(|a, b| a.path().cmp(b.path()));

    for entry in entries {
        let path = entry.path();
        let relative_path = match path.strip_prefix(temp_dir) {
            Ok(p) => p,
            Err(_) => continue,
        };
        if relative_path.as_os_str().is_empty() {
            continue;
        }

        // ZIP format requires forward slashes per spec (APPNOTE.TXT 4.4.17).
        let relative_str = relative_path.to_string_lossy().replace('\\', "/");

        if entry.path_is_symlink() {
            if let Ok(target) = std::fs::read_link(path) {
                let symlink_options = SimpleFileOptions::default()
                    .compression_method(zip::CompressionMethod::Stored);
                zip_writer.start_file(relative_str.clone(), symlink_options)?;
                zip_writer.write_all(target.to_string_lossy().as_bytes())?;
            }
            continue;
        }

        if path.is_dir() {
            zip_writer.add_directory(format!("{}/", relative_str), options)?;
        } else if path.is_file() {
            zip_writer.start_file(relative_str, options)?;
            match File::open(path) {
                Ok(mut file) => {
                    std::io::copy(&mut file, &mut zip_writer)?;
                }
                Err(e) => {
                    eprintln!("Warning: Could not read file {}: {}", path.display(), e);
                }
            }
        }
    }

    zip_writer.finish()?;
    Ok(())
}

/// Validates that `ipa_path` is a regular file containing a zip/IPA archive. A
/// directory or non-zip input otherwise surfaces later as a raw EISDIR / parse
/// error that propagates without a JSON `error` line, so callers (and the retry
/// loop) treat a deterministic input mistake as a transient failure. Emits a
/// clean JSON error instead.
fn validate_ipa_file(
    ipa_path: &std::path::Path,
    out: &Output,
) -> Result<(), Box<dyn std::error::Error>> {
    if !ipa_path.exists() {
        out.error(&format!("IPA file not found: {}", ipa_path.display()));
        return Err(format!("IPA file not found: {}", ipa_path.display()).into());
    }
    if !ipa_path.is_file() {
        let msg = format!(
            "IPA path is not a file (expected a .ipa archive, got a directory?): {}",
            ipa_path.display()
        );
        out.error(&msg);
        return Err(msg.into());
    }
    // IPAs are zip archives; check the local-file-header magic ("PK\x03\x04").
    let mut magic = [0u8; 2];
    let looks_like_zip = std::fs::File::open(ipa_path)
        .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut magic))
        .map(|_| &magic == b"PK")
        .unwrap_or(false);
    if !looks_like_zip {
        let msg = format!("IPA is not a valid zip archive: {}", ipa_path.display());
        out.error(&msg);
        return Err(msg.into());
    }
    Ok(())
}

/// Finds the first occurrence of `needle` in `haystack`.
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Extracts the embedded XML plist from a CMS-wrapped .mobileprovision. The plist
/// is stored as cleartext content inside the PKCS7 container, so we slice it out
/// rather than verifying the signature.
fn read_profile_plist(
    profile_path: &std::path::Path,
) -> Result<plist::Value, Box<dyn std::error::Error>> {
    let bytes = std::fs::read(profile_path)?;
    let start = find_subslice(&bytes, b"<?xml").ok_or("no plist found in provisioning profile")?;
    let end_marker = b"</plist>";
    let end = find_subslice(&bytes[start..], end_marker)
        .ok_or("malformed plist in provisioning profile")?
        + start
        + end_marker.len();
    let value: plist::Value = plist::from_bytes(&bytes[start..end])?;
    Ok(value)
}

/// Derives the bundle identifier the app must declare from the profile's
/// application-identifier entitlement (`TEAMID.bundle.id` -> `bundle.id`) along
/// with the team id. Returns `(None, team)` for wildcard profiles.
fn identity_from_profile(profile: &plist::Value) -> (Option<String>, String) {
    let dict = profile.as_dictionary();
    let team_id = dict
        .and_then(|d| d.get("TeamIdentifier"))
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
        .and_then(|v| v.as_string())
        .unwrap_or("")
        .to_string();
    let new_bundle_id = dict
        .and_then(|d| d.get("Entitlements"))
        .and_then(|v| v.as_dictionary())
        .and_then(|e| e.get("application-identifier"))
        .and_then(|v| v.as_string())
        .and_then(|app_id| app_id.strip_prefix(&format!("{}.", team_id)))
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty() && s != "*");
    (new_bundle_id, team_id)
}

/// Re-signs an IPA locally with a previously issued provisioning profile + cert +
/// key, skipping every Apple round-trip. The caller must have already verified
/// the profile is still valid for the target device.
fn sign_ipa_offline(
    ipa_path: &PathBuf,
    output_path: Option<&PathBuf>,
    profile: &PathBuf,
    cert: &PathBuf,
    key: &PathBuf,
    out: &Output,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::fs::File;
    use zip::ZipArchive;

    for (label, p) in [("profile", profile), ("certificate", cert), ("private key", key)] {
        if !p.exists() {
            out.error(&format!("{} not found: {}", label, p.display()));
            return Err(format!("{} not found: {}", label, p.display()).into());
        }
    }

    let output = match output_path {
        Some(p) => p.clone(),
        None => {
            let stem = ipa_path.file_stem().unwrap_or_default().to_string_lossy();
            ipa_path.with_file_name(format!("{}-signed.ipa", stem))
        }
    };

    out.progress(1, 3, "Reading provisioning profile");
    let profile_plist = read_profile_plist(profile)?;
    let (profile_bundle_id, team_id) = identity_from_profile(&profile_plist);

    out.progress(2, 3, "Extracting IPA");
    let temp_dir = std::env::temp_dir().join(format!(
        "iloader-offline-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs()
    ));
    if temp_dir.exists() {
        std::fs::remove_dir_all(&temp_dir)?;
    }
    std::fs::create_dir_all(&temp_dir)?;
    let file = File::open(ipa_path)?;
    let mut archive = ZipArchive::new(file)?;
    archive.extract(&temp_dir)?;

    let payload_dir = temp_dir.join("Payload");
    let app_dirs: Vec<_> = std::fs::read_dir(&payload_dir)?
        .filter_map(Result::ok)
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "app"))
        .collect();
    if app_dirs.is_empty() {
        std::fs::remove_dir_all(&temp_dir)?;
        out.error("No .app directory found in IPA");
        return Err("No .app directory found in IPA".into());
    }
    let app_dir = app_dirs[0].path();

    // Align the app's bundle id with the profile's app identifier.
    let info_plist_path = app_dir.join("Info.plist");
    let info_plist: plist::Value = plist::from_file(&info_plist_path)?;
    let orig_bundle_id = info_plist
        .as_dictionary()
        .and_then(|d| d.get("CFBundleIdentifier"))
        .and_then(|v| v.as_string())
        .unwrap_or("")
        .to_string();
    let new_bundle_id = profile_bundle_id.unwrap_or_else(|| {
        if orig_bundle_id.ends_with(&format!(".{}", team_id)) {
            orig_bundle_id.clone()
        } else {
            format!("{}.{}", orig_bundle_id, team_id)
        }
    });
    let mut info_dict = info_plist.into_dictionary().ok_or("invalid Info.plist")?;
    info_dict.insert(
        "CFBundleIdentifier".to_string(),
        plist::Value::String(new_bundle_id.clone()),
    );
    plist::to_file_xml(&info_plist_path, &plist::Value::Dictionary(info_dict))?;

    out.progress(3, 3, "Signing app");
    if let Err(e) = ZSignOptions::new(app_dir.to_str().unwrap())
        .with_cert_file(cert.to_str().unwrap())
        .with_pkey_file(key.to_str().unwrap())
        .with_prov_file(profile.to_str().unwrap())
        .with_force()
        .with_disable_cache()
        .with_quiet()
        .sign()
    {
        std::fs::remove_dir_all(&temp_dir)?;
        out.error(&format!("Offline signing failed: {}", e));
        return Err(format!("Offline signing failed: {}", e).into());
    }

    out.info("Repacking IPA...");
    repack_ipa(&temp_dir, &output)?;
    std::fs::remove_dir_all(&temp_dir)?;

    let output_str = output.to_string_lossy().to_string();
    let profile_str = profile.to_string_lossy().to_string();
    let cert_str = cert.to_string_lossy().to_string();
    let key_str = key.to_string_lossy().to_string();
    out.complete(
        &new_bundle_id,
        &output_str,
        &team_id,
        Some(&profile_str),
        Some(&cert_str),
        Some(&key_str),
    );
    Ok(())
}

/// Signs a standalone Mach-O / dylib in place (or to `output`) with the given
/// cert + key + profile. No Apple calls, no app bundle. zsign only signs a lone
/// Mach-O when a key + profile (or ad-hoc) are present, so the full identity is
/// required to avoid a silent no-op.
fn sign_file(
    file_path: &PathBuf,
    cert: Option<&PathBuf>,
    key: Option<&PathBuf>,
    profile: Option<&PathBuf>,
    output_path: Option<&PathBuf>,
    json_mode: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let out = Output::new(json_mode);

    if !file_path.exists() {
        out.error(&format!("File not found: {}", file_path.display()));
        return Err(format!("File not found: {}", file_path.display()).into());
    }

    let (cert, key, profile) = match (cert, key, profile) {
        (Some(c), Some(k), Some(p)) => (c, k, p),
        _ => {
            out.error("--file signing requires --cert, --key and --profile");
            return Err("--file signing requires --cert, --key and --profile".into());
        }
    };
    for (label, p) in [("certificate", cert), ("private key", key), ("profile", profile)] {
        if !p.exists() {
            out.error(&format!("{} not found: {}", label, p.display()));
            return Err(format!("{} not found: {}", label, p.display()).into());
        }
    }

    // zsign signs the input in place; copy first when a distinct output is asked for.
    let target = match output_path {
        Some(o) if o != file_path => {
            std::fs::copy(file_path, o)?;
            o.clone()
        }
        _ => file_path.clone(),
    };

    out.progress(1, 1, "Signing file");
    if let Err(e) = ZSignOptions::new(target.to_str().unwrap())
        .with_cert_file(cert.to_str().unwrap())
        .with_pkey_file(key.to_str().unwrap())
        .with_prov_file(profile.to_str().unwrap())
        .with_force()
        .with_disable_cache()
        .with_quiet()
        .sign()
    {
        out.error(&format!("File signing failed: {}", e));
        return Err(format!("File signing failed: {}", e).into());
    }

    let target_str = target.to_string_lossy().to_string();
    let profile_str = profile.to_string_lossy().to_string();
    let cert_str = cert.to_string_lossy().to_string();
    let key_str = key.to_string_lossy().to_string();
    out.complete(
        "",
        &target_str,
        "",
        Some(&profile_str),
        Some(&cert_str),
        Some(&key_str),
    );
    Ok(())
}
