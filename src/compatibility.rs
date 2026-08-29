use crate::secure_fs::hex_sha256;
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::{self, Read};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

const SOURCE: &str = include_str!("../config/compatibility.toml");

#[derive(Debug, Deserialize)]
struct Catalog {
    status: String,
    platform: Platform,
    standalone_cli: Cli,
    desktop: Desktop,
}

#[derive(Debug, Deserialize)]
struct Platform {
    os: String,
    version: String,
    build: String,
    architecture: String,
}

#[derive(Debug, Deserialize)]
struct Cli {
    path: PathBuf,
    payload_path: PathBuf,
    version: String,
    launcher_sha256: String,
    payload_sha256: String,
    certification: String,
}

#[derive(Debug, Deserialize)]
struct Desktop {
    path: PathBuf,
    executable_path: PathBuf,
    embedded_cli_path: PathBuf,
    version: String,
    build: String,
    executable_sha256: String,
    embedded_cli_version: String,
    embedded_cli_sha256: String,
    certification: String,
}

#[derive(Debug, Serialize)]
pub struct CompatibilityReport {
    pub status: String,
    pub mismatches: Vec<String>,
    pub cli_certification: String,
    pub desktop_certification: String,
}

pub fn check_compatibility() -> CompatibilityReport {
    match check() {
        Ok(report) => report,
        Err(error) => CompatibilityReport {
            status: "unverified".into(),
            mismatches: vec![error.to_string()],
            cli_certification: "unknown".into(),
            desktop_certification: "unknown".into(),
        },
    }
}

fn check() -> io::Result<CompatibilityReport> {
    let catalog: Catalog = toml::from_str(SOURCE).map_err(io::Error::other)?;
    let mut mismatches = Vec::new();
    compare(
        "platform name",
        &catalog.platform.os,
        "macOS",
        &mut mismatches,
    );
    compare_command(
        "platform version",
        "/usr/bin/sw_vers",
        &["-productVersion"],
        &catalog.platform.version,
        &mut mismatches,
    );
    compare_command(
        "platform build",
        "/usr/bin/sw_vers",
        &["-buildVersion"],
        &catalog.platform.build,
        &mut mismatches,
    );
    compare_command(
        "architecture",
        "/usr/bin/uname",
        &["-m"],
        &catalog.platform.architecture,
        &mut mismatches,
    );
    compare_hash(
        "standalone launcher",
        &catalog.standalone_cli.path,
        &catalog.standalone_cli.launcher_sha256,
        &mut mismatches,
    );
    compare_hash(
        "standalone payload",
        &catalog.standalone_cli.payload_path,
        &catalog.standalone_cli.payload_sha256,
        &mut mismatches,
    );
    compare_command(
        "standalone version",
        catalog.standalone_cli.path.to_string_lossy().as_ref(),
        &["--version"],
        &format!("codex-cli {}", catalog.standalone_cli.version),
        &mut mismatches,
    );
    compare_hash(
        "desktop executable",
        &catalog.desktop.executable_path,
        &catalog.desktop.executable_sha256,
        &mut mismatches,
    );
    compare_hash(
        "desktop embedded CLI",
        &catalog.desktop.embedded_cli_path,
        &catalog.desktop.embedded_cli_sha256,
        &mut mismatches,
    );
    compare_command(
        "desktop version",
        "/usr/libexec/PlistBuddy",
        &[
            "-c",
            "Print :CFBundleShortVersionString",
            &catalog
                .desktop
                .path
                .join("Contents/Info.plist")
                .to_string_lossy(),
        ],
        &catalog.desktop.version,
        &mut mismatches,
    );
    compare_command(
        "desktop build",
        "/usr/libexec/PlistBuddy",
        &[
            "-c",
            "Print :CFBundleVersion",
            &catalog
                .desktop
                .path
                .join("Contents/Info.plist")
                .to_string_lossy(),
        ],
        &catalog.desktop.build,
        &mut mismatches,
    );
    compare_command(
        "desktop embedded CLI version",
        catalog.desktop.embedded_cli_path.to_string_lossy().as_ref(),
        &["--version"],
        &format!("codex-cli {}", catalog.desktop.embedded_cli_version),
        &mut mismatches,
    );
    let certified = catalog.standalone_cli.certification == "passed"
        && catalog.desktop.certification == "passed";
    let status = if !mismatches.is_empty() {
        "unverified"
    } else if catalog.status != "test-target" || !certified {
        "compatible-not-certified"
    } else {
        "certified"
    };
    Ok(CompatibilityReport {
        status: status.into(),
        mismatches,
        cli_certification: catalog.standalone_cli.certification,
        desktop_certification: catalog.desktop.certification,
    })
}

fn compare(label: &str, actual: &str, expected: &str, mismatches: &mut Vec<String>) {
    if actual != expected {
        mismatches.push(format!("{label} differs"));
    }
}

fn compare_hash(label: &str, path: &Path, expected: &str, mismatches: &mut Vec<String>) {
    match read_nofollow(path) {
        Ok(content) if hex_sha256(&content) == expected => {}
        Ok(_) => mismatches.push(format!("{label} hash differs")),
        Err(_) => mismatches.push(format!("{label} is unavailable")),
    }
}

fn compare_command(
    label: &str,
    program: &str,
    arguments: &[&str],
    expected: &str,
    mismatches: &mut Vec<String>,
) {
    match Command::new(program).args(arguments).output() {
        Ok(output) if output.status.success() => {
            let actual = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if actual != expected {
                mismatches.push(format!("{label} differs"));
            }
        }
        _ => mismatches.push(format!("{label} is unavailable")),
    }
}

fn read_nofollow(path: &Path) -> io::Result<Vec<u8>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW_ANY)
        .open(path)?;
    let mut content = Vec::new();
    file.read_to_end(&mut content)?;
    Ok(content)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_parses_and_hashes_are_complete() {
        let catalog: Catalog = toml::from_str(SOURCE).unwrap();
        assert_eq!(catalog.standalone_cli.launcher_sha256.len(), 64);
        assert_eq!(catalog.desktop.executable_sha256.len(), 64);
    }
}
