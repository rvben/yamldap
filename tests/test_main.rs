use std::fs;
use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;

/// Helper to create a test YAML directory file
fn create_test_yaml(dir: &TempDir) -> PathBuf {
    let yaml_path = dir.path().join("test_directory.yaml");
    let yaml_content = r#"
base_dn: "dc=example,dc=com"
entries:
  - dn: "dc=example,dc=com"
    attributes:
      objectClass: ["top", "dcObject", "organization"]
      dc: ["example"]
      o: ["Example Organization"]
"#;
    fs::write(&yaml_path, yaml_content).unwrap();
    yaml_path
}

#[test]
fn test_cli_help() {
    let output = Command::new("cargo")
        .args(&["run", "--bin", "yamldap", "--", "--help"])
        .output()
        .expect("Failed to execute process");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("A lightweight LDAP server"));
    assert!(stdout.contains("--file"));
    assert!(stdout.contains("--port"));
}

#[test]
fn test_cli_version() {
    let output = Command::new("cargo")
        .args(&["run", "--bin", "yamldap", "--", "--version"])
        .output()
        .expect("Failed to execute process");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("yamldap"));
}

#[test]
fn test_cli_missing_file() {
    let output = Command::new("cargo")
        .args(&[
            "run",
            "--bin",
            "yamldap",
            "--",
            "--file",
            "nonexistent.yaml",
        ])
        .output()
        .expect("Failed to execute process");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("YAML file not found") || stderr.contains("No such file"));
}

#[test]
fn test_cli_invalid_port() {
    let temp_dir = TempDir::new().unwrap();
    let yaml_path = create_test_yaml(&temp_dir);

    let output = Command::new("cargo")
        .args(&[
            "run",
            "--bin",
            "yamldap",
            "--",
            "--file",
            yaml_path.to_str().unwrap(),
            "--port",
            "99999", // Invalid port
        ])
        .output()
        .expect("Failed to execute process");

    assert!(!output.status.success());
}

#[test]
fn test_cli_log_levels() {
    let temp_dir = TempDir::new().unwrap();
    let yaml_path = create_test_yaml(&temp_dir);

    for level in &[
        "debug", "info", "warn", "error", "DEBUG", "INFO", "WARN", "ERROR",
    ] {
        let output = Command::new("cargo")
            .args(&[
                "run",
                "--bin",
                "yamldap",
                "--",
                "--file",
                yaml_path.to_str().unwrap(),
                "--log-level",
                level,
                "--help", // Just check args parsing, don't actually run server
            ])
            .output()
            .expect("Failed to execute process");

        assert!(output.status.success(), "Failed for log level: {}", level);
    }
}

#[test]
fn test_cli_verbose_flag() {
    let output = Command::new("cargo")
        .args(&["run", "--bin", "yamldap", "--", "--verbose", "--help"])
        .output()
        .expect("Failed to execute process");

    assert!(output.status.success());
}

#[test]
fn test_cli_all_arguments() {
    // We don't need the yaml file for this test
    // Just test that help output shows all arguments
    let output = Command::new("cargo")
        .args(&["run", "--bin", "yamldap", "--", "--help"])
        .output()
        .expect("Failed to execute process");

    assert!(output.status.success());

    // Also verify we can parse all arguments (without actually running)
    let output_str = String::from_utf8_lossy(&output.stdout);
    assert!(output_str.contains("--file"));
    assert!(output_str.contains("--port"));
    assert!(output_str.contains("--bind"));
    assert!(output_str.contains("--log-level"));
    assert!(output_str.contains("--verbose"));
    assert!(output_str.contains("--hot-reload"));
    assert!(output_str.contains("--allow-anonymous"));
}
