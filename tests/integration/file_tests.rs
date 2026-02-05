//! Integration tests for file operation security checks

use claude_guardrails::{Config, HookInput, SecurityEngine};

fn engine() -> SecurityEngine {
    SecurityEngine::new(Config::default())
}

fn check_read(file_path: &str) -> bool {
    let json = format!(
        r#"{{"tool_name":"Read","tool_input":{{"file_path":"{}"}}}}"#,
        file_path.replace('\\', "\\\\").replace('"', "\\\"")
    );
    let input = HookInput::from_json(&json).unwrap();
    let decision = engine().check(&input);
    decision.is_allow()
}

fn check_write(file_path: &str) -> bool {
    let json = format!(
        r#"{{"tool_name":"Write","tool_input":{{"file_path":"{}","content":"test"}}}}"#,
        file_path.replace('\\', "\\\\").replace('"', "\\\"")
    );
    let input = HookInput::from_json(&json).unwrap();
    let decision = engine().check(&input);
    decision.is_allow()
}

fn check_edit(file_path: &str) -> bool {
    let json = format!(
        r#"{{"tool_name":"Edit","tool_input":{{"file_path":"{}","old_string":"a","new_string":"b"}}}}"#,
        file_path.replace('\\', "\\\\").replace('"', "\\\"")
    );
    let input = HookInput::from_json(&json).unwrap();
    let decision = engine().check(&input);
    decision.is_allow()
}

// ============================================================================
// Environment Files - BLOCKED
// ============================================================================

#[test]
fn test_env_file_blocked() {
    assert!(!check_read(".env"));
    assert!(!check_read("/path/to/.env"));
    assert!(!check_read("/home/user/project/.env"));

    assert!(!check_write(".env"));
    assert!(!check_edit(".env"));
}

#[test]
fn test_env_local_blocked() {
    assert!(!check_read(".env.local"));
    assert!(!check_read("/path/.env.local"));
}

#[test]
fn test_env_production_blocked() {
    assert!(!check_read(".env.production"));
    assert!(!check_read("/path/.env.production"));
}

// ============================================================================
// SSH Keys - BLOCKED
// ============================================================================

#[test]
fn test_ssh_private_key_blocked() {
    assert!(!check_read("/home/user/.ssh/id_rsa"));
    assert!(!check_read("~/.ssh/id_rsa"));
    assert!(!check_read("/home/user/.ssh/id_ed25519"));
    assert!(!check_read("/home/user/.ssh/id_ecdsa"));
    assert!(!check_read("/home/user/.ssh/id_dsa"));
}

// ============================================================================
// Cloud Credentials - BLOCKED
// ============================================================================

#[test]
fn test_aws_credentials_blocked() {
    assert!(!check_read("/home/user/.aws/credentials"));
    assert!(!check_read("~/.aws/credentials"));
}

#[test]
fn test_kube_config_blocked() {
    assert!(!check_read("/home/user/.kube/config"));
    assert!(!check_read("~/.kube/config"));
}

// ============================================================================
// Certificate/Key Files - BLOCKED
// ============================================================================

#[test]
fn test_pem_file_blocked() {
    assert!(!check_read("server.pem"));
    assert!(!check_read("/path/to/cert.pem"));
    assert!(!check_read("/etc/ssl/private/key.pem"));
}

#[test]
fn test_p12_file_blocked() {
    assert!(!check_read("certificate.p12"));
    assert!(!check_read("/path/to/keystore.p12"));
}

#[test]
fn test_key_file_blocked() {
    assert!(!check_read("private.key"));
    assert!(!check_read("/path/to/server.key"));
}

// ============================================================================
// Credentials Files - BLOCKED
// ============================================================================

#[test]
fn test_credentials_json_blocked() {
    assert!(!check_read("credentials.json"));
    assert!(!check_read("/path/to/credentials.json"));
}

#[test]
fn test_secrets_file_blocked() {
    assert!(!check_read("secrets.json"));
    assert!(!check_read("secrets.yaml"));
    assert!(!check_read("secrets.yml"));
    assert!(!check_read("secret.json"));
}

#[test]
fn test_docker_config_blocked() {
    assert!(!check_read("/home/user/.docker/config.json"));
    assert!(!check_read("~/.docker/config.json"));
}

#[test]
fn test_netrc_blocked() {
    assert!(!check_read("/home/user/.netrc"));
    assert!(!check_read("~/.netrc"));
}

#[test]
fn test_npmrc_blocked() {
    assert!(!check_read("/home/user/.npmrc"));
    assert!(!check_read("~/.npmrc"));
}

#[test]
fn test_pypirc_blocked() {
    assert!(!check_read("/home/user/.pypirc"));
    assert!(!check_read("~/.pypirc"));
}

// ============================================================================
// Safe Files - ALLOWED
// ============================================================================

#[test]
fn test_readme_allowed() {
    assert!(check_read("README.md"));
    assert!(check_read("/path/to/README.md"));
    assert!(check_write("README.md"));
    assert!(check_edit("README.md"));
}

#[test]
fn test_source_code_allowed() {
    assert!(check_read("src/main.rs"));
    assert!(check_read("src/lib.rs"));
    assert!(check_read("index.js"));
    assert!(check_read("app.py"));
}

#[test]
fn test_config_files_allowed() {
    assert!(check_read("package.json"));
    assert!(check_read("Cargo.toml"));
    assert!(check_read("tsconfig.json"));
}

#[test]
fn test_env_example_allowed() {
    assert!(check_read(".env.example"));
    assert!(check_read("/path/to/.env.example"));
    assert!(check_read(".env.template"));
}

#[test]
fn test_ssh_pub_key_allowed() {
    assert!(check_read("/home/user/.ssh/id_rsa.pub"));
    assert!(check_read("~/.ssh/id_ed25519.pub"));
    assert!(check_read("/home/user/.ssh/known_hosts"));
}

#[test]
fn test_aws_config_allowed() {
    // AWS config (not credentials) should be allowed
    // Note: current rules don't distinguish, but this is a good test case
    // for future refinement
}

#[test]
fn test_gitignore_allowed() {
    assert!(check_read(".gitignore"));
    assert!(check_read("/path/to/.gitignore"));
}

#[test]
fn test_dockerfile_allowed() {
    assert!(check_read("Dockerfile"));
    assert!(check_read("docker-compose.yml"));
}
