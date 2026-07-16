//! Adapter 凭据文件读取
//!
//! v0.5-D 整改 P1-1/P1-2：fail-closed + 严格 schema 校验
//!
//! 安全要求：
//! - O_NOFOLLOW 打开（防止 symlink 攻击）
//! - 在同一 fd 上 fstat 校验：regular file、link count=1、owner=当前用户、mode=0600、大小≤4KB
//! - 从同一 fd 读取内容并解析 JSON
//!
//! 凭据 schema（与 TypeScript 侧 `adapter-credentials.ts` 对齐，camelCase）：
//!   protocolVersion, endpoint, token(≥32字符), createdAt(u64), installationId(UUID)
//! endpoint 必须为 loopback HTTP URL (127.0.0.1/localhost/::1)，无 userinfo/query/fragment/path。
//!
//! fail-closed 语义 (P1-1)：
//!   - 凭据文件存在但任何校验失败 → `Err`（不得回退到环境变量）
//!   - 凭据文件不存在 → 回退到环境变量 `CLASH_VERGE_ADAPTER_TOKEN`
//!   - 环境变量设置但长度 < 32 → `Err`
//!   - 环境变量未设置 → `Err`

use anyhow::{Context, Result, bail};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// 环境变量名（向后兼容回退）
pub const ADAPTER_TOKEN_ENV: &str = "CLASH_VERGE_ADAPTER_TOKEN";

/// 凭据文件最大大小 (4 KB)
const MAX_CREDENTIALS_SIZE: u64 = 4 * 1024;

/// Token 最小长度（32 字符 ≈ 128 bit hex）
const MIN_TOKEN_LENGTH: usize = 32;

/// createdAt 合理下限（2024-01-01 UTC，早于此时间视为非法）
const MIN_CREATED_AT_MS: u64 = 1_704_067_200_000;

/// createdAt 允许的未来偏移（毫秒），用于时钟漂移容忍
const MAX_CREATED_AT_FUTURE_MS: u64 = 60_000;

/// 支持的 protocolVersion 列表
const SUPPORTED_PROTOCOL_VERSIONS: &[&str] = &["v1"];

/// The embedded Adapter listener is intentionally fixed and loopback-only.
const ADAPTER_ENDPOINT: &str = "http://127.0.0.1:33331";

/// installationId UUID 正则（大小写不敏感，canonical 8-4-4-4-12）
static UUID_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
        .expect("valid UUID regex")
});

/// 凭据 schema（camelCase，与 TypeScript 侧一致）
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
pub struct AdapterCredentials {
    /// 协议版本（如 "v1"）
    pub protocol_version: String,
    /// Loopback HTTP endpoint
    pub endpoint: String,
    /// Adapter Token（≥32 字符）
    pub token: String,
    /// 创建时间（Unix 毫秒）
    pub created_at: u64,
    /// 安装 ID（canonical UUID）
    pub installation_id: String,
}

/// 返回当前 Unix 毫秒时间戳
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// 返回凭据文件路径
fn credentials_path() -> Result<std::path::PathBuf> {
    let home = std::env::var("HOME").context("HOME environment variable is not set")?;
    Ok(std::path::PathBuf::from(home)
        .join("Library")
        .join("Application Support")
        .join("clash-control-mcp")
        .join("adapter")
        .join("credentials.json"))
}

/// 严格校验 endpoint 为 loopback HTTP origin（P1-2）
///
/// 要求：
///   - scheme = http
///   - host ∈ {127.0.0.1, localhost, ::1}
///   - 无 username/password
///   - 无 query/fragment
///   - path 为空或仅为 "/"（不允许多余 path）
#[allow(clippy::missing_errors_doc)]
pub fn validate_loopback_endpoint_strict(endpoint: &str) -> Result<()> {
    let url = url::Url::parse(endpoint).context("invalid endpoint URL")?;

    if url.scheme() != "http" {
        bail!("endpoint must use http scheme, got {}", url.scheme());
    }

    match url.host() {
        Some(url::Host::Ipv4(addr)) if addr == std::net::Ipv4Addr::LOCALHOST => {}
        Some(url::Host::Ipv6(addr)) if addr == std::net::Ipv6Addr::LOCALHOST => {}
        Some(url::Host::Domain("localhost")) => {}
        _ => bail!("endpoint must be loopback (127.0.0.1/localhost/::1)"),
    }

    if !url.username().is_empty() {
        bail!("endpoint must not contain username");
    }
    if url.password().is_some() {
        bail!("endpoint must not contain password");
    }
    if url.query().is_some() {
        bail!("endpoint must not contain query");
    }
    if url.fragment().is_some() {
        bail!("endpoint must not contain fragment");
    }
    let path = url.path();
    if path != "/" && !path.is_empty() {
        bail!("endpoint must not contain path: {}", path);
    }

    Ok(())
}

/// 旧版非严格 loopback 校验（仅检查 scheme + loopback host），保留以向后兼容。
///
/// 新代码应使用 [`validate_loopback_endpoint_strict`]。
#[allow(clippy::missing_errors_doc)]
pub fn validate_loopback_endpoint(endpoint: &str) -> Result<()> {
    let url = url::Url::parse(endpoint).context("invalid endpoint URL")?;

    if url.scheme() != "http" {
        bail!("endpoint must be http, got {}", url.scheme());
    }

    match url.host() {
        Some(url::Host::Ipv4(addr)) if addr.is_loopback() => Ok(()),
        Some(url::Host::Ipv6(addr)) if addr.is_loopback() => Ok(()),
        Some(url::Host::Domain("localhost")) => Ok(()),
        _ => bail!("endpoint must be loopback (127.0.0.1/localhost/::1)"),
    }
}

/// 严格校验凭据 schema（P1-2）
///
/// 不接受类型强转：所有字段类型不匹配直接报错（serde 解析阶段已拒绝）。
#[allow(clippy::missing_errors_doc)]
pub fn validate_credentials(creds: &AdapterCredentials) -> Result<()> {
    // protocol_version: 非空字符串且在支持列表中
    if creds.protocol_version.is_empty() {
        bail!("credentials.protocolVersion must be a non-empty string");
    }
    if !SUPPORTED_PROTOCOL_VERSIONS.contains(&creds.protocol_version.as_str()) {
        bail!(
            "credentials.protocolVersion {:?} not in supported list {:?}",
            creds.protocol_version,
            SUPPORTED_PROTOCOL_VERSIONS
        );
    }

    // endpoint: 非空 + 严格 loopback HTTP
    if creds.endpoint.is_empty() {
        bail!("credentials.endpoint must be a non-empty string");
    }
    validate_loopback_endpoint_strict(&creds.endpoint)?;
    if creds.endpoint != ADAPTER_ENDPOINT {
        bail!("credentials.endpoint must be exactly {}", ADAPTER_ENDPOINT);
    }

    // token: 长度 >= 32
    if creds.token.len() < MIN_TOKEN_LENGTH {
        bail!("credentials.token length {} < {}", creds.token.len(), MIN_TOKEN_LENGTH);
    }

    // created_at: 合理范围
    if creds.created_at < MIN_CREATED_AT_MS {
        bail!(
            "credentials.createdAt {} is before minimum {}",
            creds.created_at,
            MIN_CREATED_AT_MS
        );
    }
    let now = now_ms();
    if creds.created_at > now.saturating_add(MAX_CREATED_AT_FUTURE_MS) {
        bail!(
            "credentials.createdAt {} is in the future (now={})",
            creds.created_at,
            now
        );
    }

    // installation_id: canonical UUID
    if !UUID_RE.is_match(&creds.installation_id) {
        bail!("credentials.installationId must be a canonical UUID string");
    }

    Ok(())
}

// ============================================================================
// Unix 实现：使用 O_NOFOLLOW + fstat 安全打开和校验
// ============================================================================

#[cfg(unix)]
mod unix {
    use super::*;
    use std::io::Read;
    use std::os::unix::io::{AsRawFd, FromRawFd};

    /// 使用 O_NOFOLLOW 打开凭据文件，防止 symlink 攻击。
    /// 文件不存在时返回 `Ok(None)`，其他错误返回 `Err`。
    fn open_credentials_no_follow(path: &std::path::Path) -> Result<Option<std::fs::File>> {
        let c_path = std::ffi::CString::new(path.to_str().context("invalid path")?)?;
        let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
        if fd < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::NotFound {
                return Ok(None);
            }
            bail!("failed to open credentials file: {}", err);
        }
        // Safety: fd is a valid file descriptor from a successful open()
        Ok(Some(unsafe { std::fs::File::from_raw_fd(fd) }))
    }

    /// 在同一 fd 上 fstat 校验：
    /// - regular file
    /// - link count = 1
    /// - owner = 当前用户
    /// - mode = 0600
    /// - size ≤ 4KB
    fn validate_credentials_stat(file: &std::fs::File) -> Result<()> {
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        let ret = unsafe { libc::fstat(file.as_raw_fd(), &mut stat) };
        if ret < 0 {
            bail!("fstat failed: {}", std::io::Error::last_os_error());
        }

        if (stat.st_mode & libc::S_IFMT) != libc::S_IFREG {
            bail!("credentials file is not a regular file");
        }
        if stat.st_nlink != 1 {
            bail!("credentials file has multiple hard links");
        }
        let uid = unsafe { libc::getuid() };
        if stat.st_uid != uid {
            bail!("credentials file owner mismatch");
        }
        let mode = stat.st_mode & 0o7777;
        if mode != 0o600 {
            bail!("credentials file mode must be 0600, got {:o}", mode);
        }
        if stat.st_size as u64 > MAX_CREDENTIALS_SIZE {
            bail!("credentials file too large: {} bytes", stat.st_size);
        }

        Ok(())
    }

    /// 从同一 fd 读取内容并解析 JSON，然后执行严格 schema 校验
    fn read_credentials_from_file(file: &mut std::fs::File) -> Result<AdapterCredentials> {
        let mut content = String::new();
        file.read_to_string(&mut content)
            .context("failed to read credentials file")?;

        let creds: AdapterCredentials = serde_json::from_str(&content).context("failed to parse credentials JSON")?;

        validate_credentials(&creds)?;

        Ok(creds)
    }

    /// 安全读取凭据文件（如果存在）。
    ///
    /// 返回值：
    ///   - `Ok(None)`：文件不存在（允许回退到环境变量）
    ///   - `Ok(Some(creds))`：文件存在且通过全部校验
    ///   - `Err`：文件存在但任何校验失败（fail-closed，不得回退）
    pub fn read_credentials_if_exists() -> Result<Option<AdapterCredentials>> {
        let path = credentials_path()?;
        let file = match open_credentials_no_follow(&path)? {
            Some(f) => f,
            None => return Ok(None),
        };
        validate_credentials_stat(&file)?;
        let mut file = file;
        read_credentials_from_file(&mut file).map(Some)
    }
}

#[cfg(unix)]
pub use unix::read_credentials_if_exists;

#[cfg(not(unix))]
#[allow(clippy::missing_errors_doc)]
pub fn read_credentials_if_exists() -> Result<Option<AdapterCredentials>> {
    // Non-Unix: credentials file secure reading not supported; fall back to env.
    Ok(None)
}

/// 安全读取凭据文件。
///
/// 文件不存在或校验失败均返回 `Err`。需要区分"不存在"与"校验失败"时
/// 请使用 [`read_credentials_if_exists`]。
#[cfg(unix)]
#[allow(clippy::missing_errors_doc)]
pub fn read_credentials() -> Result<AdapterCredentials> {
    read_credentials_if_exists()?.context("credentials file not found")
}

#[cfg(not(unix))]
#[allow(clippy::missing_errors_doc)]
pub fn read_credentials() -> Result<AdapterCredentials> {
    bail!("credentials file reading is only supported on Unix");
}

/// fail-closed 解析 adapter token 的内部实现（便于单测，避免 env 竞态）。
///
/// - `creds_opt`：`Some(creds)` 表示凭据文件存在且已校验；`None` 表示文件不存在。
/// - `env_token`：环境变量 `CLASH_VERGE_ADAPTER_TOKEN` 的值（已读取）。
fn resolve_adapter_token_impl(creds_opt: Option<AdapterCredentials>, env_token: Option<String>) -> Result<String> {
    match creds_opt {
        Some(creds) => Ok(creds.token),
        None => match env_token {
            Some(token) if token.len() >= MIN_TOKEN_LENGTH => Ok(token),
            Some(token) => bail!(
                "{} length {} < {} (credentials file not present)",
                ADAPTER_TOKEN_ENV,
                token.len(),
                MIN_TOKEN_LENGTH
            ),
            None => bail!("no credentials file and {} not set", ADAPTER_TOKEN_ENV),
        },
    }
}

/// 解析 adapter token（fail-closed，P1-1）。
///
/// 优先从凭据文件读取：
///   - 凭据文件存在但校验失败 → `Err`（不回退）
///   - 凭据文件不存在 → 回退到环境变量 `CLASH_VERGE_ADAPTER_TOKEN`
///   - 环境变量设置但长度 < 32 → `Err`
///   - 环境变量未设置 → `Err`
#[allow(clippy::missing_errors_doc)]
pub fn resolve_adapter_token() -> Result<String> {
    let creds_opt = read_credentials_if_exists()?;
    let env_token = std::env::var(ADAPTER_TOKEN_ENV).ok();
    resolve_adapter_token_impl(creds_opt, env_token)
}

/// 向后兼容包装：调用 [`resolve_adapter_token`]，出错时返回空字符串。
///
/// 仅用于 adapter 为可选的场景；server 应直接使用 [`resolve_adapter_token`]
/// 的 `Result` 版本以获得 fail-closed 语义。
pub fn resolve_adapter_token_or_empty() -> String {
    resolve_adapter_token().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_creds() -> AdapterCredentials {
        AdapterCredentials {
            protocol_version: "v1".to_string(),
            endpoint: "http://127.0.0.1:33331".to_string(),
            token: "0123456789abcdef0123456789abcdef".to_string(),
            created_at: now_ms(),
            installation_id: "12345678-1234-1234-1234-123456789abc".to_string(),
        }
    }

    // ----- validate_loopback_endpoint (legacy, non-strict) -----

    #[test]
    fn validate_loopback_accepts_localhost() {
        assert!(validate_loopback_endpoint("http://localhost:12345").is_ok());
        assert!(validate_loopback_endpoint("http://127.0.0.1:12345").is_ok());
        assert!(validate_loopback_endpoint("http://[::1]:12345").is_ok());
    }

    #[test]
    fn validate_loopback_rejects_non_loopback() {
        assert!(validate_loopback_endpoint("http://192.168.1.1:12345").is_err());
        assert!(validate_loopback_endpoint("http://10.0.0.1:12345").is_err());
        assert!(validate_loopback_endpoint("http://example.com:12345").is_err());
        assert!(validate_loopback_endpoint("http://8.8.8.8:12345").is_err());
    }

    #[test]
    fn validate_loopback_rejects_non_http() {
        assert!(validate_loopback_endpoint("https://127.0.0.1:12345").is_err());
        assert!(validate_loopback_endpoint("ftp://127.0.0.1:12345").is_err());
        assert!(validate_loopback_endpoint("ws://127.0.0.1:12345").is_err());
    }

    #[test]
    fn validate_loopback_rejects_invalid_url() {
        assert!(validate_loopback_endpoint("not a url").is_err());
        assert!(validate_loopback_endpoint("").is_err());
        assert!(validate_loopback_endpoint("http://").is_err());
    }

    // ----- validate_loopback_endpoint_strict (P1-2) -----

    #[test]
    fn strict_endpoint_accepts_bare_loopback() {
        assert!(validate_loopback_endpoint_strict("http://localhost:12345").is_ok());
        assert!(validate_loopback_endpoint_strict("http://127.0.0.1:12345").is_ok());
        assert!(validate_loopback_endpoint_strict("http://[::1]:12345").is_ok());
        // trailing slash is allowed
        assert!(validate_loopback_endpoint_strict("http://127.0.0.1:12345/").is_ok());
    }

    #[test]
    fn strict_endpoint_rejects_path() {
        assert!(validate_loopback_endpoint_strict("http://127.0.0.1:12345/foo").is_err());
        assert!(validate_loopback_endpoint_strict("http://127.0.0.1:12345/adapter").is_err());
    }

    #[test]
    fn strict_endpoint_rejects_query() {
        assert!(validate_loopback_endpoint_strict("http://127.0.0.1:12345?x=1").is_err());
    }

    #[test]
    fn strict_endpoint_rejects_fragment() {
        assert!(validate_loopback_endpoint_strict("http://127.0.0.1:12345#frag").is_err());
    }

    #[test]
    fn strict_endpoint_rejects_userinfo() {
        assert!(validate_loopback_endpoint_strict("http://user:pass@127.0.0.1:12345").is_err());
        assert!(validate_loopback_endpoint_strict("http://user@127.0.0.1:12345").is_err());
    }

    #[test]
    fn strict_endpoint_rejects_non_loopback_and_non_http() {
        assert!(validate_loopback_endpoint_strict("https://127.0.0.1:12345").is_err());
        assert!(validate_loopback_endpoint_strict("http://127.0.0.2:12345").is_err());
        assert!(validate_loopback_endpoint_strict("http://192.168.1.1:12345").is_err());
        assert!(validate_loopback_endpoint_strict("http://example.com:12345").is_err());
    }

    // ----- validate_credentials (P1-2) -----

    #[test]
    fn validate_credentials_accepts_valid() {
        assert!(validate_credentials(&valid_creds()).is_ok());
    }

    #[test]
    fn validate_credentials_rejects_unsupported_protocol_version() {
        let mut creds = valid_creds();
        creds.protocol_version = "v2".to_string();
        assert!(validate_credentials(&creds).is_err());
        creds.protocol_version = String::new();
        assert!(validate_credentials(&creds).is_err());
    }

    #[test]
    fn validate_credentials_rejects_bad_endpoint() {
        let mut creds = valid_creds();
        creds.endpoint = "http://127.0.0.1:33331/path".to_string();
        assert!(validate_credentials(&creds).is_err());
        creds.endpoint = "http://192.168.1.1:33331".to_string();
        assert!(validate_credentials(&creds).is_err());
        creds.endpoint = "http://127.0.0.1:33332".to_string();
        assert!(validate_credentials(&creds).is_err());
        creds.endpoint = "http://localhost:33331".to_string();
        assert!(validate_credentials(&creds).is_err());
    }

    #[test]
    fn validate_credentials_rejects_short_token() {
        let mut creds = valid_creds();
        creds.token = "short".to_string();
        assert!(validate_credentials(&creds).is_err());
    }

    #[test]
    fn validate_credentials_rejects_created_at_below_minimum() {
        let mut creds = valid_creds();
        creds.created_at = MIN_CREATED_AT_MS - 1;
        assert!(validate_credentials(&creds).is_err());
    }

    #[test]
    fn validate_credentials_rejects_created_at_in_future() {
        let mut creds = valid_creds();
        creds.created_at = now_ms() + MAX_CREATED_AT_FUTURE_MS + 1_000;
        assert!(validate_credentials(&creds).is_err());
    }

    #[test]
    fn validate_credentials_rejects_non_uuid_installation_id() {
        let mut creds = valid_creds();
        creds.installation_id = "not-a-uuid".to_string();
        assert!(validate_credentials(&creds).is_err());
        creds.installation_id = "12345678-1234-1234-1234-123456789ab".to_string(); // too short
        assert!(validate_credentials(&creds).is_err());
        creds.installation_id = "12345678123412341234123456789abc".to_string(); // no dashes
        assert!(validate_credentials(&creds).is_err());
    }

    #[test]
    fn validate_credentials_accepts_lowercase_and_uppercase_uuid() {
        let mut creds = valid_creds();
        creds.installation_id = "ABCDEF12-1234-1234-1234-123456789ABC".to_string();
        assert!(validate_credentials(&creds).is_ok());
        creds.installation_id = "abcdef12-1234-1234-1234-123456789abc".to_string();
        assert!(validate_credentials(&creds).is_ok());
    }

    // ----- schema parsing rejects type coercion (P1-2) -----

    #[test]
    fn parse_rejects_created_at_as_string() {
        // created_at must be a number; a string value must be rejected by serde.
        let json = r#"{
            "protocolVersion": "v1",
            "endpoint": "http://127.0.0.1:33331",
            "token": "0123456789abcdef0123456789abcdef",
            "createdAt": "1704067200000",
            "installationId": "12345678-1234-1234-1234-123456789abc"
        }"#;
        let result: std::result::Result<AdapterCredentials, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn parse_rejects_protocol_version_as_number() {
        let json = r#"{
            "protocolVersion": 1,
            "endpoint": "http://127.0.0.1:33331",
            "token": "0123456789abcdef0123456789abcdef",
            "createdAt": 1704067200000,
            "installationId": "12345678-1234-1234-1234-123456789abc"
        }"#;
        let result: std::result::Result<AdapterCredentials, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn parse_accepts_camel_case_fields() {
        let now = now_ms();
        let json = format!(
            r#"{{
                "protocolVersion": "v1",
                "endpoint": "http://127.0.0.1:33331",
                "token": "0123456789abcdef0123456789abcdef",
                "createdAt": {now},
                "installationId": "12345678-1234-1234-1234-123456789abc"
            }}"#
        );
        let creds: AdapterCredentials = serde_json::from_str(&json).expect("camelCase parse should succeed");
        assert!(validate_credentials(&creds).is_ok());
    }

    #[test]
    fn parse_rejects_unknown_fields() {
        let json = format!(
            r#"{{"protocolVersion":"v1","endpoint":"http://127.0.0.1:33331","token":"0123456789abcdef0123456789abcdef","createdAt":{},"installationId":"12345678-1234-1234-1234-123456789abc","unexpected":true}}"#,
            now_ms()
        );
        let result: std::result::Result<AdapterCredentials, _> = serde_json::from_str(&json);
        assert!(result.is_err());
    }

    // ----- resolve_adapter_token fail-closed (P1-1) -----

    #[test]
    fn resolve_returns_token_when_credentials_present() {
        let creds = valid_creds();
        let token = creds.token.clone();
        let result = resolve_adapter_token_impl(Some(creds), None);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), token);
    }

    #[test]
    fn resolve_falls_back_to_env_when_file_absent() {
        let env_token = "0123456789abcdef0123456789abcdef".to_string();
        let result = resolve_adapter_token_impl(None, Some(env_token.clone()));
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), env_token);
    }

    #[test]
    fn resolve_short_env_token_returns_error_not_empty() {
        let result = resolve_adapter_token_impl(None, Some("short".to_string()));
        assert!(result.is_err());
        // fail-closed: must NOT silently return an empty string
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("CLASH_VERGE_ADAPTER_TOKEN"));
    }

    #[test]
    fn resolve_missing_env_returns_error() {
        let result = resolve_adapter_token_impl(None, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("CLASH_VERGE_ADAPTER_TOKEN"));
    }

    #[test]
    fn resolve_credentials_present_ignores_env() {
        // Even if a short env token is set, valid credentials win.
        let creds = valid_creds();
        let token = creds.token.clone();
        let result = resolve_adapter_token_impl(Some(creds), Some("short".to_string()));
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), token);
    }

    #[test]
    fn resolve_adapter_token_or_empty_returns_empty_on_error() {
        // No credentials file (HOME likely points at real home with no creds file)
        // and no env var → should return empty string via the wrapper.
        // This test only verifies the wrapper does not panic; behavior depends on env.
        let _ = resolve_adapter_token_or_empty();
    }
}
