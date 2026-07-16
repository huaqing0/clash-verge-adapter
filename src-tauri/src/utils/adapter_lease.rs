//! Profile 激活租约管理
//!
//! v0.5-D 整改 P1-3 / P0-3：
//!   - 单一全局 PENDING_COMMIT 租约（互斥）
//!   - commit 时检查 deadline
//!   - 原子状态转移：lock → check → persist → update memory（持久化失败不污染内存）
//!   - 私有权限：目录 0700、租约文件 0600
//!   - symlink / 硬链接保护（读取时 O_NOFOLLOW + fstat）
//!   - 路径穿越保护（文件名必须匹配 operation_id）
//!   - 审计日志：终态文件保留，不立即删除；`cleanup_old_leases` 清理过期文件
//!   - 重启恢复 (P0-3)：启动时扫描 PENDING_COMMIT 租约并回滚
//!
//! 租约状态机：
//!   PENDING_COMMIT → COMMITTED (MCP 健康验证后 commit)
//!   PENDING_COMMIT → ROLLED_BACK (MCP 主动 rollback / 超时自动 rollback / 重启恢复)
//!   PENDING_COMMIT → ROLLBACK_FAILED (回滚切换失败，需人工介入)
//!
//! 持久化：租约状态写入 `adapter/leases/<operationId>.json`。
//! 超时回滚：后台任务在 deadline 到期时自动 rollback 到 previousProfileUid。
//! 重启恢复：启动时扫描所有未完成租约，返回需要回滚的列表。

use anyhow::{Context, Result, bail};
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// 租约状态
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LeaseState {
    /// 租约已持久化，Adapter 正在执行 Profile 切换；此时不能 commit。
    Activating,
    /// 已 prepare，等待 MCP commit
    PendingCommit,
    /// 已原子取得回滚所有权，正在切换回 previous Profile。
    RollingBack,
    /// 已 commit，激活完成
    Committed,
    /// 已 rollback，恢复到 previous
    RolledBack,
    /// rollback 失败，需要人工介入
    RollbackFailed,
}

/// 租约记录
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseRecord {
    /// 操作 ID（高熵随机）
    pub operation_id: String,
    /// 原始 Profile UID
    pub previous_profile_uid: String,
    /// 目标 Profile UID
    pub target_profile_uid: String,
    /// 创建时间（Unix 毫秒）
    pub created_at: u64,
    /// 回滚截止时间（Unix 毫秒）
    pub deadline: u64,
    /// 目标切换验证成功后使用的回滚窗口。
    #[serde(default = "default_rollback_after_ms")]
    pub rollback_after_ms: u64,
    /// 当前状态
    pub state: LeaseState,
    /// 最后更新时间（Unix 毫秒）
    pub updated_at: u64,
    /// 失败原因（仅 ROLLBACK_FAILED 状态下可能填充，用于审计）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// 最大 rollback 超时 (60 秒)
pub const MAX_ROLLBACK_AFTER_MS: u64 = 60_000;

/// 默认 rollback 超时 (30 秒)
pub const DEFAULT_ROLLBACK_AFTER_MS: u64 = 30_000;

fn default_rollback_after_ms() -> u64 {
    DEFAULT_ROLLBACK_AFTER_MS
}

/// 租约文件最大大小 (64 KB)
const LEASE_FILE_MAX_SIZE: u64 = 64 * 1024;

/// 默认租约保留期 (7 天)
pub const DEFAULT_LEASE_RETENTION_MS: u64 = 7 * 24 * 60 * 60 * 1000;

/// 内存中的租约存储 + 全局活跃 PENDING_COMMIT 操作 ID
struct LeaseStore {
    leases: HashMap<String, LeaseRecord>,
    /// 当前唯一活跃的 PENDING_COMMIT 操作 ID（保证全局只有一个进行中的激活）
    active_pending: Option<String>,
}

static LEASES: Lazy<Mutex<LeaseStore>> = Lazy::new(|| {
    Mutex::new(LeaseStore {
        leases: HashMap::new(),
        active_pending: None,
    })
});

/// 重启恢复进行中标志（P0-3）：为 true 时阻止新的 prepare_lease
static RECOVERY_IN_PROGRESS: AtomicBool = AtomicBool::new(false);

/// 返回租约持久化目录
fn leases_dir() -> Result<PathBuf> {
    let home = std::env::var("HOME").context("HOME environment variable is not set")?;
    Ok(PathBuf::from(home)
        .join("Library")
        .join("Application Support")
        .join("clash-control-mcp")
        .join("adapter")
        .join("leases"))
}

/// 返回当前 Unix 毫秒时间戳
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// operation_id 安全性检查：仅允许字母数字、下划线、连字符（防止路径穿越）。
fn is_safe_operation_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 160 && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

fn is_safe_profile_uid(uid: &str) -> bool {
    !uid.is_empty() && uid.len() <= 120 && uid.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

fn validate_lease_record(record: &LeaseRecord) -> Result<()> {
    if !is_safe_operation_id(&record.operation_id) {
        bail!("unsafe operation_id: {}", record.operation_id);
    }
    if !is_safe_profile_uid(&record.previous_profile_uid) || !is_safe_profile_uid(&record.target_profile_uid) {
        bail!("lease contains an invalid profile UID");
    }
    if !(5_000..=MAX_ROLLBACK_AFTER_MS).contains(&record.rollback_after_ms) {
        bail!("lease rollback_after_ms is out of range");
    }
    if record.state == LeaseState::PendingCommit && record.deadline == 0 {
        bail!("PENDING_COMMIT lease has no deadline");
    }
    if record.state == LeaseState::Activating && record.deadline != 0 {
        bail!("ACTIVATING lease must not have a deadline");
    }
    Ok(())
}

/// 是否正在执行重启恢复（P0-3）
pub fn is_recovery_in_progress() -> bool {
    RECOVERY_IN_PROGRESS.load(Ordering::SeqCst)
}

/// 设置重启恢复标志
pub fn set_recovery_in_progress(v: bool) {
    RECOVERY_IN_PROGRESS.store(v, Ordering::SeqCst);
}

/// 结束重启恢复（等价于 `set_recovery_in_progress(false)`）
pub fn end_recovery() {
    set_recovery_in_progress(false);
}

/// 是否应阻止新的激活：恢复进行中，或已有活跃的 PENDING_COMMIT 租约
pub fn block_new_activations() -> bool {
    if is_recovery_in_progress() {
        return true;
    }
    let store = LEASES.lock();
    store.active_pending.is_some()
}

// ============================================================================
// Unix：原子持久化（0600 / 0700 / fsync / rename）+ 安全读取（O_NOFOLLOW+fstat）
// ============================================================================

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .with_context(|| format!("failed to set mode {:o} on {}", mode, path.display()))
}

#[cfg(unix)]
fn persist_lease_atomic(record: &LeaseRecord) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    if !is_safe_operation_id(&record.operation_id) {
        bail!("unsafe operation_id: {}", record.operation_id);
    }

    let dir = leases_dir()?;
    std::fs::create_dir_all(&dir).context("failed to create leases directory")?;
    set_mode(&dir, 0o700)?;

    let path = dir.join(format!("{}.json", record.operation_id));
    let tmp_path = dir.join(format!(
        "{}.tmp.{}.{}",
        record.operation_id,
        std::process::id(),
        nanoid::nanoid!(12)
    ));

    let content = serde_json::to_string_pretty(record).context("failed to serialize lease record")?;

    {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp_path)
            .with_context(|| format!("failed to open lease tmp file {}", tmp_path.display()))?;
        file.write_all(content.as_bytes())
            .context("failed to write lease tmp file")?;
        file.sync_all().context("failed to fsync lease tmp file")?;
    }

    std::fs::rename(&tmp_path, &path).context("failed to rename lease file")?;

    // fsync 目录使 rename 持久化
    let dir_file = std::fs::File::open(&dir).context("failed to open leases dir for fsync")?;
    dir_file.sync_all().context("failed to fsync leases dir")?;

    Ok(())
}

#[cfg(not(unix))]
fn persist_lease_atomic(record: &LeaseRecord) -> Result<()> {
    if !is_safe_operation_id(&record.operation_id) {
        bail!("unsafe operation_id: {}", record.operation_id);
    }
    let dir = leases_dir()?;
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{}.json", record.operation_id));
    let tmp_path = dir.join(format!("{}.tmp.{}", record.operation_id, std::process::id()));
    let content = serde_json::to_string_pretty(record)?;
    std::fs::write(&tmp_path, &content)?;
    std::fs::rename(&tmp_path, &path)?;
    Ok(())
}

/// 安全读取租约文件（P1-3.5, P1-3.6）
///
/// - O_NOFOLLOW 打开（拒绝 symlink）
/// - fstat 校验：regular file、nlink=1、owner=当前用户、mode=0600、大小≤64KB
/// - 从同一 fd 读取并解析
/// - 文件名（stem）必须与文件内 operation_id 一致（路径穿越保护）
#[cfg(unix)]
fn read_lease_file_safe(path: &Path) -> Result<LeaseRecord> {
    use std::io::Read;
    use std::os::unix::io::FromRawFd;

    let path_str = path.to_str().context("invalid lease path")?;
    let c_path = std::ffi::CString::new(path_str).context("invalid lease path (nul byte)")?;

    let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
    if fd < 0 {
        bail!(
            "failed to open lease file {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        );
    }

    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut stat) } < 0 {
        unsafe { libc::close(fd) };
        bail!(
            "fstat failed on lease file {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        );
    }

    if (stat.st_mode & libc::S_IFMT) != libc::S_IFREG {
        unsafe { libc::close(fd) };
        bail!("lease file is not a regular file: {}", path.display());
    }
    if stat.st_nlink != 1 {
        unsafe { libc::close(fd) };
        bail!("lease file has multiple hard links: {}", path.display());
    }
    let uid = unsafe { libc::getuid() };
    if stat.st_uid != uid {
        unsafe { libc::close(fd) };
        bail!("lease file owner mismatch: {}", path.display());
    }
    if (stat.st_mode & 0o7777) != 0o600 {
        unsafe { libc::close(fd) };
        bail!("lease file mode must be 0600: {}", path.display());
    }
    if stat.st_size as u64 > LEASE_FILE_MAX_SIZE {
        unsafe { libc::close(fd) };
        bail!("lease file too large: {}", path.display());
    }

    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    let mut content = String::new();
    file.read_to_string(&mut content)
        .with_context(|| format!("failed to read lease file {}", path.display()))?;

    let record: LeaseRecord =
        serde_json::from_str(&content).with_context(|| format!("failed to parse lease JSON {}", path.display()))?;

    validate_lease_record(&record)?;

    if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
        if stem != record.operation_id {
            bail!("filename {} does not match operation_id {}", stem, record.operation_id);
        }
    }

    Ok(record)
}

#[cfg(not(unix))]
fn read_lease_file_safe(path: &Path) -> Result<LeaseRecord> {
    let content =
        std::fs::read_to_string(path).with_context(|| format!("failed to read lease file {}", path.display()))?;
    let record: LeaseRecord =
        serde_json::from_str(&content).with_context(|| format!("failed to parse lease JSON {}", path.display()))?;
    validate_lease_record(&record)?;
    if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
        if stem != record.operation_id {
            bail!("filename {} does not match operation_id {}", stem, record.operation_id);
        }
    }
    Ok(record)
}

/// 创建新的激活租约（P1-3.1）
///
/// 1. 检查恢复标志 / 已有 PENDING_COMMIT（CONFLICT）
/// 2. 持久化到磁盘（0600）
/// 3. 写入内存 + 设置 active_pending
///
/// 持久化失败不会污染内存状态。
pub fn prepare_lease(
    previous_profile_uid: &str,
    target_profile_uid: &str,
    rollback_after_ms: u64,
) -> Result<LeaseRecord> {
    if !is_safe_profile_uid(previous_profile_uid) {
        bail!("previous_profile_uid is invalid");
    }
    if !is_safe_profile_uid(target_profile_uid) {
        bail!("target_profile_uid is invalid");
    }
    if is_recovery_in_progress() {
        bail!("recovery in progress, cannot prepare new lease");
    }

    let rollback_ms = rollback_after_ms.clamp(5_000, MAX_ROLLBACK_AFTER_MS);
    let now = now_ms();
    let operation_id = format!("op_{}_{}", now, nanoid::nanoid!(24));
    if !is_safe_operation_id(&operation_id) {
        bail!("generated unsafe operation_id: {}", operation_id);
    }

    let record = LeaseRecord {
        operation_id: operation_id.clone(),
        previous_profile_uid: previous_profile_uid.to_string(),
        target_profile_uid: target_profile_uid.to_string(),
        created_at: now,
        deadline: 0,
        rollback_after_ms: rollback_ms,
        state: LeaseState::Activating,
        updated_at: now,
        reason: None,
    };

    let mut store = LEASES.lock();
    if store.active_pending.is_some() {
        bail!("another lease is already in PENDING_COMMIT state (CONFLICT)");
    }
    // 防御性检查：内存中不应残留 PENDING_COMMIT
    if store.leases.values().any(|r| {
        matches!(
            r.state,
            LeaseState::Activating | LeaseState::PendingCommit | LeaseState::RollingBack
        )
    }) {
        bail!("an activation lease is already active (CONFLICT)");
    }

    // 持久化优先（持久化失败不更新内存）
    persist_lease_atomic(&record)?;

    // 持久化成功 → 更新内存
    store.leases.insert(operation_id.clone(), record.clone());
    store.active_pending = Some(operation_id);

    Ok(record)
}

/// 目标 Profile 已切换并重新读取验证后，开始 commit/rollback 租约窗口。
pub fn arm_lease(operation_id: &str) -> Result<LeaseRecord> {
    let mut store = LEASES.lock();
    let record = store.leases.get(operation_id).context("lease not found")?.clone();
    if record.state != LeaseState::Activating {
        bail!("lease is not in ACTIVATING state (current: {:?})", record.state);
    }
    let now = now_ms();
    let mut updated = record;
    updated.state = LeaseState::PendingCommit;
    updated.deadline = now + updated.rollback_after_ms.clamp(5_000, MAX_ROLLBACK_AFTER_MS);
    updated.updated_at = now;
    persist_lease_atomic(&updated)?;
    store.leases.insert(operation_id.to_string(), updated.clone());
    Ok(updated)
}

/// 原子取得回滚所有权，防止 commit/timeout/manual rollback 竞争。
pub fn claim_rollback(operation_id: &str) -> Result<LeaseRecord> {
    let mut store = LEASES.lock();
    let record = store.leases.get(operation_id).context("lease not found")?.clone();
    if record.state == LeaseState::RollingBack {
        bail!("rollback already in progress");
    }
    if !matches!(record.state, LeaseState::Activating | LeaseState::PendingCommit) {
        bail!("lease cannot be rolled back from state {:?}", record.state);
    }
    let mut updated = record;
    updated.state = LeaseState::RollingBack;
    updated.updated_at = now_ms();
    persist_lease_atomic(&updated)?;
    store.leases.insert(operation_id.to_string(), updated.clone());
    Ok(updated)
}

/// 查询租约状态
pub fn get_lease(operation_id: &str) -> Option<LeaseRecord> {
    LEASES.lock().leases.get(operation_id).cloned()
}

/// Commit 租约（P1-3.2：检查 deadline）
///
/// 顺序：lock → check state → check deadline → persist COMMITTED → update memory → clear active
pub fn commit_lease(operation_id: &str) -> Result<LeaseRecord> {
    let mut store = LEASES.lock();
    let record = store.leases.get(operation_id).context("lease not found")?.clone();

    if record.state != LeaseState::PendingCommit {
        bail!("lease is not in PENDING_COMMIT state (current: {:?})", record.state);
    }

    let now = now_ms();
    if now >= record.deadline {
        bail!(
            "lease expired, cannot commit (deadline={}, now={})",
            record.deadline,
            now
        );
    }

    let mut updated = record;
    updated.state = LeaseState::Committed;
    updated.updated_at = now;
    updated.reason = None;

    // 持久化优先
    persist_lease_atomic(&updated)?;

    // 持久化成功 → 更新内存 + 清除 active
    store.leases.insert(operation_id.to_string(), updated.clone());
    if store.active_pending.as_deref() == Some(operation_id) {
        store.active_pending = None;
    }

    Ok(updated)
}

/// 将租约转移到终态（内部实现，P1-3.3 / P1-3.4）
///
/// 顺序：lock → check state → persist terminal → update memory → clear active
/// 持久化失败不更新内存。
fn transition_to_terminal(operation_id: &str, new_state: LeaseState, reason: Option<&str>) -> Result<LeaseRecord> {
    let mut store = LEASES.lock();
    let record = store.leases.get(operation_id).context("lease not found")?.clone();

    // 幂等：已在目标终态
    if record.state == new_state {
        return Ok(record);
    }

    if !matches!(
        record.state,
        LeaseState::Activating | LeaseState::PendingCommit | LeaseState::RollingBack
    ) {
        bail!(
            "lease is in terminal state {:?}, cannot transition to {:?}",
            record.state,
            new_state
        );
    }

    let mut updated = record;
    updated.state = new_state.clone();
    updated.updated_at = now_ms();
    updated.reason = reason.map(|s| s.to_string());

    persist_lease_atomic(&updated)?;

    store.leases.insert(operation_id.to_string(), updated.clone());
    if store.active_pending.as_deref() == Some(operation_id) {
        store.active_pending = None;
    }

    Ok(updated)
}

/// Rollback 租约（API 回滚端点在切换 profile 后调用，仅做状态转移）
pub fn rollback_lease(operation_id: &str) -> Result<LeaseRecord> {
    claim_rollback(operation_id)?;
    transition_to_terminal(operation_id, LeaseState::RolledBack, None)
}

/// 标记租约已回滚（P0-3，恢复/超时路径：server 完成 profile 切换+验证后调用）
pub fn mark_lease_rolled_back(operation_id: &str) -> Result<LeaseRecord> {
    transition_to_terminal(operation_id, LeaseState::RolledBack, None)
}

/// 标记租约回滚失败（P0-3：server 切换/验证失败时调用，持久化 ROLLBACK_FAILED 保留文件）
pub fn mark_lease_rollback_failed(operation_id: &str, reason: &str) -> Result<LeaseRecord> {
    transition_to_terminal(operation_id, LeaseState::RollbackFailed, Some(reason))
}

/// 扫描所有已过期的 PENDING_COMMIT 租约（后台任务 / 启动时调用）
pub fn scan_expired_leases() -> Vec<LeaseRecord> {
    // Startup recovery owns every unfinished lease until it either verifies a
    // rollback or deliberately leaves writes fail-closed. Letting the periodic
    // scanner compete for the same lease can make recovery observe a lost
    // rollback claim and keep RECOVERY_IN_PROGRESS set after rollback succeeded.
    if is_recovery_in_progress() {
        return Vec::new();
    }

    let now = now_ms();
    let store = LEASES.lock();
    store
        .leases
        .values()
        .filter(|r| {
            (r.state == LeaseState::PendingCommit && now >= r.deadline)
                || (r.state == LeaseState::Activating && now >= r.created_at.saturating_add(MAX_ROLLBACK_AFTER_MS))
        })
        .cloned()
        .collect()
}

/// 启动时恢复 (P0-3)
///
/// 1. 设置 recovery_in_progress = true
/// 2. 扫描所有租约文件（fail-closed：损坏文件直接 Err）
/// 3. PENDING_COMMIT → 加入 needs_rollback 列表
/// 4. 所有有效记录加载到内存（供状态查询）
/// 5. recovery_in_progress 保持 true，直到 server 调用 `end_recovery()` / `set_recovery_in_progress(false)`
pub fn recover_leases_on_startup() -> Result<Vec<LeaseRecord>> {
    set_recovery_in_progress(true);

    let dir = leases_dir()?;
    if !dir.exists() {
        return Ok(Vec::new());
    }

    let mut loaded: Vec<LeaseRecord> = Vec::new();
    let mut needs_rollback: Vec<LeaseRecord> = Vec::new();

    for entry in std::fs::read_dir(&dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }

        let record =
            read_lease_file_safe(&path).with_context(|| format!("failed to load lease file {}", path.display()))?;

        if record.state == LeaseState::RollbackFailed {
            bail!(
                "unresolved ROLLBACK_FAILED lease blocks adapter writes: {}",
                record.operation_id
            );
        }
        if matches!(
            record.state,
            LeaseState::Activating | LeaseState::PendingCommit | LeaseState::RollingBack
        ) {
            needs_rollback.push(record.clone());
        }
        loaded.push(record);
    }

    let mut store = LEASES.lock();
    for record in loaded {
        store.leases.insert(record.operation_id.clone(), record);
    }

    Ok(needs_rollback)
}

/// 清理过期租约文件（审计保留期过后删除，P1-3.7）
///
/// 删除 mtime 早于 `now - retention_ms` 的 `.json` 文件，并从内存中移除。
/// 默认保留期 7 天（`DEFAULT_LEASE_RETENTION_MS`）。
pub fn cleanup_old_leases(retention_ms: u64) -> Result<()> {
    let dir = leases_dir()?;
    if !dir.exists() {
        return Ok(());
    }
    let now = now_ms();
    let cutoff = now.saturating_sub(retention_ms);

    let mut to_remove: Vec<PathBuf> = Vec::new();
    for entry in std::fs::read_dir(&dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let meta = match entry.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        let mtime_ms = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let terminal_and_resolved = read_lease_file_safe(&path)
            .map(|record| matches!(record.state, LeaseState::Committed | LeaseState::RolledBack))
            .unwrap_or(false);
        if terminal_and_resolved && mtime_ms < cutoff {
            to_remove.push(path);
        }
    }

    let mut store = LEASES.lock();
    for path in &to_remove {
        let _ = std::fs::remove_file(path);
        if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
            store.leases.remove(stem);
            if store.active_pending.as_deref() == Some(stem) {
                store.active_pending = None;
            }
        }
    }

    Ok(())
}

#[cfg(test)]
#[cfg(unix)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::AtomicU64;

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn reset_test_state() {
        let mut store = LEASES.lock();
        store.leases.clear();
        store.active_pending = None;
        RECOVERY_IN_PROGRESS.store(false, Ordering::SeqCst);
    }

    struct HomeGuard {
        original: Option<std::string::String>,
        temp: PathBuf,
    }

    impl HomeGuard {
        fn new() -> Self {
            let id = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
            let temp = std::env::temp_dir().join(format!("adapter_lease_test_{}_{}", std::process::id(), id));
            let _ = std::fs::remove_dir_all(&temp);
            std::fs::create_dir_all(&temp).unwrap();
            let original = std::env::var("HOME").ok();
            // SAFETY: tests are single-threaded (TEST_LOCK serializes access).
            unsafe {
                std::env::set_var("HOME", &temp);
            }
            Self { original, temp }
        }
    }

    impl Drop for HomeGuard {
        fn drop(&mut self) {
            if let Some(h) = &self.original {
                // SAFETY: tests are single-threaded (TEST_LOCK serializes access).
                unsafe {
                    std::env::set_var("HOME", h);
                }
            } else {
                // SAFETY: tests are single-threaded (TEST_LOCK serializes access).
                unsafe {
                    std::env::remove_var("HOME");
                }
            }
            let _ = std::fs::remove_dir_all(&self.temp);
        }
    }

    fn file_mode(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    fn lease_path(operation_id: &str) -> PathBuf {
        leases_dir().unwrap().join(format!("{operation_id}.json"))
    }

    fn write_file_0600(path: &Path, content: &[u8]) {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .unwrap();
        f.write_all(content).unwrap();
    }

    #[test]
    fn is_safe_operation_id_accepts_alphanumeric_underscore_hyphen() {
        assert!(is_safe_operation_id("op_123_abc"));
        assert!(is_safe_operation_id("op-456"));
        assert!(is_safe_operation_id("ABCdef0"));
    }

    #[test]
    fn unsafe_operation_id_rejected() {
        assert!(!is_safe_operation_id(""));
        assert!(!is_safe_operation_id("../etc/passwd"));
        assert!(!is_safe_operation_id("a/b"));
        assert!(!is_safe_operation_id("a;b"));
        assert!(!is_safe_operation_id("a.b"));
        assert!(!is_safe_operation_id("a b"));

        // persist_lease_atomic 拒绝不安全的 operation_id
        let _guard = TEST_LOCK.lock();
        reset_test_state();
        let _home = HomeGuard::new();
        let record = LeaseRecord {
            operation_id: "../evil".to_string(),
            previous_profile_uid: "prev".to_string(),
            target_profile_uid: "tgt".to_string(),
            created_at: now_ms(),
            deadline: now_ms() + 30_000,
            rollback_after_ms: 30_000,
            state: LeaseState::PendingCommit,
            updated_at: now_ms(),
            reason: None,
        };
        assert!(persist_lease_atomic(&record).is_err());
    }

    #[test]
    fn prepare_lease_creates_valid_record() {
        let _guard = TEST_LOCK.lock();
        reset_test_state();
        let _home = HomeGuard::new();

        let lease = prepare_lease("prev-uid", "target-uid", 30_000).unwrap();
        assert_eq!(lease.state, LeaseState::Activating);
        assert_eq!(lease.deadline, 0);
        assert_eq!(lease.previous_profile_uid, "prev-uid");
        assert_eq!(lease.target_profile_uid, "target-uid");

        // 文件存在且权限 0600
        let path = lease_path(&lease.operation_id);
        assert!(path.exists(), "lease file should exist");
        assert_eq!(file_mode(&path), 0o600, "lease file mode must be 0600");

        // 目录权限 0700
        let dir = leases_dir().unwrap();
        assert_eq!(file_mode(&dir), 0o700, "leases dir mode must be 0700");

        // 内存中可查
        assert!(get_lease(&lease.operation_id).is_some());
        assert!(block_new_activations());
    }

    #[test]
    fn second_prepare_lease_while_pending_is_rejected() {
        let _guard = TEST_LOCK.lock();
        reset_test_state();
        let _home = HomeGuard::new();

        let _first = prepare_lease("prev-uid", "target-uid", 30_000).unwrap();
        let second = prepare_lease("prev-uid-2", "target-uid-2", 30_000);
        assert!(second.is_err());
        let msg = second.unwrap_err().to_string();
        assert!(
            msg.contains("CONFLICT") || msg.contains("PENDING_COMMIT"),
            "expected conflict, got: {msg}"
        );
    }

    #[test]
    fn commit_lease_succeeds_and_retains_terminal_state() {
        let _guard = TEST_LOCK.lock();
        reset_test_state();
        let _home = HomeGuard::new();

        let lease = prepare_lease("prev-uid", "target-uid", 60_000).unwrap();
        let armed = arm_lease(&lease.operation_id).unwrap();
        assert_eq!(armed.state, LeaseState::PendingCommit);
        let committed = commit_lease(&armed.operation_id).unwrap();
        assert_eq!(committed.state, LeaseState::Committed);

        // active 已清除
        assert!(!block_new_activations());

        // 文件保留终态（审计）
        let path = lease_path(&lease.operation_id);
        assert!(path.exists(), "terminal lease file should be retained");
        let record = read_lease_file_safe(&path).unwrap();
        assert_eq!(record.state, LeaseState::Committed);
    }

    #[test]
    fn commit_before_verified_activation_is_rejected() {
        let _guard = TEST_LOCK.lock();
        reset_test_state();
        let _home = HomeGuard::new();

        let lease = prepare_lease("prev-uid", "target-uid", 60_000).unwrap();
        let result = commit_lease(&lease.operation_id);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Activating"));
        assert_eq!(get_lease(&lease.operation_id).unwrap().state, LeaseState::Activating);
    }

    #[test]
    fn rollback_claim_wins_over_concurrent_commit() {
        let _guard = TEST_LOCK.lock();
        reset_test_state();
        let _home = HomeGuard::new();

        let lease = prepare_lease("prev-uid", "target-uid", 60_000).unwrap();
        arm_lease(&lease.operation_id).unwrap();
        let claimed = claim_rollback(&lease.operation_id).unwrap();
        assert_eq!(claimed.state, LeaseState::RollingBack);
        assert!(commit_lease(&lease.operation_id).is_err());
        assert_eq!(get_lease(&lease.operation_id).unwrap().state, LeaseState::RollingBack);
    }

    #[test]
    fn commit_after_deadline_is_rejected() {
        let _guard = TEST_LOCK.lock();
        reset_test_state();
        let _home = HomeGuard::new();

        // 直接构造一个已过期的 PENDING_COMMIT 记录
        let now = now_ms();
        let record = LeaseRecord {
            operation_id: "op_test_expired".to_string(),
            previous_profile_uid: "prev".to_string(),
            target_profile_uid: "tgt".to_string(),
            created_at: now - 10_000,
            deadline: now - 1, // 已过期
            rollback_after_ms: 30_000,
            state: LeaseState::PendingCommit,
            updated_at: now - 10_000,
            reason: None,
        };
        persist_lease_atomic(&record).unwrap();
        {
            let mut store = LEASES.lock();
            store.leases.insert(record.operation_id.clone(), record.clone());
            store.active_pending = Some(record.operation_id.clone());
        }

        let result = commit_lease("op_test_expired");
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("expired"), "expected expired error, got: {msg}");
    }

    #[test]
    fn expired_scan_is_paused_until_startup_recovery_ends() {
        let _guard = TEST_LOCK.lock();
        reset_test_state();
        let _home = HomeGuard::new();

        let now = now_ms();
        let record = LeaseRecord {
            operation_id: "op_expired_during_recovery".to_string(),
            previous_profile_uid: "prev".to_string(),
            target_profile_uid: "target".to_string(),
            created_at: now.saturating_sub(60_000),
            deadline: now.saturating_sub(1),
            rollback_after_ms: 30_000,
            state: LeaseState::PendingCommit,
            updated_at: now.saturating_sub(30_000),
            reason: None,
        };
        persist_lease_atomic(&record).unwrap();
        {
            let mut store = LEASES.lock();
            store.leases.insert(record.operation_id.clone(), record.clone());
            store.active_pending = Some(record.operation_id.clone());
        }

        set_recovery_in_progress(true);
        assert!(
            scan_expired_leases().is_empty(),
            "periodic scanning must not compete with startup recovery"
        );
        assert_eq!(
            get_lease(&record.operation_id).unwrap().state,
            LeaseState::PendingCommit,
            "the recovery owner must retain the unfinished lease"
        );

        end_recovery();
        let expired = scan_expired_leases();
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].operation_id, record.operation_id);
    }

    #[test]
    fn rollback_lease_succeeds() {
        let _guard = TEST_LOCK.lock();
        reset_test_state();
        let _home = HomeGuard::new();

        let lease = prepare_lease("prev-uid", "target-uid", 30_000).unwrap();
        let rolled = rollback_lease(&lease.operation_id).unwrap();
        assert_eq!(rolled.state, LeaseState::RolledBack);
        assert!(!block_new_activations());

        // 文件保留终态
        let path = lease_path(&lease.operation_id);
        assert!(path.exists());
        let record = read_lease_file_safe(&path).unwrap();
        assert_eq!(record.state, LeaseState::RolledBack);
    }

    #[test]
    fn rollback_failed_persists_state() {
        let _guard = TEST_LOCK.lock();
        reset_test_state();
        let _home = HomeGuard::new();

        let lease = prepare_lease("prev-uid", "target-uid", 30_000).unwrap();
        let failed = mark_lease_rollback_failed(&lease.operation_id, "switch failed").unwrap();
        assert_eq!(failed.state, LeaseState::RollbackFailed);
        assert_eq!(failed.reason.as_deref(), Some("switch failed"));
        assert!(!block_new_activations());

        let path = lease_path(&lease.operation_id);
        assert!(path.exists());
        let record = read_lease_file_safe(&path).unwrap();
        assert_eq!(record.state, LeaseState::RollbackFailed);
        assert_eq!(record.reason.as_deref(), Some("switch failed"));
    }

    #[test]
    fn recover_loads_pending_leases() {
        let _guard = TEST_LOCK.lock();
        reset_test_state();
        let _home = HomeGuard::new();

        // 手动持久化一个 PENDING_COMMIT 租约
        let now = now_ms();
        let record = LeaseRecord {
            operation_id: "op_recover_pending".to_string(),
            previous_profile_uid: "prev".to_string(),
            target_profile_uid: "tgt".to_string(),
            created_at: now,
            deadline: now + 30_000,
            rollback_after_ms: 30_000,
            state: LeaseState::PendingCommit,
            updated_at: now,
            reason: None,
        };
        persist_lease_atomic(&record).unwrap();
        // 清空内存模拟重启
        {
            let mut store = LEASES.lock();
            store.leases.clear();
            store.active_pending = None;
        }

        let needs_rollback = recover_leases_on_startup().unwrap();
        assert_eq!(needs_rollback.len(), 1);
        assert_eq!(needs_rollback[0].operation_id, "op_recover_pending");

        // 已加载到内存
        assert!(get_lease("op_recover_pending").is_some());

        // 恢复标志为 true
        assert!(is_recovery_in_progress());
        end_recovery();
    }

    #[test]
    fn recover_loads_terminal_leases_to_memory() {
        let _guard = TEST_LOCK.lock();
        reset_test_state();
        let _home = HomeGuard::new();

        let now = now_ms();
        let committed = LeaseRecord {
            operation_id: "op_recover_committed".to_string(),
            previous_profile_uid: "prev".to_string(),
            target_profile_uid: "tgt".to_string(),
            created_at: now - 5_000,
            deadline: now + 30_000,
            rollback_after_ms: 30_000,
            state: LeaseState::Committed,
            updated_at: now - 5_000,
            reason: None,
        };
        persist_lease_atomic(&committed).unwrap();
        {
            let mut store = LEASES.lock();
            store.leases.clear();
            store.active_pending = None;
        }

        let needs_rollback = recover_leases_on_startup().unwrap();
        assert!(needs_rollback.is_empty(), "no pending leases expected");

        // 终态租约已加载到内存（供状态查询）
        let loaded = get_lease("op_recover_committed").unwrap();
        assert_eq!(loaded.state, LeaseState::Committed);
        end_recovery();
    }

    #[test]
    fn unresolved_rollback_failure_keeps_recovery_fail_closed() {
        let _guard = TEST_LOCK.lock();
        reset_test_state();
        let _home = HomeGuard::new();

        let now = now_ms();
        let failed = LeaseRecord {
            operation_id: "op_recover_failed".to_string(),
            previous_profile_uid: "prev".to_string(),
            target_profile_uid: "tgt".to_string(),
            created_at: now - 5_000,
            deadline: now - 1,
            rollback_after_ms: 30_000,
            state: LeaseState::RollbackFailed,
            updated_at: now,
            reason: Some("manual recovery required".to_string()),
        };
        persist_lease_atomic(&failed).unwrap();

        let error = recover_leases_on_startup().unwrap_err().to_string();
        assert!(error.contains("ROLLBACK_FAILED"));
        assert!(is_recovery_in_progress());
        assert!(prepare_lease("prev", "target", 30_000).is_err());
        end_recovery();
    }

    #[test]
    fn corrupted_lease_file_is_rejected() {
        let _guard = TEST_LOCK.lock();
        reset_test_state();
        let _home = HomeGuard::new();

        let dir = leases_dir().unwrap();
        std::fs::create_dir_all(&dir).unwrap();
        set_mode(&dir, 0o700).unwrap();

        // 1. 无效 JSON
        let bad_path = dir.join("op_bad_json.json");
        write_file_0600(&bad_path, b"not json");
        assert!(read_lease_file_safe(&bad_path).is_err());

        // 2. 错误的 mode (0644)
        let wrong_mode_path = dir.join("op_wrong_mode.json");
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o644)
                .open(&wrong_mode_path)
                .unwrap();
            let now = now_ms();
            let rec = LeaseRecord {
                operation_id: "op_wrong_mode".to_string(),
                previous_profile_uid: "prev".to_string(),
                target_profile_uid: "tgt".to_string(),
                created_at: now,
                deadline: now + 30_000,
                rollback_after_ms: 30_000,
                state: LeaseState::PendingCommit,
                updated_at: now,
                reason: None,
            };
            f.write_all(serde_json::to_string(&rec).unwrap().as_bytes()).unwrap();
        }
        assert!(read_lease_file_safe(&wrong_mode_path).is_err());

        // 3. symlink（O_NOFOLLOW 拒绝）
        let target_path = dir.join("op_symlink_target.json");
        {
            let now = now_ms();
            let rec = LeaseRecord {
                operation_id: "op_symlink_target".to_string(),
                previous_profile_uid: "prev".to_string(),
                target_profile_uid: "tgt".to_string(),
                created_at: now,
                deadline: now + 30_000,
                rollback_after_ms: 30_000,
                state: LeaseState::PendingCommit,
                updated_at: now,
                reason: None,
            };
            write_file_0600(&target_path, serde_json::to_string(&rec).unwrap().as_bytes());
        }
        let link_path = dir.join("op_symlink.json");
        let _ = std::fs::remove_file(&link_path);
        std::os::unix::fs::symlink(&target_path, &link_path).unwrap();
        assert!(read_lease_file_safe(&link_path).is_err());

        // 4. 文件名与 operation_id 不一致
        let mismatch_path = dir.join("op_mismatch.json");
        {
            let now = now_ms();
            let rec = LeaseRecord {
                operation_id: "op_different_id".to_string(),
                previous_profile_uid: "prev".to_string(),
                target_profile_uid: "tgt".to_string(),
                created_at: now,
                deadline: now + 30_000,
                rollback_after_ms: 30_000,
                state: LeaseState::PendingCommit,
                updated_at: now,
                reason: None,
            };
            write_file_0600(&mismatch_path, serde_json::to_string(&rec).unwrap().as_bytes());
        }
        assert!(read_lease_file_safe(&mismatch_path).is_err());
    }

    #[test]
    fn block_new_activations_during_recovery() {
        let _guard = TEST_LOCK.lock();
        reset_test_state();
        let _home = HomeGuard::new();

        set_recovery_in_progress(true);
        assert!(is_recovery_in_progress());
        assert!(block_new_activations());

        // prepare_lease 被阻止
        let result = prepare_lease("prev", "target", 30_000);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("recovery"), "expected recovery error, got: {msg}");

        // 恢复结束后可正常 prepare
        set_recovery_in_progress(false);
        assert!(!is_recovery_in_progress());
        let lease = prepare_lease("prev", "target", 30_000);
        assert!(lease.is_ok());
    }

    #[test]
    fn cleanup_old_leases_removes_expired_files() {
        let _guard = TEST_LOCK.lock();
        reset_test_state();
        let _home = HomeGuard::new();

        // 创建一个终态租约文件
        let now = now_ms();
        let record = LeaseRecord {
            operation_id: "op_old_committed".to_string(),
            previous_profile_uid: "prev".to_string(),
            target_profile_uid: "tgt".to_string(),
            created_at: now - 8 * 24 * 60 * 60 * 1000,
            deadline: now - 8 * 24 * 60 * 60 * 1000 + 30_000,
            rollback_after_ms: 30_000,
            state: LeaseState::Committed,
            updated_at: now - 8 * 24 * 60 * 60 * 1000,
            reason: None,
        };
        persist_lease_atomic(&record).unwrap();
        {
            let mut store = LEASES.lock();
            store.leases.insert(record.operation_id.clone(), record.clone());
        }

        let path = lease_path("op_old_committed");
        assert!(path.exists());

        // 将 mtime 设为 8 天前（使用 libc::utimensat，避免额外依赖）
        let old_time = SystemTime::now() - std::time::Duration::from_secs(8 * 24 * 60 * 60);
        let c_path = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
        let times = libc::timespec {
            tv_sec: old_time
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0),
            tv_nsec: 0,
        };
        let times_arr = [times, times];
        unsafe {
            libc::utimensat(libc::AT_FDCWD, c_path.as_ptr(), times_arr.as_ptr(), 0);
        }

        cleanup_old_leases(DEFAULT_LEASE_RETENTION_MS).unwrap();
        assert!(!path.exists(), "old lease file should be removed");
        assert!(get_lease("op_old_committed").is_none());
    }
}
