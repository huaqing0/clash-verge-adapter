use crate::process::AsyncHandler;
use crate::singleton;
use crate::utils::notification::{NotificationEvent, notify_event};
use crate::utils::window_manager::WindowManager;
use crate::{config::Config, core::handle, feat, module::lightweight::entry_lightweight_mode};
use anyhow::{Result, anyhow, bail};
use arc_swap::ArcSwap;
use clash_verge_logging::{Type, logging};
use smartstring::alias::String;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fmt,
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use tauri_plugin_global_shortcut::{Code, GlobalShortcutExt as _, ShortcutState};

/// Enum representing all available hotkey functions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HotkeyFunction {
    OpenOrCloseDashboard,
    ClashModeRule,
    ClashModeGlobal,
    ClashModeDirect,
    ToggleSystemProxy,
    ToggleTunMode,
    EntryLightweightMode,
    ReactivateProfiles,
    Quit,
    #[cfg(target_os = "macos")]
    Hide,
}

impl fmt::Display for HotkeyFunction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::OpenOrCloseDashboard => "open_or_close_dashboard",
            Self::ClashModeRule => "clash_mode_rule",
            Self::ClashModeGlobal => "clash_mode_global",
            Self::ClashModeDirect => "clash_mode_direct",
            Self::ToggleSystemProxy => "toggle_system_proxy",
            Self::ToggleTunMode => "toggle_tun_mode",
            Self::EntryLightweightMode => "entry_lightweight_mode",
            Self::ReactivateProfiles => "reactivate_profiles",
            Self::Quit => "quit",
            #[cfg(target_os = "macos")]
            Self::Hide => "hide",
        };
        write!(f, "{s}")
    }
}

impl FromStr for HotkeyFunction {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim() {
            "open_or_close_dashboard" => Ok(Self::OpenOrCloseDashboard),
            "clash_mode_rule" => Ok(Self::ClashModeRule),
            "clash_mode_global" => Ok(Self::ClashModeGlobal),
            "clash_mode_direct" => Ok(Self::ClashModeDirect),
            "toggle_system_proxy" => Ok(Self::ToggleSystemProxy),
            "toggle_tun_mode" => Ok(Self::ToggleTunMode),
            "entry_lightweight_mode" => Ok(Self::EntryLightweightMode),
            "reactivate_profiles" => Ok(Self::ReactivateProfiles),
            "quit" => Ok(Self::Quit),
            #[cfg(target_os = "macos")]
            "hide" => Ok(Self::Hide),
            _ => bail!("invalid hotkey function: {}", s),
        }
    }
}

#[cfg(target_os = "macos")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
/// Enum representing predefined system hotkeys
pub enum SystemHotkey {
    CmdQ,
    CmdW,
}

#[cfg(target_os = "macos")]
impl fmt::Display for SystemHotkey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::CmdQ => "CMD+Q",
            Self::CmdW => "CMD+W",
        };
        write!(f, "{s}")
    }
}

#[cfg(target_os = "macos")]
impl SystemHotkey {
    pub const fn function(self) -> HotkeyFunction {
        match self {
            Self::CmdQ => HotkeyFunction::Quit,
            Self::CmdW => HotkeyFunction::Hide,
        }
    }
}

pub struct Hotkey {
    current: ArcSwap<Vec<String>>,
}

#[async_trait::async_trait]
trait HotkeyRegistrationBackend: Sync {
    fn unregister(&self, hotkey: &str) -> Result<()>;
    async fn register(&self, hotkey: &str, function: &str) -> Result<()>;
    fn is_registered(&self, hotkey: &str) -> bool;
}

struct NativeHotkeyRegistrationBackend<'a> {
    hotkey: &'a Hotkey,
}

#[async_trait::async_trait]
impl HotkeyRegistrationBackend for NativeHotkeyRegistrationBackend<'_> {
    fn unregister(&self, hotkey: &str) -> Result<()> {
        self.hotkey.unregister(hotkey)
    }

    async fn register(&self, hotkey: &str, function: &str) -> Result<()> {
        self.hotkey.register(hotkey, function).await
    }

    fn is_registered(&self, hotkey: &str) -> bool {
        handle::Handle::app_handle().global_shortcut().is_registered(hotkey)
    }
}

impl Hotkey {
    fn new() -> Self {
        Self {
            current: ArcSwap::new(Arc::new(Vec::new())),
        }
    }

    /// Execute the function associated with a hotkey function enum
    fn execute_function(function: HotkeyFunction) {
        match function {
            HotkeyFunction::OpenOrCloseDashboard => {
                AsyncHandler::spawn(async move || {
                    crate::feat::open_or_close_dashboard().await;
                    notify_event(NotificationEvent::DashboardToggled).await;
                });
            }
            HotkeyFunction::ClashModeRule => {
                AsyncHandler::spawn(async move || {
                    feat::change_clash_mode("rule".into()).await;
                    notify_event(NotificationEvent::ClashModeChanged { mode: "Rule" }).await;
                });
            }
            HotkeyFunction::ClashModeGlobal => {
                AsyncHandler::spawn(async move || {
                    feat::change_clash_mode("global".into()).await;
                    notify_event(NotificationEvent::ClashModeChanged { mode: "Global" }).await;
                });
            }
            HotkeyFunction::ClashModeDirect => {
                AsyncHandler::spawn(async move || {
                    feat::change_clash_mode("direct".into()).await;
                    notify_event(NotificationEvent::ClashModeChanged { mode: "Direct" }).await;
                });
            }
            HotkeyFunction::ToggleSystemProxy => {
                AsyncHandler::spawn(async move || {
                    let is_proxy_enabled = feat::toggle_system_proxy().await;
                    notify_event(NotificationEvent::SystemProxyToggled(is_proxy_enabled)).await;
                });
            }
            HotkeyFunction::ToggleTunMode => {
                AsyncHandler::spawn(async move || {
                    let is_tun_enable = feat::toggle_tun_mode(None).await;
                    notify_event(NotificationEvent::TunModeToggled(is_tun_enable)).await;
                });
            }
            HotkeyFunction::EntryLightweightMode => {
                AsyncHandler::spawn(async move || {
                    entry_lightweight_mode().await;
                    notify_event(NotificationEvent::LightweightModeEntered).await;
                });
            }
            HotkeyFunction::ReactivateProfiles => {
                AsyncHandler::spawn(async move || match feat::enhance_profiles().await {
                    Ok(outcome) if outcome.is_valid() => {
                        handle::Handle::refresh_clash();
                        notify_event(NotificationEvent::ProfilesReactivated).await;
                    }
                    Ok(outcome) => {
                        let message = outcome.to_string();
                        logging!(
                            warn,
                            Type::Hotkey,
                            "Hotkey profile reactivation failed validation: {}",
                            message.as_str()
                        );
                        handle::Handle::notice_message("reactivate_profiles::error", message);
                    }
                    Err(err) => {
                        logging!(
                            error,
                            Type::Hotkey,
                            "Failed to reactivate subscriptions via hotkey: {}",
                            err
                        );
                        handle::Handle::notice_message("reactivate_profiles::error", err.to_string());
                    }
                });
            }
            HotkeyFunction::Quit => {
                AsyncHandler::spawn(async move || {
                    notify_event(NotificationEvent::AppQuit).await;
                    feat::quit().await;
                });
            }
            #[cfg(target_os = "macos")]
            HotkeyFunction::Hide => {
                AsyncHandler::spawn(async move || {
                    feat::hide().await;
                    notify_event(NotificationEvent::AppHidden).await;
                });
            }
        }
    }

    #[cfg(target_os = "macos")]
    /// Register a system hotkey using enum
    pub async fn register_system_hotkey(&self, hotkey: SystemHotkey) -> Result<()> {
        let hotkey_str = hotkey.to_string();
        let function = hotkey.function();
        self.register_hotkey_with_function(&hotkey_str, function).await
    }

    #[cfg(target_os = "macos")]
    /// Unregister a system hotkey using enum
    pub fn unregister_system_hotkey(&self, hotkey: SystemHotkey) -> Result<()> {
        let hotkey_str = hotkey.to_string();
        self.unregister(&hotkey_str)
    }

    /// Register a hotkey with function enum
    #[allow(clippy::unused_async)]
    pub async fn register_hotkey_with_function(&self, hotkey: &str, function: HotkeyFunction) -> Result<()> {
        let app_handle = handle::Handle::app_handle();
        let manager = app_handle.global_shortcut();

        logging!(
            debug,
            Type::Hotkey,
            "Attempting to register hotkey: {} for function: {}",
            hotkey,
            function
        );

        if manager.is_registered(hotkey) {
            logging!(
                debug,
                Type::Hotkey,
                "Hotkey {} was already registered, unregistering first",
                hotkey
            );
            manager.unregister(hotkey)?;
        }

        let is_quit = matches!(function, HotkeyFunction::Quit);
        let pressed = AtomicBool::new(false);

        manager.on_shortcut(hotkey, move |_app_handle, hotkey_event, event| match event.state {
            ShortcutState::Released => {
                pressed.store(false, Ordering::Relaxed);
            }
            ShortcutState::Pressed => {
                if pressed.swap(true, Ordering::Relaxed) {
                    logging!(
                        debug,
                        Type::Hotkey,
                        "Ignoring repeated hotkey press: {:?}",
                        hotkey_event
                    );
                    return;
                }

                logging!(debug, Type::Hotkey, "Hotkey pressed: {:?}", hotkey_event);
                let hotkey = hotkey_event.key;
                if hotkey == Code::KeyQ && is_quit {
                    if let Some(window) = WindowManager::get_main_window()
                        && window.is_focused().unwrap_or(false)
                    {
                        logging!(debug, Type::Hotkey, "Executing quit function");
                        Self::execute_function(function);
                    }
                } else {
                    AsyncHandler::spawn(move || async move {
                        logging!(debug, Type::Hotkey, "Executing function directly");

                        let is_enable_global_hotkey =
                            Config::verge().await.data_arc().enable_global_hotkey.unwrap_or(true);

                        if is_enable_global_hotkey {
                            Self::execute_function(function);
                        } else {
                            use crate::utils::window_manager::WindowManager;
                            let window = WindowManager::get_main_window();
                            let is_visible = WindowManager::is_main_window_visible(window.as_ref());
                            let is_focused = WindowManager::is_main_window_focused(window.as_ref());

                            if is_focused && is_visible {
                                Self::execute_function(function);
                            }
                        }
                    });
                }
            }
        })?;

        logging!(
            debug,
            Type::Hotkey,
            "Successfully registered hotkey {} for {}",
            hotkey,
            function
        );
        Ok(())
    }
}

singleton!(Hotkey, INSTANCE);

impl Hotkey {
    pub async fn init(&self, skip: bool) -> Result<()> {
        let verge = Config::verge().await;
        let enable_global_hotkey = verge.latest_arc().enable_global_hotkey.unwrap_or(true);

        logging!(
            debug,
            Type::Hotkey,
            "Initializing global hotkeys: {}",
            enable_global_hotkey
        );

        // Always remember the configured mapping, even when global hotkeys are
        // disabled. Otherwise a later false -> true transition diffs against an
        // empty mapping and can leave unchanged shortcuts unregistered.
        let hotkeys = verge.latest_arc().hotkeys.clone().unwrap_or_default();
        if skip {
            logging!(
                debug,
                Type::Hotkey,
                "skip native registration for {} hotkeys",
                hotkeys.len()
            );
        }
        self.update_registration_state(hotkeys, !skip).await
    }

    pub fn reset(&self) -> Result<()> {
        let app_handle = handle::Handle::app_handle();
        let manager = app_handle.global_shortcut();
        manager.unregister_all()?;
        Ok(())
    }

    /// Register a hotkey with string-based function (backward compatibility)
    pub async fn register(&self, hotkey: &str, func: &str) -> Result<()> {
        let function = HotkeyFunction::from_str(func)?;
        self.register_hotkey_with_function(hotkey, function).await
    }

    pub fn unregister(&self, hotkey: &str) -> Result<()> {
        let app_handle = handle::Handle::app_handle();
        let manager = app_handle.global_shortcut();
        manager.unregister(hotkey)?;
        logging!(debug, Type::Hotkey, "Unregister hotkey {}", hotkey);
        Ok(())
    }

    pub async fn update(&self, new_hotkeys: Vec<String>, should_register: bool) -> Result<()> {
        let backend = NativeHotkeyRegistrationBackend { hotkey: self };
        self.update_with_backend(new_hotkeys, should_register, &backend).await
    }

    pub async fn update_registration_state(&self, new_hotkeys: Vec<String>, should_register: bool) -> Result<()> {
        self.update(new_hotkeys, should_register).await
    }

    pub fn should_register_user_hotkeys(enable_global_hotkey: bool) -> bool {
        if enable_global_hotkey {
            return true;
        }
        let window = WindowManager::get_main_window();
        WindowManager::is_main_window_visible(window.as_ref()) && WindowManager::is_main_window_focused(window.as_ref())
    }

    async fn update_with_backend<B: HotkeyRegistrationBackend>(
        &self,
        new_hotkeys: Vec<String>,
        should_register: bool,
        backend: &B,
    ) -> Result<()> {
        let current_hotkeys = (**self.current.load()).clone();
        let old_map = Self::get_map_from_vec(&current_hotkeys)?;
        let new_map = Self::get_map_from_vec(&new_hotkeys)?;
        let target_map = if should_register {
            new_map.clone()
        } else {
            HashMap::new()
        };
        let initial_registered = old_map
            .iter()
            .filter(|(key, _)| backend.is_registered(key.as_str()))
            .map(|(key, function)| (key.clone(), function.clone()))
            .collect::<HashMap<_, _>>();

        // A registered accelerator that is not part of the currently managed
        // mapping may belong to a system shortcut. Never steal it because its
        // original callback cannot be reconstructed during rollback.
        if let Some(accelerator) = target_map
            .keys()
            .find(|key| !old_map.contains_key(*key) && backend.is_registered(key.as_str()))
        {
            bail!("refusing to replace unmanaged registered hotkey: {accelerator}");
        }

        let mut del = initial_registered
            .iter()
            .filter(|(key, old_function)| target_map.get(*key) != Some(*old_function))
            .map(|(key, _)| key.clone())
            .collect::<Vec<_>>();
        let mut add = target_map
            .iter()
            .filter(|(key, function)| !backend.is_registered(key.as_str()) || old_map.get(*key) != Some(*function))
            .map(|(key, function)| (key.clone(), function.clone()))
            .collect::<Vec<_>>();
        del.sort();
        add.sort_by(|left, right| left.0.cmp(&right.0));
        let mut removed = Vec::new();
        let mut added = Vec::new();

        for key in &del {
            if let Err(error) = backend.unregister(key) {
                let rollback_verified = self
                    .rollback_update(backend, &added, &removed, &initial_registered, &old_map, &new_map)
                    .await;
                return Err(anyhow!(
                    "failed to unregister hotkey {key}: {error}; rollbackVerified={rollback_verified}"
                ));
            }
            if let Some(function) = initial_registered.get(key) {
                removed.push((key.clone(), function.clone()));
            }
        }

        for (key, function) in &add {
            if let Err(error) = backend.register(key, function).await {
                let rollback_verified = self
                    .rollback_update(backend, &added, &removed, &initial_registered, &old_map, &new_map)
                    .await;
                return Err(anyhow!(
                    "failed to register hotkey {key} for {function}: {error}; rollbackVerified={rollback_verified}"
                ));
            }
            added.push((key.clone(), function.clone()));
        }

        if !Self::registration_matches(backend, &target_map, old_map.keys().chain(new_map.keys())) {
            let rollback_verified = self
                .rollback_update(backend, &added, &removed, &initial_registered, &old_map, &new_map)
                .await;
            bail!("native hotkey registration verification failed; rollbackVerified={rollback_verified}");
        }

        self.current.store(Arc::new(new_hotkeys));
        Ok(())
    }

    fn get_map_from_vec(hotkeys: &[String]) -> Result<HashMap<String, String>> {
        let mut map = HashMap::new();
        let mut functions = HashSet::new();

        for hotkey in hotkeys {
            let parts = hotkey.split(',').map(str::trim).collect::<Vec<_>>();
            if parts.len() != 2 || parts[0].is_empty() || parts[1].is_empty() {
                bail!("invalid hotkey configuration entry: {hotkey}");
            }
            HotkeyFunction::from_str(parts[0])?;
            if !functions.insert(parts[0].to_owned()) {
                bail!("duplicate hotkey function: {}", parts[0]);
            }
            if map.insert(parts[1].into(), parts[0].into()).is_some() {
                bail!("duplicate hotkey accelerator: {}", parts[1]);
            }
        }
        Ok(map)
    }

    fn registration_matches<'a, B: HotkeyRegistrationBackend>(
        backend: &B,
        desired: &HashMap<String, String>,
        managed_keys: impl Iterator<Item = &'a String>,
    ) -> bool {
        desired.keys().all(|key| backend.is_registered(key.as_str()))
            && managed_keys
                .filter(|key| !desired.contains_key(*key))
                .all(|key| !backend.is_registered(key.as_str()))
    }

    async fn rollback_update<B: HotkeyRegistrationBackend>(
        &self,
        backend: &B,
        added: &[(String, String)],
        removed: &[(String, String)],
        initial_registered: &HashMap<String, String>,
        old_map: &HashMap<String, String>,
        new_map: &HashMap<String, String>,
    ) -> bool {
        let mut rollback_succeeded = true;
        for (key, _) in added.iter().rev() {
            if backend.unregister(key).is_err() {
                rollback_succeeded = false;
            }
        }
        for (key, function) in removed {
            if backend.register(key, function).await.is_err() {
                rollback_succeeded = false;
            }
        }
        rollback_succeeded
            && Self::registration_matches(backend, initial_registered, old_map.keys().chain(new_map.keys()))
    }

    /// Return only registrations that are both in the committed mapping and
    /// currently confirmed by Tauri's native global shortcut manager.
    pub fn registered_mapping(&self) -> Result<BTreeMap<std::string::String, std::string::String>> {
        let current = self.current.load();
        let mapping = Self::get_map_from_vec(&current)?;
        let manager = handle::Handle::app_handle().global_shortcut();
        let mut registered = BTreeMap::new();
        for (accelerator, function) in mapping {
            if manager.is_registered(accelerator.as_str()) {
                registered.insert(function.to_string(), accelerator.to_string());
            }
        }
        Ok(registered)
    }

    pub fn registration_failures(
        &self,
        desired: &BTreeMap<std::string::String, std::string::String>,
    ) -> Vec<std::string::String> {
        let manager = handle::Handle::app_handle().global_shortcut();
        desired
            .iter()
            .filter_map(|(function, accelerator)| {
                (!manager.is_registered(accelerator.as_str())).then(|| function.clone())
            })
            .collect()
    }
}

impl Drop for Hotkey {
    fn drop(&mut self) {
        let app_handle = handle::Handle::app_handle();
        if let Err(e) = app_handle.global_shortcut().unregister_all() {
            logging!(error, Type::Hotkey, "Error unregistering all hotkeys: {:?}", e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Hotkey, HotkeyRegistrationBackend};
    use anyhow::{Result, bail};
    use parking_lot::Mutex;
    use std::collections::HashSet;
    use std::mem::ManuallyDrop;
    use std::sync::Arc;

    struct FaultInjectingBackend {
        registered: Mutex<HashSet<std::string::String>>,
        fail_register: std::string::String,
    }

    #[async_trait::async_trait]
    impl HotkeyRegistrationBackend for FaultInjectingBackend {
        fn unregister(&self, hotkey: &str) -> Result<()> {
            self.registered.lock().remove(hotkey);
            Ok(())
        }

        async fn register(&self, hotkey: &str, _function: &str) -> Result<()> {
            if hotkey == self.fail_register {
                bail!("injected native registration failure");
            }
            self.registered.lock().insert(hotkey.to_owned());
            Ok(())
        }

        fn is_registered(&self, hotkey: &str) -> bool {
            self.registered.lock().contains(hotkey)
        }
    }

    #[test]
    fn strict_parser_rejects_malformed_and_duplicate_config_without_touching_os() {
        assert!(Hotkey::get_map_from_vec(&["missing-comma".into()]).is_err());
        assert!(
            Hotkey::get_map_from_vec(&[
                "open_or_close_dashboard,CommandOrControl+Shift+V".into(),
                "toggle_system_proxy,CommandOrControl+Shift+V".into(),
            ])
            .is_err()
        );
        assert!(
            Hotkey::get_map_from_vec(&[
                "open_or_close_dashboard,CommandOrControl+Shift+V".into(),
                "open_or_close_dashboard,CommandOrControl+Shift+P".into(),
            ])
            .is_err()
        );
    }

    #[test]
    fn strict_parser_accepts_real_user_config_functions() {
        let mapping = Hotkey::get_map_from_vec(&[
            "open_or_close_dashboard,CommandOrControl+Shift+V".into(),
            "toggle_system_proxy,CommandOrControl+Shift+P".into(),
        ])
        .expect("valid real user mapping");
        assert_eq!(
            mapping.get("CommandOrControl+Shift+V").map(|value| value.as_str()),
            Some("open_or_close_dashboard")
        );
    }

    #[tokio::test]
    async fn partial_native_registration_failure_restores_old_mapping() {
        // Hotkey::drop talks to the real Tauri app handle; keep this isolated
        // fault-injection test entirely on the fake backend.
        let hotkey = ManuallyDrop::new(Hotkey::new());
        let old = vec!["open_or_close_dashboard,CommandOrControl+Shift+A".into()];
        hotkey.current.store(Arc::new(old.clone()));
        let backend = FaultInjectingBackend {
            registered: Mutex::new(HashSet::from(["CommandOrControl+Shift+A".to_owned()])),
            fail_register: "CommandOrControl+Shift+C".to_owned(),
        };

        let error = hotkey
            .update_with_backend(
                vec![
                    "toggle_system_proxy,CommandOrControl+Shift+B".into(),
                    "toggle_tun_mode,CommandOrControl+Shift+C".into(),
                ],
                true,
                &backend,
            )
            .await
            .expect_err("second registration must fail");

        assert!(error.to_string().contains("rollbackVerified=true"));
        assert_eq!(
            backend.registered.lock().clone(),
            HashSet::from(["CommandOrControl+Shift+A".to_owned()])
        );
        assert_eq!(**hotkey.current.load(), old);
    }

    #[tokio::test]
    async fn enabling_reconciles_unchanged_but_missing_native_registrations() {
        let hotkey = ManuallyDrop::new(Hotkey::new());
        let old = vec![
            "open_or_close_dashboard,CmdOrCtrl+Shift+W".into(),
            "toggle_system_proxy,CmdOrCtrl+Shift+B".into(),
        ];
        hotkey.current.store(Arc::new(old));
        let backend = FaultInjectingBackend {
            registered: Mutex::new(HashSet::new()),
            fail_register: "__never__".to_owned(),
        };
        let desired = vec![
            "open_or_close_dashboard,CmdOrCtrl+Shift+U".into(),
            "toggle_system_proxy,CmdOrCtrl+Shift+B".into(),
        ];

        hotkey
            .update_with_backend(desired.clone(), true, &backend)
            .await
            .expect("all desired shortcuts should be registered");

        assert_eq!(
            backend.registered.lock().clone(),
            HashSet::from(["CmdOrCtrl+Shift+U".to_owned(), "CmdOrCtrl+Shift+B".to_owned(),])
        );
        assert_eq!(**hotkey.current.load(), desired);
    }

    #[tokio::test]
    async fn disabling_unregisters_only_managed_user_hotkeys() {
        let hotkey = ManuallyDrop::new(Hotkey::new());
        let configured = vec![
            "open_or_close_dashboard,CmdOrCtrl+Shift+W".into(),
            "toggle_system_proxy,CmdOrCtrl+Shift+B".into(),
        ];
        hotkey.current.store(Arc::new(configured.clone()));
        let backend = FaultInjectingBackend {
            registered: Mutex::new(HashSet::from([
                "CmdOrCtrl+Shift+W".to_owned(),
                "CmdOrCtrl+Shift+B".to_owned(),
                "CMD+Q".to_owned(),
            ])),
            fail_register: "__never__".to_owned(),
        };

        hotkey
            .update_with_backend(configured.clone(), false, &backend)
            .await
            .expect("managed shortcuts should be deactivated");

        assert_eq!(backend.registered.lock().clone(), HashSet::from(["CMD+Q".to_owned()]));
        assert_eq!(**hotkey.current.load(), configured);
    }

    #[tokio::test]
    async fn failed_enable_restores_exact_initial_native_subset() {
        let hotkey = ManuallyDrop::new(Hotkey::new());
        let old = vec![
            "open_or_close_dashboard,CmdOrCtrl+Shift+W".into(),
            "toggle_system_proxy,CmdOrCtrl+Shift+B".into(),
        ];
        hotkey.current.store(Arc::new(old.clone()));
        let backend = FaultInjectingBackend {
            registered: Mutex::new(HashSet::from(["CmdOrCtrl+Shift+B".to_owned()])),
            fail_register: "CmdOrCtrl+Shift+U".to_owned(),
        };

        let error = hotkey
            .update_with_backend(
                vec![
                    "open_or_close_dashboard,CmdOrCtrl+Shift+U".into(),
                    "toggle_system_proxy,CmdOrCtrl+Shift+B".into(),
                ],
                true,
                &backend,
            )
            .await
            .expect_err("registration must fail");

        assert!(error.to_string().contains("rollbackVerified=true"));
        assert_eq!(
            backend.registered.lock().clone(),
            HashSet::from(["CmdOrCtrl+Shift+B".to_owned()])
        );
        assert_eq!(**hotkey.current.load(), old);
    }
}
