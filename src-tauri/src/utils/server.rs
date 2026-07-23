use super::resolve;
use super::{adapter_credentials, adapter_lease};
use crate::{
    cmd::is_port_in_use,
    config::{Config, DEFAULT_PAC, IProfiles, IVerge, IVergeTheme, PrfItem, PrfOption, PrfSelected},
    core::{CoreManager, handle, hotkey::Hotkey},
    feat,
    module::lightweight,
    process::AsyncHandler,
    utils::window_manager::WindowManager,
};
use anyhow::{Result, anyhow, bail};
use clash_verge_logging::{Type, logging, logging_error};
use once_cell::sync::{Lazy, OnceCell};
use parking_lot::Mutex;
use reqwest::ClientBuilder;
use sha2::{Digest as _, Sha256};
use smartstring::alias::String;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::{Duration, Instant};
use tauri::Emitter as _;
use tauri_plugin_mihomo::models::ProxyType;
use tokio::sync::oneshot;
use warp::Filter as _;

#[derive(serde::Deserialize, Debug)]
struct QueryParam {
    param: String,
}

/// Activate endpoint JSON body: `{ rollbackAfterMs?: number }`
#[derive(serde::Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct ActivateBody {
    #[serde(default)]
    rollback_after_ms: Option<u64>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct SelectProxyBody {
    group: String,
    proxy: String,
    expected_profile_uid: Option<String>,
}

#[derive(serde::Deserialize)]
struct BooleanSettingBody {
    value: bool,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClashSettingBody {
    setting: String,
    value: serde_json::Value,
    expected_current: serde_json::Value,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProfileMetadataBody {
    patch: serde_json::Map<std::string::String, serde_json::Value>,
    expected_current: serde_json::Map<std::string::String, serde_json::Value>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProfileFileBody {
    kind: String,
    content: std::string::String,
    expected_fingerprint: String,
}

/// v1.1: Verge Preferences write body.
/// Per v2.3.1 section 6 v1.1-B line 853: must deserialize to a restricted
/// Preferences DTO, NOT accept IVerge or arbitrary JSON mapping.
#[derive(Clone, Debug, PartialEq)]
enum ExpectedField<T> {
    Missing,
    Null,
    Value(T),
}

impl<T> Default for ExpectedField<T> {
    fn default() -> Self {
        Self::Missing
    }
}

impl<'de, T> serde::Deserialize<'de> for ExpectedField<T>
where
    T: serde::Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(match Option::<T>::deserialize(deserializer)? {
            Some(value) => Self::Value(value),
            None => Self::Null,
        })
    }
}

impl<T> ExpectedField<T>
where
    T: serde::Serialize,
{
    fn as_json(&self) -> Option<serde_json::Value> {
        match self {
            Self::Missing => None,
            Self::Null => Some(serde_json::Value::Null),
            Self::Value(value) => serde_json::to_value(value).ok(),
        }
    }
}

impl<T> ExpectedField<T> {
    fn value(&self) -> Option<&T> {
        match self {
            Self::Value(value) => Some(value),
            Self::Missing | Self::Null => None,
        }
    }
}

fn deserialize_present_value<'de, D, T>(deserializer: D) -> std::result::Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

/// Restricted preference patch. Basic/Layout values are non-null. Theme
/// values additionally accept explicit JSON null to restore an unset field.
#[derive(Clone, Debug, Default, serde::Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
struct VergePreferencesPatch {
    #[serde(default, deserialize_with = "deserialize_present_value")]
    language: Option<std::string::String>,
    #[serde(default, deserialize_with = "deserialize_present_value")]
    theme_mode: Option<std::string::String>,
    #[serde(default, deserialize_with = "deserialize_present_value")]
    tray_event: Option<std::string::String>,
    #[serde(default, deserialize_with = "deserialize_present_value")]
    env_type: Option<std::string::String>,
    #[serde(default, deserialize_with = "deserialize_present_value")]
    start_page: Option<std::string::String>,
    #[serde(default)]
    primary_color: ExpectedField<std::string::String>,
    #[serde(default)]
    secondary_color: ExpectedField<std::string::String>,
    #[serde(default)]
    primary_text: ExpectedField<std::string::String>,
    #[serde(default)]
    secondary_text: ExpectedField<std::string::String>,
    #[serde(default)]
    info_color: ExpectedField<std::string::String>,
    #[serde(default)]
    error_color: ExpectedField<std::string::String>,
    #[serde(default)]
    warning_color: ExpectedField<std::string::String>,
    #[serde(default)]
    success_color: ExpectedField<std::string::String>,
    #[serde(default)]
    font_family: ExpectedField<std::string::String>,
    #[serde(default, deserialize_with = "deserialize_present_value")]
    traffic_graph: Option<bool>,
    #[serde(default, deserialize_with = "deserialize_present_value")]
    enable_memory_usage: Option<bool>,
    #[serde(default, deserialize_with = "deserialize_present_value")]
    enable_group_icon: Option<bool>,
    #[serde(default, deserialize_with = "deserialize_present_value")]
    pause_render_traffic_stats_on_blur: Option<bool>,
    #[serde(default, deserialize_with = "deserialize_present_value")]
    collapse_navbar: Option<bool>,
    #[serde(default, deserialize_with = "deserialize_present_value")]
    menu_icon: Option<std::string::String>,
    #[serde(default, deserialize_with = "deserialize_present_value")]
    notice_position: Option<std::string::String>,
    #[serde(default, deserialize_with = "deserialize_present_value")]
    enable_hover_jump_navigator: Option<bool>,
    #[serde(default, deserialize_with = "deserialize_present_value")]
    menu_order: Option<Vec<std::string::String>>,
}

/// Restricted expected-current snapshot. `ExpectedField` distinguishes a
/// missing field from a field whose real current value is null.
#[derive(Clone, Debug, Default, serde::Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
struct VergePreferencesExpectedCurrent {
    #[serde(default)]
    language: ExpectedField<std::string::String>,
    #[serde(default)]
    theme_mode: ExpectedField<std::string::String>,
    #[serde(default)]
    tray_event: ExpectedField<std::string::String>,
    #[serde(default)]
    env_type: ExpectedField<std::string::String>,
    #[serde(default)]
    start_page: ExpectedField<std::string::String>,
    #[serde(default)]
    primary_color: ExpectedField<std::string::String>,
    #[serde(default)]
    secondary_color: ExpectedField<std::string::String>,
    #[serde(default)]
    primary_text: ExpectedField<std::string::String>,
    #[serde(default)]
    secondary_text: ExpectedField<std::string::String>,
    #[serde(default)]
    info_color: ExpectedField<std::string::String>,
    #[serde(default)]
    error_color: ExpectedField<std::string::String>,
    #[serde(default)]
    warning_color: ExpectedField<std::string::String>,
    #[serde(default)]
    success_color: ExpectedField<std::string::String>,
    #[serde(default)]
    font_family: ExpectedField<std::string::String>,
    #[serde(default)]
    traffic_graph: ExpectedField<bool>,
    #[serde(default)]
    enable_memory_usage: ExpectedField<bool>,
    #[serde(default)]
    enable_group_icon: ExpectedField<bool>,
    #[serde(default)]
    pause_render_traffic_stats_on_blur: ExpectedField<bool>,
    #[serde(default)]
    collapse_navbar: ExpectedField<bool>,
    #[serde(default)]
    menu_icon: ExpectedField<std::string::String>,
    #[serde(default)]
    notice_position: ExpectedField<std::string::String>,
    #[serde(default)]
    enable_hover_jump_navigator: ExpectedField<bool>,
    #[serde(default)]
    menu_order: ExpectedField<Vec<std::string::String>>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct VergePreferencesBody {
    patch: VergePreferencesPatch,
    expected_current: VergePreferencesExpectedCurrent,
    expected_owner_fingerprint: std::string::String,
}

/// v1.1: Hotkeys write body.
/// Per v2.3.1 section 6 v1.1-B line 856: hotkeys must go through native
/// registration update with conflict/partial-failure rollback.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct HotkeysBody {
    mapping: BTreeMap<std::string::String, std::string::String>,
    enable_global_hotkey: bool,
    expected_current_mapping: BTreeMap<std::string::String, std::string::String>,
    expected_enable_global: bool,
    expected_owner_fingerprint: std::string::String,
}

impl VergePreferencesPatch {
    fn as_json_map(&self) -> serde_json::Map<std::string::String, serde_json::Value> {
        let mut map = serde_json::Map::new();
        macro_rules! insert_present {
            ($field:ident) => {
                if let Some(value) = &self.$field {
                    map.insert(
                        stringify!($field).to_owned(),
                        serde_json::to_value(value).expect("typed preference must serialize"),
                    );
                }
            };
        }
        insert_present!(language);
        insert_present!(theme_mode);
        insert_present!(tray_event);
        insert_present!(env_type);
        insert_present!(start_page);
        macro_rules! insert_nullable {
            ($field:ident) => {
                if let Some(value) = self.$field.as_json() {
                    map.insert(stringify!($field).to_owned(), value);
                }
            };
        }
        insert_nullable!(primary_color);
        insert_nullable!(secondary_color);
        insert_nullable!(primary_text);
        insert_nullable!(secondary_text);
        insert_nullable!(info_color);
        insert_nullable!(error_color);
        insert_nullable!(warning_color);
        insert_nullable!(success_color);
        insert_nullable!(font_family);
        insert_present!(traffic_graph);
        insert_present!(enable_memory_usage);
        insert_present!(enable_group_icon);
        insert_present!(pause_render_traffic_stats_on_blur);
        insert_present!(collapse_navbar);
        insert_present!(menu_icon);
        insert_present!(notice_position);
        insert_present!(enable_hover_jump_navigator);
        insert_present!(menu_order);
        map
    }

    fn to_iverge(&self, current: &IVerge) -> IVerge {
        let mut patch = IVerge {
            language: self.language.clone().map(Into::into),
            theme_mode: self.theme_mode.clone().map(Into::into),
            tray_event: self.tray_event.clone().map(Into::into),
            env_type: self.env_type.clone().map(Into::into),
            start_page: self.start_page.clone().map(Into::into),
            traffic_graph: self.traffic_graph,
            enable_memory_usage: self.enable_memory_usage,
            enable_group_icon: self.enable_group_icon,
            pause_render_traffic_stats_on_blur: self.pause_render_traffic_stats_on_blur,
            collapse_navbar: self.collapse_navbar,
            menu_icon: self.menu_icon.clone().map(Into::into),
            notice_position: self.notice_position.clone().map(Into::into),
            enable_hover_jump_navigator: self.enable_hover_jump_navigator,
            menu_order: self
                .menu_order
                .clone()
                .map(|items| items.into_iter().map(Into::into).collect()),
            ..IVerge::default()
        };

        if let Some(theme) = self.desired_theme_setting(current) {
            // `IVerge::patch_config` cannot express clearing the outer Option.
            // A fully empty theme is therefore applied temporarily and then
            // collapsed to `None` by `set_verge_preferences` after the native
            // patch path succeeds.
            patch.theme_setting = Some(theme.unwrap_or_default());
        }
        patch
    }

    fn desired_theme_setting(&self, current: &IVerge) -> Option<Option<IVergeTheme>> {
        let mut theme = current.theme_setting.clone().unwrap_or_default();
        let mut changed = false;
        macro_rules! apply_theme_field {
            ($field:ident) => {
                match &self.$field {
                    ExpectedField::Missing => {}
                    ExpectedField::Null => {
                        theme.$field = None;
                        changed = true;
                    }
                    ExpectedField::Value(value) => {
                        theme.$field = Some(value.clone().into());
                        changed = true;
                    }
                }
            };
        }
        apply_theme_field!(primary_color);
        apply_theme_field!(secondary_color);
        apply_theme_field!(primary_text);
        apply_theme_field!(secondary_text);
        apply_theme_field!(info_color);
        apply_theme_field!(error_color);
        apply_theme_field!(warning_color);
        apply_theme_field!(success_color);
        apply_theme_field!(font_family);
        if !changed {
            return None;
        }
        let empty = theme.primary_color.is_none()
            && theme.secondary_color.is_none()
            && theme.primary_text.is_none()
            && theme.secondary_text.is_none()
            && theme.info_color.is_none()
            && theme.error_color.is_none()
            && theme.warning_color.is_none()
            && theme.success_color.is_none()
            && theme.font_family.is_none()
            && theme.css_injection.is_none();
        Some((!empty).then_some(theme))
    }
}

impl VergePreferencesExpectedCurrent {
    fn as_json_map(&self) -> serde_json::Map<std::string::String, serde_json::Value> {
        let mut map = serde_json::Map::new();
        macro_rules! insert_expected {
            ($field:ident) => {
                if let Some(value) = self.$field.as_json() {
                    map.insert(stringify!($field).to_owned(), value);
                }
            };
        }
        insert_expected!(language);
        insert_expected!(theme_mode);
        insert_expected!(tray_event);
        insert_expected!(env_type);
        insert_expected!(start_page);
        insert_expected!(primary_color);
        insert_expected!(secondary_color);
        insert_expected!(primary_text);
        insert_expected!(secondary_text);
        insert_expected!(info_color);
        insert_expected!(error_color);
        insert_expected!(warning_color);
        insert_expected!(success_color);
        insert_expected!(font_family);
        insert_expected!(traffic_graph);
        insert_expected!(enable_memory_usage);
        insert_expected!(enable_group_icon);
        insert_expected!(pause_render_traffic_stats_on_blur);
        insert_expected!(collapse_navbar);
        insert_expected!(menu_icon);
        insert_expected!(notice_position);
        insert_expected!(enable_hover_jump_navigator);
        insert_expected!(menu_order);
        map
    }
}

fn validate_owner_fingerprint(value: &str) -> Result<()> {
    if value.len() != 32 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("expectedOwnerFingerprint must be a 32-character lowercase hex SHA-256 prefix");
    }
    if value.bytes().any(|byte| byte.is_ascii_uppercase()) {
        bail!("expectedOwnerFingerprint must use lowercase hex");
    }
    Ok(())
}

fn valid_hex_color(value: &str) -> bool {
    let Some(hex) = value.strip_prefix('#') else {
        return false;
    };
    matches!(hex.len(), 6 | 8) && hex.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn validate_font_family(value: &str) -> Result<()> {
    if value.len() > 128 {
        bail!("font_family must be at most 128 bytes");
    }
    let lower = value.to_ascii_lowercase();
    if lower.contains("http:")
        || lower.contains("https:")
        || lower.contains("data:")
        || lower.contains("//")
        || value
            .chars()
            .any(|character| character.is_control() || matches!(character, ';' | '{' | '}' | '\\'))
    {
        bail!("font_family contains forbidden URL, CSS, escape, or control syntax");
    }
    Ok(())
}

fn validate_preferences_body(body: &VergePreferencesBody) -> Result<()> {
    validate_owner_fingerprint(&body.expected_owner_fingerprint)?;
    let patch = body.patch.as_json_map();
    let expected = body.expected_current.as_json_map();
    if patch.is_empty() {
        bail!("patch must not be empty");
    }
    let patch_keys = patch.keys().map(std::string::String::as_str).collect::<HashSet<_>>();
    let expected_keys = expected.keys().map(std::string::String::as_str).collect::<HashSet<_>>();
    if patch_keys != expected_keys {
        bail!("expectedCurrent must contain exactly the same fields as patch");
    }

    if let Some(value) = &body.patch.language
        && !matches!(
            value.as_str(),
            "en" | "ru" | "zh" | "fa" | "tt" | "id" | "ar" | "ko" | "tr" | "de" | "es" | "jp" | "zhtw"
        )
    {
        bail!("unsupported language");
    }
    if let Some(value) = &body.patch.theme_mode
        && !matches!(value.as_str(), "light" | "dark" | "system")
    {
        bail!("unsupported theme_mode");
    }
    if let Some(value) = &body.patch.tray_event {
        #[cfg(target_os = "linux")]
        bail!("tray_event is unsupported on Linux");
        #[cfg(not(target_os = "linux"))]
        if !matches!(
            value.as_str(),
            "main_window" | "tray_menu" | "system_proxy" | "tun_mode" | "disable"
        ) {
            bail!("unsupported tray_event");
        }
    }
    if let Some(value) = &body.patch.env_type
        && !matches!(value.as_str(), "bash" | "fish" | "nushell" | "cmd" | "powershell")
    {
        bail!("unsupported env_type");
    }
    if let Some(value) = &body.patch.start_page
        && !matches!(
            value.as_str(),
            "/" | "/proxies" | "/profile" | "/connections" | "/rules" | "/logs" | "/unlock" | "/settings"
        )
    {
        bail!("unsupported start_page");
    }
    for (name, value) in [
        (
            "primary_color",
            body.patch.primary_color.value().map(std::string::String::as_str),
        ),
        (
            "secondary_color",
            body.patch.secondary_color.value().map(std::string::String::as_str),
        ),
        (
            "primary_text",
            body.patch.primary_text.value().map(std::string::String::as_str),
        ),
        (
            "secondary_text",
            body.patch.secondary_text.value().map(std::string::String::as_str),
        ),
        (
            "info_color",
            body.patch.info_color.value().map(std::string::String::as_str),
        ),
        (
            "error_color",
            body.patch.error_color.value().map(std::string::String::as_str),
        ),
        (
            "warning_color",
            body.patch.warning_color.value().map(std::string::String::as_str),
        ),
        (
            "success_color",
            body.patch.success_color.value().map(std::string::String::as_str),
        ),
    ] {
        if let Some(value) = value
            && !valid_hex_color(value)
        {
            bail!("{name} must be #RRGGBB or #RRGGBBAA");
        }
    }
    if let Some(value) = body.patch.font_family.value() {
        validate_font_family(value)?;
    }
    if let Some(value) = &body.patch.menu_icon
        && !matches!(value.as_str(), "monochrome" | "colorful" | "disable")
    {
        bail!("unsupported menu_icon");
    }
    if let Some(value) = &body.patch.notice_position
        && !matches!(
            value.as_str(),
            "top-left" | "top-right" | "bottom-left" | "bottom-right"
        )
    {
        bail!("unsupported notice_position");
    }
    if let Some(items) = &body.patch.menu_order {
        const ALLOWED: &[&str] = &[
            "/",
            "/proxies",
            "/profile",
            "/connections",
            "/rules",
            "/logs",
            "/unlock",
            "/settings",
        ];
        if items.len() > ALLOWED.len() {
            bail!("menu_order has too many entries");
        }
        let mut seen = HashSet::new();
        for item in items {
            if !ALLOWED.contains(&item.as_str()) {
                bail!("unsupported menu_order entry");
            }
            if !seen.insert(item.as_str()) {
                bail!("duplicate menu_order entry");
            }
        }
    }
    Ok(())
}

fn preference_effective_timing(key: &str) -> &'static str {
    // Clash Verge owns one unique `main` WebView. Closing the dashboard hides
    // that WebView and reopening it only shows the same instance; start_page is
    // read by build_new_window(), which runs again on the next application
    // launch rather than on a hide/show cycle.
    if key == "start_page" {
        "NEXT_LAUNCH"
    } else {
        "IMMEDIATE"
    }
}

fn content_fingerprint(content: &str) -> std::string::String {
    hex::encode(Sha256::digest(content.as_bytes()))[..16].to_owned()
}

fn yaml_value_to_json(value: &serde_yaml_ng::Value) -> Option<serde_json::Value> {
    serde_json::to_value(value).ok()
}

fn json_value_to_yaml(value: serde_json::Value) -> Result<serde_yaml_ng::Value> {
    serde_yaml_ng::to_value(value).map_err(|error| anyhow!("invalid setting value: {error}"))
}

fn supported_clash_setting(setting: &str) -> bool {
    matches!(
        setting,
        "unified-delay" | "log-level" | "ipv6" | "tun" | "dns" | "mixed-port"
    )
}

fn validate_clash_setting(setting: &str, value: &serde_json::Value) -> Result<()> {
    if !supported_clash_setting(setting) {
        bail!("unsupported Clash setting");
    }
    match setting {
        "unified-delay" | "ipv6" if !value.is_boolean() => bail!("setting must be boolean"),
        "log-level" => {
            let level = value.as_str().ok_or_else(|| anyhow!("log-level must be a string"))?;
            if !matches!(level, "debug" | "info" | "warning" | "error" | "silent") {
                bail!("unsupported log-level");
            }
        }
        "tun" | "dns" if !value.is_object() => bail!("setting must be an object"),
        "mixed-port" => {
            let port = value.as_u64().ok_or_else(|| anyhow!("mixed-port must be an integer"))?;
            if !(1..=65_535).contains(&port) {
                bail!("mixed-port must be between 1 and 65535");
            }
        }
        _ => {}
    }
    Ok(())
}

fn runtime_value_matches_change(
    actual: Option<&serde_json::Value>,
    desired: &serde_json::Value,
    expected_current: Option<&serde_json::Value>,
) -> bool {
    if expected_current == Some(desired) {
        return true;
    }
    match (actual, desired, expected_current) {
        (Some(serde_json::Value::Object(actual)), serde_json::Value::Object(desired), expected) => {
            let expected = expected.and_then(serde_json::Value::as_object);
            desired.iter().all(|(key, desired_value)| {
                let expected_value = expected.and_then(|object| object.get(key));
                if expected_value == Some(desired_value) {
                    return true;
                }
                match actual.get(key) {
                    Some(actual_value) => {
                        runtime_value_matches_change(Some(actual_value), desired_value, expected_value)
                    }
                    // Mihomo omits several false-valued TUN defaults from
                    // /configs. Absence is therefore equivalent to false.
                    None => desired_value == &serde_json::Value::Bool(false),
                }
            })
        }
        (Some(serde_json::Value::String(actual)), serde_json::Value::String(desired), _) => {
            actual.eq_ignore_ascii_case(desired)
        }
        (Some(actual), desired, _) => actual == desired,
        (None, serde_json::Value::Bool(false), _) => true,
        _ => false,
    }
}

async fn persisted_clash_value(setting: &str) -> Option<serde_json::Value> {
    let content = tokio::fs::read_to_string(crate::utils::dirs::clash_path().ok()?)
        .await
        .ok()?;
    let mapping = serde_yaml_ng::from_str::<serde_yaml_ng::Mapping>(&content).ok()?;
    mapping.get(setting).and_then(yaml_value_to_json)
}

async fn persisted_dns_value() -> Option<serde_json::Value> {
    let path = crate::utils::dirs::app_home_dir()
        .ok()?
        .join(crate::constants::files::DNS_CONFIG);
    let content = tokio::fs::read_to_string(path).await.ok()?;
    let mapping = serde_yaml_ng::from_str::<serde_yaml_ng::Mapping>(&content).ok()?;
    mapping.get("dns").and_then(yaml_value_to_json)
}

async fn runtime_clash_value(setting: &str) -> Option<serde_json::Value> {
    let runtime = Config::runtime().await.latest_arc();
    runtime.config.as_ref()?.get(setting).and_then(yaml_value_to_json)
}

async fn current_clash_value(setting: &str) -> Option<serde_json::Value> {
    if setting == "dns" {
        return persisted_dns_value().await;
    }
    Config::clash()
        .await
        .latest_arc()
        .0
        .get(setting)
        .and_then(yaml_value_to_json)
}

fn adapter_build_id() -> &'static str {
    static BUILD_ID: Lazy<std::string::String> = Lazy::new(|| {
        serde_json::from_str::<serde_json::Value>(include_str!("../../resources/adapter-manifest.json"))
            .ok()
            .and_then(|manifest| manifest.get("adapterBuildId")?.as_str().map(ToOwned::to_owned))
            .unwrap_or_else(|| "invalid-adapter-manifest".to_owned())
    });
    BUILD_ID.as_str()
}

const ADAPTER_TOKEN_ENV: &str = "CLASH_VERGE_ADAPTER_TOKEN";

fn adapter_authorized(header: Option<String>, token: &str) -> bool {
    token.len() >= 32
        && header
            .as_deref()
            .and_then(|value| value.strip_prefix("Bearer "))
            .is_some_and(|candidate| constant_time_eq(candidate.as_bytes(), token.as_bytes()))
}

fn constant_time_eq(candidate: &[u8], expected: &[u8]) -> bool {
    if candidate.len() != expected.len() {
        return false;
    }
    candidate
        .iter()
        .zip(expected)
        .fold(0_u8, |difference, (left, right)| difference | (left ^ right))
        == 0
}

fn is_safe_adapter_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 120
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

fn is_safe_adapter_label(value: &str) -> bool {
    !value.is_empty() && value.chars().count() <= 256 && !value.chars().any(char::is_control)
}

static ADAPTER_RATE_LIMITS: Lazy<Mutex<HashMap<std::string::String, Instant>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// Profile operations may update both persisted Profile data and the active
/// runtime configuration. Keep a UID busy for the complete async handler so a
/// refresh cannot overlap an activation (and vice versa).
static ADAPTER_UID_OPERATIONS: Lazy<Mutex<HashSet<std::string::String>>> = Lazy::new(|| Mutex::new(HashSet::new()));

/// Live Verge mutations share runtime, in-memory drafts, and persisted files.
/// Serialize them globally so a profile activation cannot race a proxy or
/// settings mutation that was validated against the previous active profile.
static ADAPTER_MUTATION_ACTIVE: Lazy<Mutex<bool>> = Lazy::new(|| Mutex::new(false));

struct AdapterMutationGuard;

impl Drop for AdapterMutationGuard {
    fn drop(&mut self) {
        *ADAPTER_MUTATION_ACTIVE.lock() = false;
    }
}

fn try_acquire_adapter_mutation() -> Option<AdapterMutationGuard> {
    let mut active = ADAPTER_MUTATION_ACTIVE.lock();
    if *active {
        return None;
    }
    *active = true;
    Some(AdapterMutationGuard)
}

struct AdapterUidOperationGuard {
    uid: std::string::String,
}

impl Drop for AdapterUidOperationGuard {
    fn drop(&mut self) {
        ADAPTER_UID_OPERATIONS.lock().remove(&self.uid);
    }
}

fn try_acquire_adapter_uid_operation(uid: &str) -> Option<AdapterUidOperationGuard> {
    let mut active = ADAPTER_UID_OPERATIONS.lock();
    if !active.insert(uid.to_owned()) {
        return None;
    }
    Some(AdapterUidOperationGuard { uid: uid.to_owned() })
}

fn adapter_rate_limited(action: &str, uid: &str, minimum_interval: Duration) -> bool {
    let now = Instant::now();
    let key = format!("{action}:{uid}");
    let mut limits = ADAPTER_RATE_LIMITS.lock();
    if limits.len() > 2_048 {
        limits.retain(|_, seen| now.duration_since(*seen) < Duration::from_secs(60));
    }
    if limits
        .get(&key)
        .is_some_and(|seen| now.duration_since(*seen) < minimum_interval)
    {
        return true;
    }
    limits.insert(key, now);
    false
}

fn adapter_reply(status: warp::http::StatusCode, body: serde_json::Value) -> impl warp::Reply {
    warp::reply::with_status(warp::reply::json(&body), status)
}

/// Tauri's WebView emitter synchronously waits for the main thread. Calling it
/// directly from an Adapter HTTP worker can deadlock when the main thread is
/// concurrently serving a WebView URL-scheme request while holding the
/// WebView manager lock. Queue the event onto the main thread and let the HTTP
/// response complete without waiting for JavaScript evaluation.
fn schedule_frontend_event(event: &'static str) -> bool {
    let app_handle = handle::Handle::app_handle().clone();
    let emitter = app_handle.clone();
    app_handle
        .run_on_main_thread(move || {
            if let Err(error) = emitter.emit(event, ()) {
                logging!(warn, Type::Frontend, "Adapter frontend event failed: {error}");
            }
        })
        .is_ok()
}

fn schedule_refresh_clash() -> bool {
    let app_handle = handle::Handle::app_handle().clone();
    app_handle.run_on_main_thread(handle::Handle::refresh_clash).is_ok()
}

fn schedule_refresh_verge() -> bool {
    let app_handle = handle::Handle::app_handle().clone();
    app_handle.run_on_main_thread(handle::Handle::refresh_verge).is_ok()
}

fn schedule_profile_refresh(uid: String) -> bool {
    let app_handle = handle::Handle::app_handle().clone();
    let emitter = app_handle.clone();
    app_handle
        .run_on_main_thread(move || {
            handle::Handle::notify_profile_changed(&uid);
            if let Err(error) = emitter.emit("verge://refresh-profiles", ()) {
                logging!(warn, Type::Frontend, "Adapter profile refresh event failed: {error}");
            }
        })
        .is_ok()
}

/// Serialize a successful operation response using the v1 top-level contract
/// consumed by VergeAdapterClient. Do not wrap these fields in `operation`.
fn lease_success_json(lease: &adapter_lease::LeaseRecord) -> serde_json::Value {
    serde_json::json!({
        "ok": true,
        "operationId": lease.operation_id,
        "previousProfileUid": lease.previous_profile_uid,
        "targetProfileUid": lease.target_profile_uid,
        "createdAt": lease.created_at,
        "deadline": lease.deadline,
        "state": lease.state,
        "updatedAt": lease.updated_at,
        "reason": lease.reason,
    })
}

/// 读取当前激活的 profile UID（用于回滚后 re-verify）。
async fn read_current_profile_uid() -> std::string::String {
    let profiles = Config::profiles().await;
    let profiles_data = profiles.data_arc();
    match &profiles_data.current {
        Some(s) => s.to_string(),
        None => std::string::String::new(),
    }
}

fn selected_proxy(selected: Option<&Vec<PrfSelected>>, group: &str) -> Option<std::string::String> {
    selected?
        .iter()
        .find(|entry| entry.name.as_deref() == Some(group))
        .and_then(|entry| entry.now.as_ref())
        .map(ToString::to_string)
}

fn with_selected_proxy(original: Option<Vec<PrfSelected>>, group: &str, proxy: &str) -> Vec<PrfSelected> {
    let mut selected = original.unwrap_or_default();
    if let Some(entry) = selected.iter_mut().find(|entry| entry.name.as_deref() == Some(group)) {
        entry.now = Some(proxy.into());
    } else {
        selected.push(PrfSelected {
            name: Some(group.into()),
            now: Some(proxy.into()),
        });
    }
    selected
}

async fn read_current_profile_selection() -> Result<(std::string::String, Option<Vec<PrfSelected>>)> {
    let profiles = Config::profiles().await;
    let profiles_data = profiles.latest_arc();
    let uid = profiles_data
        .current
        .as_ref()
        .ok_or_else(|| anyhow!("no active profile"))?
        .to_string();
    let item = profiles_data
        .items
        .as_ref()
        .and_then(|items| items.iter().find(|item| item.uid.as_deref() == Some(uid.as_str())))
        .ok_or_else(|| anyhow!("active profile item is missing"))?;
    Ok((uid, item.selected.clone()))
}

/// Replace the exact `selected` value in both the in-memory profile draft and
/// profiles.yaml. Unlike patch_item this can restore an original `None` value.
async fn replace_profile_selection(uid: &str, selected: Option<Vec<PrfSelected>>) -> Result<()> {
    let uid: String = uid.into();
    Config::profiles()
        .await
        .with_data_modify(|mut profiles| async move {
            let item = profiles
                .items
                .as_mut()
                .and_then(|items| items.iter_mut().find(|item| item.uid.as_ref() == Some(&uid)))
                .ok_or_else(|| anyhow!("active profile item is missing"))?;
            item.selected = selected;
            profiles.save_file().await?;
            Ok((profiles, ()))
        })
        .await
}

async fn read_persisted_profile_selection(uid: &str, group: &str) -> Result<Option<std::string::String>> {
    let path = crate::utils::dirs::profiles_path()?;
    let profiles = crate::utils::help::read_yaml::<IProfiles>(&path).await?;
    let selected = profiles
        .items
        .as_ref()
        .and_then(|items| items.iter().find(|item| item.uid.as_deref() == Some(uid)))
        .and_then(|item| selected_proxy(item.selected.as_ref(), group));
    Ok(selected)
}

async fn read_memory_profile_selection(uid: &str, group: &str) -> Result<Option<std::string::String>> {
    let profiles = Config::profiles().await;
    let profiles_data = profiles.latest_arc();
    let selected = profiles_data
        .items
        .as_ref()
        .and_then(|items| items.iter().find(|item| item.uid.as_deref() == Some(uid)))
        .and_then(|item| selected_proxy(item.selected.as_ref(), group));
    Ok(selected)
}

async fn read_runtime_selection(group: &str) -> Result<(std::string::String, Vec<std::string::String>)> {
    let proxies = handle::Handle::mihomo().await.get_proxies().await?;
    let group_data = proxies
        .proxies
        .get(group)
        .ok_or_else(|| anyhow!("proxy group not found"))?;
    if !matches!(group_data.proxy_type, ProxyType::Selector) {
        bail!("proxy group is not a Selector");
    }
    let current = group_data
        .now
        .as_ref()
        .ok_or_else(|| anyhow!("proxy group current selection is missing"))?
        .to_string();
    let candidates = group_data
        .all
        .as_ref()
        .ok_or_else(|| anyhow!("proxy group candidates are missing"))?
        .iter()
        .map(ToString::to_string)
        .collect();
    Ok((current, candidates))
}

async fn cleanup_previous_proxy_connections(previous_proxy: &str) -> (usize, usize) {
    let mihomo = handle::Handle::mihomo().await;
    let Ok(connections) = mihomo.get_connections().await else {
        return (0, 0);
    };
    let matching = connections
        .connections
        .unwrap_or_default()
        .into_iter()
        .filter(|connection| connection.chains.iter().any(|node| node.as_str() == previous_proxy))
        .collect::<Vec<_>>();
    let attempted = matching.len();
    let mut closed = 0;
    for connection in matching {
        if mihomo.close_connection(&connection.id).await.is_ok() {
            closed += 1;
        }
    }
    (attempted, closed)
}

async fn persisted_allow_lan() -> Result<Option<bool>> {
    let config = crate::utils::help::read_mapping(&crate::utils::dirs::clash_path()?).await?;
    Ok(config.get("allow-lan").and_then(serde_yaml_ng::Value::as_bool))
}

async fn persisted_auto_close_connection() -> Result<Option<bool>> {
    let config = crate::utils::help::read_yaml::<IVerge>(&crate::utils::dirs::verge_path()?).await?;
    Ok(config.auto_close_connection)
}

/// P0-3.4 / P0-3.5: 回滚单个 PENDING_COMMIT 租约（带 re-verify）。
///
/// 顺序：
///   1. 切换 profile 回 `previous_profile_uid`
///   2. 重新读取当前 profile UID 验证等于 `previous_profile_uid`
///   3. 验证通过 → `mark_lease_rolled_back`
///   4. 验证失败 → `mark_lease_rollback_failed`（持久化 ROLLBACK_FAILED，保留文件供审计）
///
/// 返回 `true` 表示回滚成功，`false` 表示回滚失败（已持久化 ROLLBACK_FAILED）。
async fn rollback_lease_with_verify(lease: &adapter_lease::LeaseRecord) -> bool {
    let operation_id: std::string::String = lease.operation_id.as_str().into();
    let claimed = if lease.state == adapter_lease::LeaseState::RollingBack {
        lease.clone()
    } else {
        match adapter_lease::claim_rollback(&operation_id) {
            Ok(record) => record,
            Err(e) => {
                logging!(
                    warn,
                    Type::Setup,
                    "Lease rollback claim rejected: operationId={}, error={}",
                    operation_id,
                    e
                );
                return false;
            }
        }
    };
    let previous_uid: String = claimed.previous_profile_uid.as_str().into();

    // 1. 切换 profile 回 previous
    match crate::cmd::patch_profiles_config_by_profile_index(previous_uid.clone()).await {
        Ok(outcome) if outcome.is_valid() => {
            // 2. 重新读取并验证
            let current = read_current_profile_uid().await;
            if current.as_str() == claimed.previous_profile_uid.as_str() {
                // 3. 验证通过
                if let Err(e) = adapter_lease::mark_lease_rolled_back(&operation_id) {
                    logging!(
                        error,
                        Type::Setup,
                        "Failed to mark lease as rolled back: operationId={}, error={}",
                        operation_id,
                        e
                    );
                    return false;
                }
                logging!(
                    info,
                    Type::Setup,
                    "Lease rolled back successfully: operationId={}",
                    operation_id
                );
                true
            } else {
                // 4. 验证失败
                let reason = format!(
                    "re-verify failed: expected={}, got={}",
                    claimed.previous_profile_uid, current
                );
                logging!(
                    error,
                    Type::Setup,
                    "Lease rollback verification failed: operationId={}, {}",
                    operation_id,
                    reason
                );
                if let Err(e) = adapter_lease::mark_lease_rollback_failed(&operation_id, &reason) {
                    logging!(
                        error,
                        Type::Setup,
                        "Failed to mark lease as rollback_failed: operationId={}, error={}",
                        operation_id,
                        e
                    );
                }
                false
            }
        }
        Ok(outcome) => {
            let reason = format!("rollback profile validation failed: {}", outcome);
            logging!(
                error,
                Type::Setup,
                "Lease rollback profile validation failed: operationId={}, {}",
                operation_id,
                reason
            );
            if let Err(e) = adapter_lease::mark_lease_rollback_failed(&operation_id, &reason) {
                logging!(
                    error,
                    Type::Setup,
                    "Failed to mark lease as rollback_failed: operationId={}, error={}",
                    operation_id,
                    e
                );
            }
            false
        }
        Err(e) => {
            let reason = format!("rollback profile switch failed: {}", e);
            logging!(
                error,
                Type::Setup,
                "Lease rollback profile switch failed: operationId={}, {}",
                operation_id,
                reason
            );
            if let Err(e) = adapter_lease::mark_lease_rollback_failed(&operation_id, &reason) {
                logging!(
                    error,
                    Type::Setup,
                    "Failed to mark lease as rollback_failed: operationId={}, error={}",
                    operation_id,
                    e
                );
            }
            false
        }
    }
}

fn adapter_write_blocked() -> bool {
    !resolve::is_resolve_done() || adapter_lease::is_recovery_in_progress()
}

async fn select_proxy_and_sync(body: SelectProxyBody) -> (warp::http::StatusCode, serde_json::Value) {
    if !is_safe_adapter_label(&body.group) || !is_safe_adapter_label(&body.proxy) {
        return (
            warp::http::StatusCode::BAD_REQUEST,
            serde_json::json!({"ok": false, "error": "invalid proxy group or proxy name"}),
        );
    }

    let (profile_uid, original_selected) = match read_current_profile_selection().await {
        Ok(snapshot) => snapshot,
        Err(error) => {
            return (
                warp::http::StatusCode::CONFLICT,
                serde_json::json!({"ok": false, "error": error.to_string()}),
            );
        }
    };
    if body
        .expected_profile_uid
        .as_ref()
        .is_some_and(|expected| expected.as_str() != profile_uid.as_str())
    {
        return (
            warp::http::StatusCode::CONFLICT,
            serde_json::json!({
                "ok": false,
                "error": "active profile changed before proxy selection",
                "currentProfileUid": profile_uid,
            }),
        );
    }

    let _uid_operation = match try_acquire_adapter_uid_operation(&profile_uid) {
        Some(guard) => guard,
        None => {
            return (
                warp::http::StatusCode::CONFLICT,
                serde_json::json!({"ok": false, "error": "UID_OPERATION_BUSY"}),
            );
        }
    };
    let (previous_runtime, candidates) = match read_runtime_selection(&body.group).await {
        Ok(runtime) => runtime,
        Err(error) => {
            return (
                warp::http::StatusCode::BAD_REQUEST,
                serde_json::json!({"ok": false, "error": error.to_string()}),
            );
        }
    };
    if !candidates.iter().any(|candidate| candidate == body.proxy.as_str()) {
        return (
            warp::http::StatusCode::BAD_REQUEST,
            serde_json::json!({"ok": false, "error": "proxy is not a member of the selected group"}),
        );
    }

    if previous_runtime != body.proxy.as_str()
        && let Err(error) = handle::Handle::mihomo()
            .await
            .select_node_for_group(&body.group, &body.proxy)
            .await
    {
        return (
            warp::http::StatusCode::BAD_GATEWAY,
            serde_json::json!({"ok": false, "error": error.to_string()}),
        );
    }

    let updated_selected = with_selected_proxy(original_selected.clone(), &body.group, &body.proxy);
    if let Err(error) = replace_profile_selection(&profile_uid, Some(updated_selected)).await {
        let _ = handle::Handle::mihomo()
            .await
            .select_node_for_group(&body.group, &previous_runtime)
            .await;
        return (
            warp::http::StatusCode::INTERNAL_SERVER_ERROR,
            serde_json::json!({"ok": false, "error": format!("failed to persist proxy selection: {error}")}),
        );
    }

    let runtime_state = read_runtime_selection(&body.group).await.ok().map(|state| state.0);
    let memory_state = read_memory_profile_selection(&profile_uid, &body.group)
        .await
        .ok()
        .flatten();
    let persisted_state = read_persisted_profile_selection(&profile_uid, &body.group)
        .await
        .ok()
        .flatten();
    let profile_still_current = read_current_profile_uid().await == profile_uid;
    let verified = runtime_state.as_deref() == Some(body.proxy.as_str())
        && memory_state.as_deref() == Some(body.proxy.as_str())
        && persisted_state.as_deref() == Some(body.proxy.as_str())
        && profile_still_current;

    if !verified {
        let persist_rollback = replace_profile_selection(&profile_uid, original_selected.clone())
            .await
            .is_ok();
        let runtime_rollback = handle::Handle::mihomo()
            .await
            .select_node_for_group(&body.group, &previous_runtime)
            .await
            .is_ok();
        let rollback_runtime = read_runtime_selection(&body.group).await.ok().map(|state| state.0);
        let rollback_persisted = read_persisted_profile_selection(&profile_uid, &body.group)
            .await
            .ok()
            .flatten();
        let expected_persisted = selected_proxy(original_selected.as_ref(), &body.group);
        let rollback_verified = persist_rollback
            && runtime_rollback
            && rollback_runtime.as_deref() == Some(previous_runtime.as_str())
            && rollback_persisted == expected_persisted;
        return (
            warp::http::StatusCode::INTERNAL_SERVER_ERROR,
            serde_json::json!({
                "ok": false,
                "error": "proxy selection state verification failed",
                "rollbackVerified": rollback_verified,
            }),
        );
    }

    let gui_refresh_emitted = schedule_frontend_event("verge://refresh-proxy-config");
    // Tray updates also cross the Tauri main-thread boundary. Do not hold the
    // Adapter request open on them; the frontend refresh and normal tray
    // lifecycle will rebuild the menu from the already-verified state.
    let tray_synced = false;
    let auto_close_connection = Config::verge().await.latest_arc().auto_close_connection.unwrap_or(true);
    let (connections_matched, connections_closed) = if auto_close_connection && previous_runtime != body.proxy.as_str()
    {
        cleanup_previous_proxy_connections(&previous_runtime).await
    } else {
        (0, 0)
    };

    logging!(
        info,
        Type::Setup,
        "Adapter audit action=proxies.select profileUid={} group={} result=verified",
        profile_uid,
        body.group
    );
    (
        warp::http::StatusCode::OK,
        serde_json::json!({
            "ok": true,
            "profileUid": profile_uid,
            "group": body.group,
            "previous": previous_runtime,
            "requested": body.proxy,
            "runtimeState": runtime_state,
            "memoryState": memory_state,
            "persistedState": persisted_state,
            "verified": true,
            "guiRefreshEmitted": gui_refresh_emitted,
            "traySynced": tray_synced,
            "autoCloseConnection": auto_close_connection,
            "connectionsMatched": connections_matched,
            "connectionsClosed": connections_closed,
        }),
    )
}

async fn set_allow_lan(value: bool) -> (warp::http::StatusCode, serde_json::Value) {
    let previous = Config::clash()
        .await
        .latest_arc()
        .0
        .get("allow-lan")
        .and_then(serde_yaml_ng::Value::as_bool)
        .unwrap_or(false);
    let mut patch = serde_yaml_ng::Mapping::new();
    patch.insert("allow-lan".into(), value.into());
    if let Err(error) = feat::patch_clash(&patch).await {
        return (
            warp::http::StatusCode::INTERNAL_SERVER_ERROR,
            serde_json::json!({"ok": false, "error": error.to_string()}),
        );
    }

    let memory_state = Config::clash()
        .await
        .latest_arc()
        .0
        .get("allow-lan")
        .and_then(serde_yaml_ng::Value::as_bool);
    let persisted_state = persisted_allow_lan().await.ok().flatten();
    let runtime_state = handle::Handle::mihomo()
        .await
        .get_base_config()
        .await
        .ok()
        .map(|config| config.allow_lan);
    let verified = memory_state == Some(value) && persisted_state == Some(value) && runtime_state == Some(value);
    if !verified {
        let mut rollback = serde_yaml_ng::Mapping::new();
        rollback.insert("allow-lan".into(), previous.into());
        let rollback_applied = feat::patch_clash(&rollback).await.is_ok();
        let rollback_runtime = handle::Handle::mihomo()
            .await
            .get_base_config()
            .await
            .ok()
            .map(|config| config.allow_lan);
        return (
            warp::http::StatusCode::INTERNAL_SERVER_ERROR,
            serde_json::json!({
                "ok": false,
                "error": "allow-lan verification failed",
                "rollbackVerified": rollback_applied && rollback_runtime == Some(previous),
            }),
        );
    }
    (
        warp::http::StatusCode::OK,
        serde_json::json!({
            "ok": true,
            "setting": "allow-lan",
            "previous": previous,
            "desiredState": value,
            "memoryState": memory_state,
            "persistedState": persisted_state,
            "runtimeState": runtime_state,
            "verified": true,
        }),
    )
}

async fn set_auto_close_connection(value: bool) -> (warp::http::StatusCode, serde_json::Value) {
    let previous = Config::verge().await.latest_arc().auto_close_connection.unwrap_or(true);
    let patch = IVerge {
        auto_close_connection: Some(value),
        ..IVerge::default()
    };
    if let Err(error) = feat::patch_verge(&patch, false).await {
        return (
            warp::http::StatusCode::INTERNAL_SERVER_ERROR,
            serde_json::json!({"ok": false, "error": error.to_string()}),
        );
    }
    schedule_refresh_verge();
    let memory_state = Config::verge().await.latest_arc().auto_close_connection;
    let persisted_state = persisted_auto_close_connection().await.ok().flatten();
    let verified = memory_state == Some(value) && persisted_state == Some(value);
    if !verified {
        let rollback = IVerge {
            auto_close_connection: Some(previous),
            ..IVerge::default()
        };
        let rollback_applied = feat::patch_verge(&rollback, false).await.is_ok();
        schedule_refresh_verge();
        return (
            warp::http::StatusCode::INTERNAL_SERVER_ERROR,
            serde_json::json!({
                "ok": false,
                "error": "auto-close-connection verification failed",
                "rollbackVerified": rollback_applied,
            }),
        );
    }
    (
        warp::http::StatusCode::OK,
        serde_json::json!({
            "ok": true,
            "setting": "auto-close-connection",
            "previous": previous,
            "desiredState": value,
            "memoryState": memory_state,
            "persistedState": persisted_state,
            "guiRefreshEmitted": true,
            "verified": true,
        }),
    )
}

// ============================================================================
// v1.1-B: Verge Preferences write endpoints
// Per v2.3.1 section 6 v1.1-B line 851-858.
// ============================================================================

/// v1.1: Preferences allowlist. Only these keys are accepted by the
/// verge-preferences write endpoint. Keys NOT in this set are rejected.
/// Per v2.3.1 section 6 v1.1 line 833-836.
const VERGE_PREFERENCES_ALLOWLIST: &[&str] = &[
    // Basic
    "language",
    "theme_mode",
    "tray_event",
    "env_type",
    "start_page",
    // Theme (nested under theme_setting in IVerge)
    "primary_color",
    "secondary_color",
    "primary_text",
    "secondary_text",
    "info_color",
    "error_color",
    "warning_color",
    "success_color",
    "font_family",
    // Layout
    "traffic_graph",
    "enable_memory_usage",
    "enable_group_icon",
    "pause_render_traffic_stats_on_blur",
    "collapse_navbar",
    "menu_icon",
    "notice_position",
    "enable_hover_jump_navigator",
    "menu_order",
];

/// Read a single preference value from an IVerge snapshot.
fn read_preference_value(verge: &IVerge, key: &str) -> serde_json::Value {
    match key {
        "language" => serde_json::to_value(&verge.language).unwrap_or(serde_json::Value::Null),
        "theme_mode" => serde_json::to_value(&verge.theme_mode).unwrap_or(serde_json::Value::Null),
        "tray_event" => serde_json::to_value(&verge.tray_event).unwrap_or(serde_json::Value::Null),
        "env_type" => serde_json::to_value(&verge.env_type).unwrap_or(serde_json::Value::Null),
        "start_page" => serde_json::to_value(&verge.start_page).unwrap_or(serde_json::Value::Null),
        "primary_color" => verge
            .theme_setting
            .as_ref()
            .and_then(|t| t.primary_color.as_ref())
            .map(|s| serde_json::Value::String(s.to_string()))
            .unwrap_or(serde_json::Value::Null),
        "secondary_color" => verge
            .theme_setting
            .as_ref()
            .and_then(|t| t.secondary_color.as_ref())
            .map(|s| serde_json::Value::String(s.to_string()))
            .unwrap_or(serde_json::Value::Null),
        "primary_text" => verge
            .theme_setting
            .as_ref()
            .and_then(|t| t.primary_text.as_ref())
            .map(|s| serde_json::Value::String(s.to_string()))
            .unwrap_or(serde_json::Value::Null),
        "secondary_text" => verge
            .theme_setting
            .as_ref()
            .and_then(|t| t.secondary_text.as_ref())
            .map(|s| serde_json::Value::String(s.to_string()))
            .unwrap_or(serde_json::Value::Null),
        "info_color" => verge
            .theme_setting
            .as_ref()
            .and_then(|t| t.info_color.as_ref())
            .map(|s| serde_json::Value::String(s.to_string()))
            .unwrap_or(serde_json::Value::Null),
        "error_color" => verge
            .theme_setting
            .as_ref()
            .and_then(|t| t.error_color.as_ref())
            .map(|s| serde_json::Value::String(s.to_string()))
            .unwrap_or(serde_json::Value::Null),
        "warning_color" => verge
            .theme_setting
            .as_ref()
            .and_then(|t| t.warning_color.as_ref())
            .map(|s| serde_json::Value::String(s.to_string()))
            .unwrap_or(serde_json::Value::Null),
        "success_color" => verge
            .theme_setting
            .as_ref()
            .and_then(|t| t.success_color.as_ref())
            .map(|s| serde_json::Value::String(s.to_string()))
            .unwrap_or(serde_json::Value::Null),
        "font_family" => verge
            .theme_setting
            .as_ref()
            .and_then(|t| t.font_family.as_ref())
            .map(|s| serde_json::Value::String(s.to_string()))
            .unwrap_or(serde_json::Value::Null),
        "traffic_graph" => serde_json::to_value(&verge.traffic_graph).unwrap_or(serde_json::Value::Null),
        "enable_memory_usage" => serde_json::to_value(&verge.enable_memory_usage).unwrap_or(serde_json::Value::Null),
        "enable_group_icon" => serde_json::to_value(&verge.enable_group_icon).unwrap_or(serde_json::Value::Null),
        "pause_render_traffic_stats_on_blur" => {
            serde_json::to_value(&verge.pause_render_traffic_stats_on_blur).unwrap_or(serde_json::Value::Null)
        }
        "collapse_navbar" => serde_json::to_value(&verge.collapse_navbar).unwrap_or(serde_json::Value::Null),
        "menu_icon" => verge
            .menu_icon
            .as_ref()
            .map(|s| serde_json::Value::String(s.to_string()))
            .unwrap_or(serde_json::Value::Null),
        "notice_position" => verge
            .notice_position
            .as_ref()
            .map(|s| serde_json::Value::String(s.to_string()))
            .unwrap_or(serde_json::Value::Null),
        "enable_hover_jump_navigator" => {
            serde_json::to_value(&verge.enable_hover_jump_navigator).unwrap_or(serde_json::Value::Null)
        }
        "menu_order" => serde_json::to_value(&verge.menu_order).unwrap_or(serde_json::Value::Null),
        _ => serde_json::Value::Null,
    }
}

/// Build an IVerge patch from a validated preference patch map.
/// Preserves existing theme_setting fields when only some theme keys change.
fn build_verge_preference_patch(
    patch: &serde_json::Map<std::string::String, serde_json::Value>,
    current_verge: &IVerge,
) -> IVerge {
    let mut verge = IVerge::default();
    let mut theme = current_verge.theme_setting.clone().unwrap_or_default();
    let mut has_theme_change = false;

    for (key, value) in patch {
        match key.as_str() {
            "language" => verge.language = serde_json::from_value(value.clone()).unwrap_or(None),
            "theme_mode" => verge.theme_mode = serde_json::from_value(value.clone()).unwrap_or(None),
            "tray_event" => verge.tray_event = serde_json::from_value(value.clone()).unwrap_or(None),
            "env_type" => verge.env_type = serde_json::from_value(value.clone()).unwrap_or(None),
            "start_page" => verge.start_page = serde_json::from_value(value.clone()).unwrap_or(None),
            "primary_color" => {
                theme.primary_color = serde_json::from_value(value.clone()).unwrap_or(None);
                has_theme_change = true;
            }
            "secondary_color" => {
                theme.secondary_color = serde_json::from_value(value.clone()).unwrap_or(None);
                has_theme_change = true;
            }
            "primary_text" => {
                theme.primary_text = serde_json::from_value(value.clone()).unwrap_or(None);
                has_theme_change = true;
            }
            "secondary_text" => {
                theme.secondary_text = serde_json::from_value(value.clone()).unwrap_or(None);
                has_theme_change = true;
            }
            "info_color" => {
                theme.info_color = serde_json::from_value(value.clone()).unwrap_or(None);
                has_theme_change = true;
            }
            "error_color" => {
                theme.error_color = serde_json::from_value(value.clone()).unwrap_or(None);
                has_theme_change = true;
            }
            "warning_color" => {
                theme.warning_color = serde_json::from_value(value.clone()).unwrap_or(None);
                has_theme_change = true;
            }
            "success_color" => {
                theme.success_color = serde_json::from_value(value.clone()).unwrap_or(None);
                has_theme_change = true;
            }
            "font_family" => {
                theme.font_family = serde_json::from_value(value.clone()).unwrap_or(None);
                has_theme_change = true;
            }
            "traffic_graph" => verge.traffic_graph = serde_json::from_value(value.clone()).unwrap_or(None),
            "enable_memory_usage" => verge.enable_memory_usage = serde_json::from_value(value.clone()).unwrap_or(None),
            "enable_group_icon" => verge.enable_group_icon = serde_json::from_value(value.clone()).unwrap_or(None),
            "pause_render_traffic_stats_on_blur" => {
                verge.pause_render_traffic_stats_on_blur = serde_json::from_value(value.clone()).unwrap_or(None)
            }
            "collapse_navbar" => verge.collapse_navbar = serde_json::from_value(value.clone()).unwrap_or(None),
            "menu_icon" => verge.menu_icon = serde_json::from_value(value.clone()).unwrap_or(None),
            "notice_position" => verge.notice_position = serde_json::from_value(value.clone()).unwrap_or(None),
            "enable_hover_jump_navigator" => {
                verge.enable_hover_jump_navigator = serde_json::from_value(value.clone()).unwrap_or(None)
            }
            "menu_order" => verge.menu_order = serde_json::from_value(value.clone()).unwrap_or(None),
            _ => {}
        }
    }

    if has_theme_change {
        verge.theme_setting = Some(theme);
    }

    verge
}

/// Read a preference value from the persisted verge.yaml file.
async fn read_persisted_preference(key: &str) -> serde_json::Value {
    match crate::utils::dirs::verge_path() {
        Ok(path) => match crate::utils::help::read_yaml::<IVerge>(&path).await {
            Ok(config) => read_preference_value(&config, key),
            Err(_) => serde_json::Value::Null,
        },
        Err(_) => serde_json::Value::Null,
    }
}

/// Calculate a real owner fingerprint from verge.yaml file content.
/// Per P0-4: must be from real file content, not a hardcoded string.
async fn compute_verge_fingerprint() -> Result<std::string::String> {
    let path = crate::utils::dirs::verge_path()?;
    let content = tokio::fs::read_to_string(&path)
        .await
        .map_err(|error| anyhow!("failed to read verge.yaml for fingerprint: {error}"))?;
    let hash = Sha256::digest(content.as_bytes());
    Ok(hex::encode(&hash[..16]))
}

/// v1.1-A: GET /adapter/v1/settings/verge-preferences
/// Returns the live memory state (only allowlisted keys).
/// Per v2.3.1 section 6 v1.1-A line 846.
async fn get_verge_preferences() -> (warp::http::StatusCode, serde_json::Value) {
    let owner_fingerprint = match compute_verge_fingerprint().await {
        Ok(fingerprint) => fingerprint,
        Err(error) => {
            return (
                warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({
                    "ok": false,
                    "errorCode": "FINGERPRINT_UNAVAILABLE",
                    "error": error.to_string(),
                }),
            );
        }
    };
    let verge = Config::verge().await.latest_arc();
    let mut memory_state = serde_json::Map::new();
    for key in VERGE_PREFERENCES_ALLOWLIST {
        memory_state.insert((*key).to_string(), read_preference_value(&verge, key));
    }
    // Also include hotkeys and enable_global_hotkey for inspect
    memory_state.insert(
        "hotkeys".to_string(),
        serde_json::to_value(&verge.hotkeys).unwrap_or(serde_json::Value::Null),
    );
    memory_state.insert(
        "enable_global_hotkey".to_string(),
        serde_json::to_value(&verge.enable_global_hotkey).unwrap_or(serde_json::Value::Null),
    );

    // Read persisted state (best-effort)
    let persisted_state = match crate::utils::dirs::verge_path() {
        Ok(path) => match crate::utils::help::read_yaml::<IVerge>(&path).await {
            Ok(config) => {
                let mut persisted = serde_json::Map::new();
                for key in VERGE_PREFERENCES_ALLOWLIST {
                    persisted.insert((*key).to_string(), read_preference_value(&config, key));
                }
                persisted.insert(
                    "hotkeys".to_string(),
                    serde_json::to_value(&config.hotkeys).unwrap_or(serde_json::Value::Null),
                );
                persisted.insert(
                    "enable_global_hotkey".to_string(),
                    serde_json::to_value(&config.enable_global_hotkey).unwrap_or(serde_json::Value::Null),
                );
                Some(serde_json::Value::Object(persisted))
            }
            Err(_) => None,
        },
        Err(_) => None,
    };

    (
        warp::http::StatusCode::OK,
        serde_json::json!({
            "ok": true,
            "memoryState": serde_json::Value::Object(memory_state),
            "persistedState": persisted_state,
            "ownerFingerprint": owner_fingerprint,
        }),
    )
}

/// v1.1-B: POST /adapter/v1/settings/verge-preferences
/// Writes preferences with state drift detection, patch_verge, verification,
/// and compensating rollback. Per v2.3.1 section 6 v1.1-B line 851-858.
async fn set_verge_preferences(body: VergePreferencesBody) -> (warp::http::StatusCode, serde_json::Value) {
    // 1. Reject malformed, unknown, null, and semantically invalid fields
    // before reading or mutating any application state.
    if let Err(error) = validate_preferences_body(&body) {
        return (
            warp::http::StatusCode::BAD_REQUEST,
            serde_json::json!({
                "ok": false,
                "errorCode": "INVALID_REQUEST",
                "error": error.to_string(),
            }),
        );
    }

    // Invalid requests never consume the mutation cooldown.
    if adapter_rate_limited("verge-prefs-write", "global", std::time::Duration::from_secs(1)) {
        return (
            warp::http::StatusCode::TOO_MANY_REQUESTS,
            serde_json::json!({
                "ok": false,
                "errorCode": "RATE_LIMITED",
                "error": "RATE_LIMITED",
                "retryAfterMs": 1000,
            }),
        );
    }

    let owner_fingerprint = match compute_verge_fingerprint().await {
        Ok(fingerprint) => fingerprint,
        Err(error) => {
            return (
                warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({
                    "ok": false,
                    "errorCode": "FINGERPRINT_UNAVAILABLE",
                    "error": error.to_string(),
                }),
            );
        }
    };
    if owner_fingerprint != body.expected_owner_fingerprint {
        return (
            warp::http::StatusCode::CONFLICT,
            serde_json::json!({
                "ok": false,
                "errorCode": "CHANGED",
                "error": "VERGE_OWNER_CHANGED_SINCE_PREVIEW",
                "ownerFingerprint": owner_fingerprint,
            }),
        );
    }

    let patch_map = body.patch.as_json_map();
    let expected_map = body.expected_current.as_json_map();
    let current_verge = (*Config::verge().await.latest_arc()).clone();

    // 2. Lock the previewed memory values as well as the real owner file.
    for (key, expected) in &expected_map {
        let actual = read_preference_value(&current_verge, key);
        if actual != *expected {
            return (
                warp::http::StatusCode::CONFLICT,
                serde_json::json!({
                    "ok": false,
                    "errorCode": "CHANGED",
                    "error": "VERGE_PREFERENCES_CHANGED_SINCE_PREVIEW",
                    "currentState": actual,
                    "key": key,
                }),
            );
        }
    }

    // The file may have diverged from memory even when its fingerprint was
    // previewed correctly. Refuse to overwrite that state.
    for (key, expected) in &expected_map {
        let actual = read_persisted_preference(key).await;
        if actual != *expected {
            return (
                warp::http::StatusCode::CONFLICT,
                serde_json::json!({
                    "ok": false,
                    "errorCode": "CHANGED",
                    "error": "VERGE_PERSISTED_PREFERENCES_CHANGED_SINCE_PREVIEW",
                    "persistedState": actual,
                    "key": key,
                }),
            );
        }
    }

    let desired_theme_setting = body.patch.desired_theme_setting(&current_verge);
    let patch = body.patch.to_iverge(&current_verge);

    // 3. Apply through the native Verge path. Even a reported failure can
    // follow partial OS/UI side effects, so always compensate before returning.
    if let Err(error) = feat::patch_verge(&patch, false).await {
        let rollback = restore_preferences_snapshot(&current_verge, &expected_map).await;
        let rollback_verified = rollback.verified();
        return (
            warp::http::StatusCode::INTERNAL_SERVER_ERROR,
            serde_json::json!({
                "ok": false,
                "errorCode": if rollback_verified { "ROLLED_BACK" } else { "RECOVERY_REQUIRED" },
                "error": format!("patch_verge failed: {error}"),
                "rollbackInvoked": true,
                "rollbackMemoryVerified": rollback.memory_verified,
                "rollbackPersistedVerified": rollback.persisted_verified,
                "rollbackSideEffectsRestored": rollback.side_effect_restore_succeeded,
                "rollbackVerified": rollback_verified,
                "sideEffectState": "UNVERIFIED",
                "manualAction": "Verify the affected preference in the Clash Verge window before retrying.",
                "ownerFingerprint": compute_verge_fingerprint().await.ok(),
            }),
        );
    }

    // `patch_config` treats `None` as "field absent", so an explicitly cleared
    // final theme cannot be represented by the native partial patch alone.
    // Collapse an all-empty theme back to the exact outer `None` state only
    // after the native path succeeds, then persist and verify it transactionally.
    if desired_theme_setting.as_ref().is_some_and(Option::is_none) {
        let verge = Config::verge().await;
        verge.edit_draft(|draft| draft.theme_setting = None);
        verge.apply();
        let exact_snapshot = verge.latest_arc();
        if let Err(error) = exact_snapshot.save_file().await {
            let rollback = restore_preferences_snapshot(&current_verge, &expected_map).await;
            let rollback_verified = rollback.verified();
            return (
                warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({
                    "ok": false,
                    "errorCode": if rollback_verified { "ROLLED_BACK" } else { "RECOVERY_REQUIRED" },
                    "error": format!("failed to persist cleared theme state: {error}"),
                    "rollbackInvoked": true,
                    "rollbackMemoryVerified": rollback.memory_verified,
                    "rollbackPersistedVerified": rollback.persisted_verified,
                    "rollbackSideEffectsRestored": rollback.side_effect_restore_succeeded,
                    "rollbackVerified": rollback_verified,
                    "sideEffectState": "UNVERIFIED",
                    "manualAction": "Verify the affected preference in the Clash Verge window before retrying.",
                    "ownerFingerprint": compute_verge_fingerprint().await.ok(),
                }),
            );
        }
    }

    // 4. Queue a GUI refresh, then independently re-read memory and disk.
    let gui_refresh_emitted = schedule_refresh_verge();
    let memory_verge = Config::verge().await.latest_arc();
    let mut fields = serde_json::Map::new();
    let mut all_verified = true;

    for (key, desired) in &patch_map {
        let previous = read_preference_value(&current_verge, key);
        let memory_state = read_preference_value(&memory_verge, key);
        let persisted_state = read_persisted_preference(key).await;

        let verified = memory_state == *desired && persisted_state == *desired;
        if !verified {
            all_verified = false;
        }

        fields.insert(
            key.to_string(),
            serde_json::json!({
                "previous": previous,
                "desiredState": desired,
                "memoryState": memory_state,
                "persistedState": persisted_state,
                "guiRefreshEmitted": gui_refresh_emitted,
                "sideEffectState": "UNVERIFIED",
                "effectiveTiming": preference_effective_timing(key),
                "verified": verified,
            }),
        );
    }

    // 5. A memory/disk mismatch is a failed transaction. Restore the exact
    // snapshot (including nullable fields) and report GUI/OS state honestly.
    if !all_verified {
        let rollback = restore_preferences_snapshot(&current_verge, &expected_map).await;
        let rollback_verified = rollback.verified();

        return (
            warp::http::StatusCode::INTERNAL_SERVER_ERROR,
            serde_json::json!({
                "ok": false,
                "errorCode": if rollback_verified { "ROLLED_BACK" } else { "RECOVERY_REQUIRED" },
                "error": "verge preferences verification failed",
                "fields": serde_json::Value::Object(fields),
                "rollbackInvoked": true,
                "rollbackMemoryVerified": rollback.memory_verified,
                "rollbackPersistedVerified": rollback.persisted_verified,
                "rollbackSideEffectsRestored": rollback.side_effect_restore_succeeded,
                "rollbackVerified": rollback_verified,
                "sideEffectState": "UNVERIFIED",
                "manualAction": "Verify the affected preference in the Clash Verge window before retrying.",
                "ownerFingerprint": compute_verge_fingerprint().await.ok(),
            }),
        );
    }

    let owner_fingerprint = match compute_verge_fingerprint().await {
        Ok(fingerprint) => fingerprint,
        Err(error) => {
            let rollback = restore_preferences_snapshot(&current_verge, &expected_map).await;
            let rollback_verified = rollback.verified();
            return (
                warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({
                    "ok": false,
                    "errorCode": if rollback_verified { "ROLLED_BACK" } else { "RECOVERY_REQUIRED" },
                    "error": format!("could not fingerprint committed verge.yaml: {error}"),
                    "rollbackInvoked": true,
                    "rollbackMemoryVerified": rollback.memory_verified,
                    "rollbackPersistedVerified": rollback.persisted_verified,
                    "rollbackSideEffectsRestored": rollback.side_effect_restore_succeeded,
                    "rollbackVerified": rollback_verified,
                    "sideEffectState": "UNVERIFIED",
                    "manualAction": "Verify the affected preference in the Clash Verge window before retrying.",
                }),
            );
        }
    };

    (
        warp::http::StatusCode::OK,
        serde_json::json!({
            "ok": true,
            "fields": serde_json::Value::Object(fields),
            "rollbackInvoked": false,
            "rollbackVerified": false,
            "ownerFingerprint": owner_fingerprint,
            "sideEffectState": "UNVERIFIED",
            "guiRefreshQueued": gui_refresh_emitted,
        }),
    )
}

struct PreferencesRollbackEvidence {
    memory_verified: bool,
    persisted_verified: bool,
    side_effect_restore_succeeded: bool,
}

impl PreferencesRollbackEvidence {
    fn verified(&self) -> bool {
        self.memory_verified && self.persisted_verified && self.side_effect_restore_succeeded
    }
}

async fn restore_preferences_snapshot(
    snapshot: &IVerge,
    expected: &serde_json::Map<std::string::String, serde_json::Value>,
) -> PreferencesRollbackEvidence {
    // Replay native side effects for every non-null original value first.
    let rollback_patch = build_verge_preference_patch(expected, snapshot);
    let native_restore_succeeded = feat::patch_verge(&rollback_patch, false).await.is_ok();

    // patch_config cannot express clearing an Option. Force the exact snapshot
    // after the native replay so nullable values are restored too.
    let verge = Config::verge().await;
    verge.edit_draft(|draft| *draft = snapshot.clone());
    verge.apply();
    let persisted_write_succeeded = snapshot.save_file().await.is_ok();
    let gui_refresh_emitted = schedule_refresh_verge();

    let memory = Config::verge().await.latest_arc();
    let mut memory_verified = true;
    let mut persisted_verified = persisted_write_succeeded;
    for (key, expected_value) in expected {
        if read_preference_value(&memory, key) != *expected_value {
            memory_verified = false;
        }
        if read_persisted_preference(key).await != *expected_value {
            persisted_verified = false;
        }
    }

    PreferencesRollbackEvidence {
        memory_verified,
        persisted_verified,
        side_effect_restore_succeeded: native_restore_succeeded && gui_refresh_emitted,
    }
}

/// Convert hotkeys Vec<String> (format: "{func},{key}") to a func->key mapping.
fn canonical_accelerator_variants(accelerator: &str) -> Vec<std::string::String> {
    let mut parts = accelerator.split('+').collect::<Vec<_>>();
    let key = parts.pop().unwrap_or_default().to_ascii_lowercase();
    let mut modifiers = Vec::<&str>::new();
    let mut command_or_control = false;

    for part in parts {
        match part {
            "Command" | "Cmd" | "Super" | "Meta" => modifiers.push("command"),
            "CommandOrControl" | "CommandOrCtrl" | "CmdOrControl" | "CmdOrCtrl" => {
                command_or_control = true;
            }
            "Control" | "Ctrl" => modifiers.push("control"),
            "Alt" | "Option" => modifiers.push("alt"),
            "Shift" => modifiers.push("shift"),
            _ => {}
        }
    }

    let platform_modifiers = if command_or_control {
        vec![Some("command"), Some("control")]
    } else {
        vec![None]
    };
    let mut variants = platform_modifiers
        .into_iter()
        .map(|platform_modifier| {
            let mut normalized = modifiers.clone();
            if let Some(platform_modifier) = platform_modifier {
                normalized.push(platform_modifier);
            }
            normalized.sort_unstable();
            normalized.dedup();
            format!("{}+{}", normalized.join("+"), key)
        })
        .collect::<Vec<_>>();
    variants.sort();
    variants.dedup();
    variants
}

fn accelerator_is_system_reserved(accelerator: &str) -> bool {
    const RESERVED: &[&str] = &[
        "command+q",
        "command+w",
        "command+m",
        "command+h",
        "command+space",
        "command+tab",
        "alt+command+escape",
        "alt+command+space",
        "command+control+q",
        "command+control+space",
        "control+space",
        "alt+control+space",
        "alt+f4",
        "alt+control+del",
        "alt+control+delete",
    ];
    canonical_accelerator_variants(accelerator)
        .iter()
        .any(|variant| RESERVED.contains(&variant.as_str()))
}

fn validate_hotkey_mapping(mapping: &BTreeMap<std::string::String, std::string::String>) -> Result<()> {
    static ACCELERATOR: Lazy<regex::Regex> = Lazy::new(|| {
        regex::Regex::new(
            r"^(CommandOrControl|CommandOrCtrl|CmdOrControl|CmdOrCtrl|Command|Cmd|Super|Meta|Control|Ctrl|Alt|Option|Shift)(\+(CommandOrControl|CommandOrCtrl|CmdOrControl|CmdOrCtrl|Command|Cmd|Super|Meta|Control|Ctrl|Alt|Option|Shift))*\+([A-Za-z0-9]|F([1-9]|1[0-9]|2[0-4])|Space|Enter|Escape|Tab|Backspace|Up|Down|Left|Right|Home|End|PageUp|PageDown)$",
        )
        .expect("hotkey accelerator regex must compile")
    });
    const FUNCTIONS: &[&str] = &[
        "open_or_close_dashboard",
        "clash_mode_rule",
        "clash_mode_global",
        "clash_mode_direct",
        "toggle_system_proxy",
        "toggle_tun_mode",
        "entry_lightweight_mode",
        "reactivate_profiles",
    ];
    let mut accelerators = HashMap::<std::string::String, &str>::new();
    for (function, accelerator) in mapping {
        if !FUNCTIONS.contains(&function.as_str()) {
            bail!("unknown hotkey function: {function}");
        }
        if accelerator.is_empty() || accelerator.len() > 64 || !ACCELERATOR.is_match(accelerator) {
            bail!("invalid accelerator for {function}");
        }
        let canonical_variants = canonical_accelerator_variants(accelerator);
        if accelerator_is_system_reserved(accelerator) {
            bail!("system-reserved accelerator for {function}");
        }
        if let Some(existing_function) = canonical_variants
            .iter()
            .find_map(|variant| accelerators.get(variant).copied())
        {
            bail!("duplicate hotkey accelerator: {accelerator} conflicts with {existing_function}");
        }
        for variant in canonical_variants {
            accelerators.insert(variant, function.as_str());
        }
    }
    Ok(())
}

fn hotkeys_vec_to_mapping(hotkeys: &[String]) -> Result<BTreeMap<std::string::String, std::string::String>> {
    let mut map = BTreeMap::new();
    for entry in hotkeys {
        let parts = entry.split(',').map(str::trim).collect::<Vec<_>>();
        if parts.len() != 2 || parts[0].is_empty() || parts[1].is_empty() {
            bail!("invalid hotkey entry: {entry}");
        }
        if map.insert(parts[0].to_owned(), parts[1].to_owned()).is_some() {
            bail!("duplicate hotkey function: {}", parts[0]);
        }
    }
    validate_hotkey_mapping(&map)?;
    Ok(map)
}

/// Convert a func->key mapping to hotkeys Vec<String> (format: "{func},{key}").
///
/// Keep the persisted order for functions that already exist. A mapping is a
/// semantic object, but Verge stores it as a Vec; sorting that Vec on every
/// write needlessly changes the owner-file fingerprint and prevents an exact
/// value restore from returning to the original bytes. Newly added functions
/// are appended in the BTreeMap's deterministic order.
fn mapping_to_hotkeys_vec(
    mapping: &BTreeMap<std::string::String, std::string::String>,
    current_hotkeys: &[String],
) -> Result<Vec<String>> {
    validate_hotkey_mapping(mapping)?;
    let mut remaining = mapping.clone();
    let mut result = Vec::with_capacity(mapping.len());

    for entry in current_hotkeys {
        let Some((function, _)) = entry.split_once(',') else {
            continue;
        };
        let function = function.trim();
        if let Some(key) = remaining.remove(function) {
            result.push(String::from(format!("{function},{key}").as_str()));
        }
    }

    result.extend(
        remaining
            .into_iter()
            .map(|(function, key)| String::from(format!("{function},{key}").as_str())),
    );
    Ok(result)
}

fn expected_native_hotkey_mapping(
    mapping: &BTreeMap<std::string::String, std::string::String>,
    enable_global_hotkey: bool,
) -> BTreeMap<std::string::String, std::string::String> {
    if Hotkey::should_register_user_hotkeys(enable_global_hotkey) {
        mapping.clone()
    } else {
        BTreeMap::new()
    }
}

/// v1.1-B: POST /adapter/v1/settings/hotkeys
/// Writes hotkey mapping + enable_global_hotkey with state drift detection,
/// native registration (via patch_verge HOTKEY flag), verification, and
/// compensating rollback. Per v2.3.1 section 6 v1.1-B line 856.
async fn set_hotkeys(body: HotkeysBody) -> (warp::http::StatusCode, serde_json::Value) {
    if let Err(error) = validate_owner_fingerprint(&body.expected_owner_fingerprint)
        .and_then(|()| validate_hotkey_mapping(&body.mapping))
        .and_then(|()| validate_hotkey_mapping(&body.expected_current_mapping))
    {
        return (
            warp::http::StatusCode::BAD_REQUEST,
            serde_json::json!({
                "ok": false,
                "errorCode": "INVALID_REQUEST",
                "error": error.to_string(),
            }),
        );
    }

    if adapter_rate_limited("hotkeys-write", "global", std::time::Duration::from_secs(1)) {
        return (
            warp::http::StatusCode::TOO_MANY_REQUESTS,
            serde_json::json!({
                "ok": false,
                "errorCode": "RATE_LIMITED",
                "error": "RATE_LIMITED",
                "retryAfterMs": 1000,
            }),
        );
    }

    let owner_fingerprint = match compute_verge_fingerprint().await {
        Ok(fingerprint) => fingerprint,
        Err(error) => {
            return (
                warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({
                    "ok": false,
                    "errorCode": "FINGERPRINT_UNAVAILABLE",
                    "error": error.to_string(),
                }),
            );
        }
    };
    if owner_fingerprint != body.expected_owner_fingerprint {
        return (
            warp::http::StatusCode::CONFLICT,
            serde_json::json!({
                "ok": false,
                "errorCode": "CHANGED",
                "error": "VERGE_OWNER_CHANGED_SINCE_PREVIEW",
                "ownerFingerprint": owner_fingerprint,
            }),
        );
    }

    let current_verge = (*Config::verge().await.latest_arc()).clone();
    let current_hotkeys = current_verge.hotkeys.clone().unwrap_or_default();
    let current_mapping = match hotkeys_vec_to_mapping(&current_hotkeys) {
        Ok(mapping) => mapping,
        Err(error) => {
            return (
                warp::http::StatusCode::CONFLICT,
                serde_json::json!({
                    "ok": false,
                    "errorCode": "INVALID_CURRENT_STATE",
                    "error": error.to_string(),
                }),
            );
        }
    };
    let current_enable_global = current_verge.enable_global_hotkey.unwrap_or(true);

    // 1. State drift detection
    if body.expected_current_mapping != current_mapping {
        return (
            warp::http::StatusCode::CONFLICT,
            serde_json::json!({
                "ok": false,
                "errorCode": "CHANGED",
                "error": "HOTKEYS_CHANGED_SINCE_PREVIEW",
                "currentMapping": current_mapping,
            }),
        );
    }
    if body.expected_enable_global != current_enable_global {
        return (
            warp::http::StatusCode::CONFLICT,
            serde_json::json!({
                "ok": false,
                "errorCode": "CHANGED",
                "error": "ENABLE_GLOBAL_HOTKEY_CHANGED_SINCE_PREVIEW",
                "currentEnableGlobal": current_enable_global,
            }),
        );
    }

    // 2. Build IVerge patch with hotkeys + enable_global_hotkey
    let desired_vec =
        mapping_to_hotkeys_vec(&body.mapping, &current_hotkeys).expect("validated hotkey mapping must serialize");
    let patch = IVerge {
        hotkeys: Some(desired_vec.clone()),
        enable_global_hotkey: Some(body.enable_global_hotkey),
        ..IVerge::default()
    };

    // 3. Apply via patch_verge (triggers HOTKEY flag -> native registration)
    if let Err(error) = feat::patch_verge(&patch, false).await {
        let rollback = restore_hotkeys_snapshot(&current_verge, &current_mapping).await;
        let expected_native = expected_native_hotkey_mapping(&body.mapping, body.enable_global_hotkey);
        return (
            warp::http::StatusCode::INTERNAL_SERVER_ERROR,
            serde_json::json!({
                "ok": false,
                "errorCode": if rollback.verified { "ROLLED_BACK" } else { "RECOVERY_REQUIRED" },
                "error": format!("patch_verge failed: {error}"),
                "registrationFailures": Hotkey::global().registration_failures(&expected_native),
                "rollbackInvoked": true,
                "rollbackVerified": rollback.verified,
                "rollbackMemoryVerified": rollback.memory_verified,
                "rollbackPersistedVerified": rollback.persisted_verified,
                "rollbackNativeVerified": rollback.native_verified,
                "sideEffectState": if rollback.native_verified { "VERIFIED" } else { "UNVERIFIED" },
                "guiState": "UNVERIFIED",
                "ownerFingerprint": compute_verge_fingerprint().await.ok(),
            }),
        );
    }

    let gui_refresh_emitted = schedule_refresh_verge();

    // 4. Verify: read memory + persisted state
    let memory_verge = Config::verge().await.latest_arc();
    let memory_hotkeys = memory_verge.hotkeys.clone().unwrap_or_default();
    let memory_mapping = hotkeys_vec_to_mapping(&memory_hotkeys).unwrap_or_default();
    let memory_enable_global = memory_verge.enable_global_hotkey.unwrap_or(true);

    let persisted_mapping = match crate::utils::dirs::verge_path() {
        Ok(path) => match crate::utils::help::read_yaml::<IVerge>(&path).await {
            Ok(config) => hotkeys_vec_to_mapping(&config.hotkeys.clone().unwrap_or_default()).unwrap_or_default(),
            Err(_) => BTreeMap::new(),
        },
        Err(_) => BTreeMap::new(),
    };
    let persisted_enable_global = match crate::utils::dirs::verge_path() {
        Ok(path) => match crate::utils::help::read_yaml::<IVerge>(&path).await {
            Ok(config) => config.enable_global_hotkey.unwrap_or(true),
            Err(_) => true,
        },
        Err(_) => false,
    };

    let expected_native_mapping = expected_native_hotkey_mapping(&body.mapping, body.enable_global_hotkey);
    let registered_mapping = Hotkey::global().registered_mapping().unwrap_or_default();
    let registration_failures = Hotkey::global().registration_failures(&expected_native_mapping);
    let native_verified = registered_mapping == expected_native_mapping && registration_failures.is_empty();
    let memory_verified = memory_mapping == body.mapping && memory_enable_global == body.enable_global_hotkey;
    let persisted_verified = persisted_mapping == body.mapping && persisted_enable_global == body.enable_global_hotkey;
    let verified = memory_verified && persisted_verified && native_verified;

    // 5. Compensating rollback on failure
    if !verified {
        let rollback = restore_hotkeys_snapshot(&current_verge, &current_mapping).await;

        return (
            warp::http::StatusCode::INTERNAL_SERVER_ERROR,
            serde_json::json!({
                "ok": false,
                "errorCode": if rollback.verified { "ROLLED_BACK" } else { "RECOVERY_REQUIRED" },
                "error": "hotkeys verification failed",
                "previousMapping": current_mapping,
                "desiredMapping": body.mapping,
                "expectedNativeMapping": expected_native_mapping,
                "registeredMapping": registered_mapping,
                "previousEnableGlobal": current_enable_global,
                "desiredEnableGlobal": body.enable_global_hotkey,
                "memoryEnableGlobal": memory_enable_global,
                "persistedEnableGlobal": persisted_enable_global,
                "nativeRegistrationInvoked": true,
                "guiRefreshEmitted": gui_refresh_emitted,
                "registrationFailures": registration_failures,
                "rollbackInvoked": true,
                "rollbackVerified": rollback.verified,
                "rollbackMemoryVerified": rollback.memory_verified,
                "rollbackPersistedVerified": rollback.persisted_verified,
                "rollbackNativeVerified": rollback.native_verified,
                "sideEffectState": if rollback.native_verified { "VERIFIED" } else { "UNVERIFIED" },
                "guiState": "UNVERIFIED",
                "ownerFingerprint": compute_verge_fingerprint().await.ok(),
            }),
        );
    }

    let owner_fingerprint = match compute_verge_fingerprint().await {
        Ok(fingerprint) => fingerprint,
        Err(error) => {
            let rollback = restore_hotkeys_snapshot(&current_verge, &current_mapping).await;
            return (
                warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({
                    "ok": false,
                    "errorCode": if rollback.verified { "ROLLED_BACK" } else { "RECOVERY_REQUIRED" },
                    "error": format!("could not fingerprint committed verge.yaml: {error}"),
                    "rollbackInvoked": true,
                    "rollbackVerified": rollback.verified,
                    "rollbackMemoryVerified": rollback.memory_verified,
                    "rollbackPersistedVerified": rollback.persisted_verified,
                    "rollbackNativeVerified": rollback.native_verified,
                    "guiState": "UNVERIFIED",
                }),
            );
        }
    };

    // 6. Success response
    (
        warp::http::StatusCode::OK,
        serde_json::json!({
            "ok": true,
            "previousMapping": current_mapping,
            "desiredMapping": body.mapping,
            "expectedNativeMapping": expected_native_mapping,
            "registeredMapping": registered_mapping,
            "previousEnableGlobal": current_enable_global,
            "desiredEnableGlobal": body.enable_global_hotkey,
            "memoryEnableGlobal": memory_enable_global,
            "persistedEnableGlobal": persisted_enable_global,
            "nativeRegistrationInvoked": true,
            "guiRefreshEmitted": gui_refresh_emitted,
            "registrationFailures": registration_failures,
            "rollbackInvoked": false,
            "rollbackVerified": false,
            "ownerFingerprint": owner_fingerprint,
            "sideEffectState": "VERIFIED",
            "guiState": "UNVERIFIED",
            "guiRefreshQueued": gui_refresh_emitted,
        }),
    )
}

struct HotkeysRollbackEvidence {
    memory_verified: bool,
    persisted_verified: bool,
    native_verified: bool,
    verified: bool,
}

async fn restore_hotkeys_snapshot(
    snapshot: &IVerge,
    expected_mapping: &BTreeMap<std::string::String, std::string::String>,
) -> HotkeysRollbackEvidence {
    let rollback_patch = IVerge {
        hotkeys: Some(snapshot.hotkeys.clone().unwrap_or_default()),
        enable_global_hotkey: Some(snapshot.enable_global_hotkey.unwrap_or(true)),
        ..IVerge::default()
    };
    let native_replay_succeeded = feat::patch_verge(&rollback_patch, false).await.is_ok();

    let verge = Config::verge().await;
    verge.edit_draft(|draft| *draft = snapshot.clone());
    verge.apply();
    let persisted_write_succeeded = snapshot.save_file().await.is_ok();
    schedule_refresh_verge();

    let memory = Config::verge().await.latest_arc();
    let memory_mapping = hotkeys_vec_to_mapping(&memory.hotkeys.clone().unwrap_or_default()).ok();
    let memory_verified = memory_mapping.as_ref() == Some(expected_mapping)
        && memory.enable_global_hotkey.unwrap_or(true) == snapshot.enable_global_hotkey.unwrap_or(true);

    let persisted = match crate::utils::dirs::verge_path() {
        Ok(path) => crate::utils::help::read_yaml::<IVerge>(&path).await.ok(),
        Err(_) => None,
    };
    let persisted_verified = persisted_write_succeeded
        && persisted.is_some_and(|config| {
            hotkeys_vec_to_mapping(&config.hotkeys.unwrap_or_default())
                .ok()
                .as_ref()
                == Some(expected_mapping)
                && config.enable_global_hotkey.unwrap_or(true) == snapshot.enable_global_hotkey.unwrap_or(true)
        });
    let snapshot_enable_global = snapshot.enable_global_hotkey.unwrap_or(true);
    let expected_native_mapping = expected_native_hotkey_mapping(expected_mapping, snapshot_enable_global);
    let native_verified = native_replay_succeeded
        && Hotkey::global().registered_mapping().ok().as_ref() == Some(&expected_native_mapping);

    HotkeysRollbackEvidence {
        memory_verified,
        persisted_verified,
        native_verified,
        verified: memory_verified && persisted_verified && native_verified,
    }
}

async fn set_clash_setting(body: ClashSettingBody) -> (warp::http::StatusCode, serde_json::Value) {
    if let Err(error) = validate_clash_setting(&body.setting, &body.value) {
        return (
            warp::http::StatusCode::BAD_REQUEST,
            serde_json::json!({"ok": false, "error": error.to_string()}),
        );
    }

    let previous = match current_clash_value(&body.setting).await {
        Some(value) => value,
        None => {
            return (
                warp::http::StatusCode::CONFLICT,
                serde_json::json!({"ok": false, "error": "setting is unavailable in the current Verge state"}),
            );
        }
    };
    if previous != body.expected_current {
        return (
            warp::http::StatusCode::CONFLICT,
            serde_json::json!({
                "ok": false,
                "error": "SETTING_CHANGED_SINCE_PREVIEW",
                "currentState": previous,
            }),
        );
    }

    let desired_yaml = match json_value_to_yaml(body.value.clone()) {
        Ok(value) => value,
        Err(error) => {
            return (
                warp::http::StatusCode::BAD_REQUEST,
                serde_json::json!({"ok": false, "error": error.to_string()}),
            );
        }
    };

    let apply_result: Result<()> = if body.setting == "dns" {
        let mut dns_document = serde_yaml_ng::Mapping::new();
        dns_document.insert("dns".into(), desired_yaml.clone());
        if let Err(error) = crate::cmd::save_dns_config(dns_document).await {
            Err(anyhow!(error.to_string()))
        } else {
            let enabled = Config::verge().await.latest_arc().enable_dns_settings.unwrap_or(false);
            if enabled {
                match CoreManager::global().update_config_forced().await {
                    Ok(outcome) if outcome.is_valid() => {
                        schedule_refresh_clash();
                        Ok(())
                    }
                    Ok(outcome) => Err(anyhow!("DNS runtime validation failed: {outcome}")),
                    Err(error) => Err(error),
                }
            } else {
                Ok(())
            }
        }
    } else {
        let mut patch = serde_yaml_ng::Mapping::new();
        patch.insert(body.setting.as_str().into(), desired_yaml.clone());
        if let Err(error) = feat::patch_clash(&patch).await {
            Err(error)
        } else if body.setting == "mixed-port" {
            let port = body.value.as_u64().unwrap_or_default() as u16;
            let verge_patch = IVerge {
                verge_mixed_port: Some(port),
                ..IVerge::default()
            };
            feat::patch_verge(&verge_patch, false).await
        } else {
            Ok(())
        }
    };

    if let Err(error) = apply_result {
        let rollback_yaml = json_value_to_yaml(previous.clone());
        let rollback_applied = if let Ok(rollback_value) = rollback_yaml {
            if body.setting == "dns" {
                let mut dns_document = serde_yaml_ng::Mapping::new();
                dns_document.insert("dns".into(), rollback_value);
                crate::cmd::save_dns_config(dns_document).await.is_ok()
                    && CoreManager::global().update_config_forced().await.is_ok()
            } else {
                let mut rollback = serde_yaml_ng::Mapping::new();
                rollback.insert(body.setting.as_str().into(), rollback_value);
                let clash_rollback = feat::patch_clash(&rollback).await.is_ok();
                if body.setting == "mixed-port" {
                    let previous_port = previous.as_u64().unwrap_or_default() as u16;
                    let verge_rollback = IVerge {
                        verge_mixed_port: Some(previous_port),
                        ..IVerge::default()
                    };
                    clash_rollback && feat::patch_verge(&verge_rollback, false).await.is_ok()
                } else {
                    clash_rollback
                }
            }
        } else {
            false
        };
        return (
            warp::http::StatusCode::INTERNAL_SERVER_ERROR,
            serde_json::json!({
                "ok": false,
                "error": error.to_string(),
                "rollbackVerified": rollback_applied && current_clash_value(&body.setting).await == Some(previous),
            }),
        );
    }

    let memory_state = current_clash_value(&body.setting).await;
    let persisted_state = if body.setting == "dns" {
        persisted_dns_value().await
    } else {
        persisted_clash_value(&body.setting).await
    };
    let runtime_state = runtime_clash_value(&body.setting).await;
    let applied_to_runtime =
        body.setting != "dns" || Config::verge().await.latest_arc().enable_dns_settings.unwrap_or(false);
    let runtime_matches =
        runtime_value_matches_change(runtime_state.as_ref(), &body.value, Some(&body.expected_current));
    let verified = memory_state.as_ref() == Some(&body.value)
        && persisted_state.as_ref() == Some(&body.value)
        && (!applied_to_runtime || runtime_matches);

    if !verified {
        let rollback_value = json_value_to_yaml(previous.clone());
        let rollback_applied = if let Ok(rollback_value) = rollback_value {
            if body.setting == "dns" {
                let mut dns_document = serde_yaml_ng::Mapping::new();
                dns_document.insert("dns".into(), rollback_value);
                crate::cmd::save_dns_config(dns_document).await.is_ok()
                    && CoreManager::global().update_config_forced().await.is_ok()
            } else {
                let mut rollback = serde_yaml_ng::Mapping::new();
                rollback.insert(body.setting.as_str().into(), rollback_value);
                feat::patch_clash(&rollback).await.is_ok()
            }
        } else {
            false
        };
        return (
            warp::http::StatusCode::INTERNAL_SERVER_ERROR,
            serde_json::json!({
                "ok": false,
                "error": "Clash setting state verification failed",
                "memoryMatches": memory_state.as_ref() == Some(&body.value),
                "persistedMatches": persisted_state.as_ref() == Some(&body.value),
                "runtimeMatches": !applied_to_runtime || runtime_matches,
                "rollbackVerified": rollback_applied && current_clash_value(&body.setting).await == Some(previous),
            }),
        );
    }

    let gui_refresh_emitted = schedule_frontend_event("verge://refresh-clash-config");
    let tray_synced = false;
    (
        warp::http::StatusCode::OK,
        serde_json::json!({
            "ok": true,
            "setting": body.setting,
            "previous": previous,
            "desiredState": body.value,
            "memoryState": memory_state,
            "persistedState": persisted_state,
            "runtimeState": runtime_state,
            "appliedToRuntime": applied_to_runtime,
            "verified": true,
            "guiRefreshEmitted": gui_refresh_emitted,
            "traySynced": tray_synced,
        }),
    )
}

fn metadata_value(item: &PrfItem, key: &str) -> Option<serde_json::Value> {
    match key {
        "name" => item
            .name
            .as_ref()
            .map(|value| serde_json::Value::String(value.to_string())),
        "desc" => item
            .desc
            .as_ref()
            .map(|value| serde_json::Value::String(value.to_string())),
        "update_interval" => item
            .option
            .as_ref()
            .and_then(|option| option.update_interval)
            .map(serde_json::Value::from),
        _ => None,
    }
}

fn build_metadata_patch(
    original: &PrfItem,
    patch: &serde_json::Map<std::string::String, serde_json::Value>,
) -> Result<PrfItem> {
    let mut result = PrfItem::default();
    for (key, value) in patch {
        match key.as_str() {
            "name" => {
                let text = value.as_str().ok_or_else(|| anyhow!("name must be a string"))?;
                if text.chars().any(char::is_control) || text.chars().count() > 256 {
                    bail!("name is invalid");
                }
                result.name = Some(text.into());
            }
            "desc" => {
                let text = value.as_str().ok_or_else(|| anyhow!("desc must be a string"))?;
                if text.chars().any(char::is_control) || text.chars().count() > 2048 {
                    bail!("desc is invalid");
                }
                result.desc = Some(text.into());
            }
            "update_interval" => {
                let interval = value
                    .as_u64()
                    .ok_or_else(|| anyhow!("update_interval must be a non-negative integer"))?;
                if interval > 31 * 24 * 60 {
                    bail!("update_interval is too large");
                }
                let mut option = original.option.clone().unwrap_or_else(PrfOption::default);
                option.update_interval = Some(interval);
                result.option = Some(option);
            }
            _ => bail!("metadata field is not allowed"),
        }
    }
    if patch.is_empty() {
        bail!("metadata patch must not be empty");
    }
    Ok(result)
}

fn metadata_snapshot(
    item: &PrfItem,
    keys: impl Iterator<Item = std::string::String>,
) -> serde_json::Map<std::string::String, serde_json::Value> {
    keys.map(|key| {
        let value = metadata_value(item, &key).unwrap_or(serde_json::Value::Null);
        (key, value)
    })
    .collect()
}

async fn restore_profile_metadata_exact(uid: &str, original: &PrfItem) -> Result<()> {
    let uid = uid.to_owned();
    let original = original.clone();
    Config::profiles()
        .await
        .with_data_modify(|mut profiles| async move {
            let item = profiles
                .items
                .get_or_insert_with(Vec::new)
                .iter_mut()
                .find(|item| item.uid.as_deref() == Some(uid.as_str()))
                .ok_or_else(|| anyhow!("profile disappeared during metadata rollback"))?;
            item.name = original.name;
            item.desc = original.desc;
            item.option = original.option;
            profiles.save_file().await?;
            Ok((profiles, ()))
        })
        .await
}

async fn update_profile_metadata(
    uid: String,
    body: ProfileMetadataBody,
) -> (warp::http::StatusCode, serde_json::Value) {
    if !is_safe_adapter_id(&uid) {
        return (
            warp::http::StatusCode::BAD_REQUEST,
            serde_json::json!({"ok": false, "error": "invalid profile UID"}),
        );
    }
    let original = {
        let profiles = Config::profiles().await.latest_arc();
        match profiles.get_item(&uid) {
            Ok(item) => item.clone(),
            Err(error) => {
                return (
                    warp::http::StatusCode::NOT_FOUND,
                    serde_json::json!({"ok": false, "error": error.to_string()}),
                );
            }
        }
    };
    let keys = body.patch.keys().cloned().collect::<Vec<_>>();
    let previous = metadata_snapshot(&original, keys.iter().cloned());
    if previous != body.expected_current {
        return (
            warp::http::StatusCode::CONFLICT,
            serde_json::json!({"ok": false, "error": "PROFILE_CHANGED_SINCE_PREVIEW", "currentState": previous}),
        );
    }
    let patch = match build_metadata_patch(&original, &body.patch) {
        Ok(patch) => patch,
        Err(error) => {
            return (
                warp::http::StatusCode::BAD_REQUEST,
                serde_json::json!({"ok": false, "error": error.to_string()}),
            );
        }
    };
    if let Err(error) = crate::cmd::patch_profile(uid.clone(), patch).await {
        return (
            warp::http::StatusCode::INTERNAL_SERVER_ERROR,
            serde_json::json!({"ok": false, "error": error.to_string()}),
        );
    }

    let memory_state = {
        let profiles = Config::profiles().await.latest_arc();
        profiles
            .get_item(&uid)
            .ok()
            .map(|item| metadata_snapshot(item, keys.iter().cloned()))
    };
    let persisted_profiles = IProfiles::new().await;
    let persisted_state = persisted_profiles
        .get_item(&uid)
        .ok()
        .map(|item| metadata_snapshot(item, keys.iter().cloned()));
    let desired = body.patch;
    let verified = memory_state.as_ref() == Some(&desired) && persisted_state.as_ref() == Some(&desired);
    if !verified {
        let rollback_applied = restore_profile_metadata_exact(uid.as_str(), &original).await.is_ok();
        if rollback_applied {
            let _ = crate::core::Timer::global().refresh().await;
        }
        return (
            warp::http::StatusCode::INTERNAL_SERVER_ERROR,
            serde_json::json!({
                "ok": false,
                "error": "profile metadata verification failed",
                "rollbackVerified": rollback_applied,
            }),
        );
    }
    let gui_refresh_emitted = schedule_profile_refresh(uid.clone());
    (
        warp::http::StatusCode::OK,
        serde_json::json!({
            "ok": true,
            "profileUid": uid,
            "previous": previous,
            "desiredState": desired,
            "memoryState": memory_state,
            "persistedState": persisted_state,
            "verified": true,
            "guiRefreshEmitted": gui_refresh_emitted,
        }),
    )
}

fn profile_file_kind_matches(item: &PrfItem, kind: &str) -> bool {
    let item_type = item.itype.as_deref().unwrap_or_default();
    let file = item.file.as_deref().unwrap_or_default();
    match kind {
        "merge" => item_type == "merge",
        "override" => item_type == "script" && (file.ends_with(".yaml") || file.ends_with(".yml")),
        "rules" => item_type == "rules",
        // A workspace write is the generic, optimistic-concurrency protected
        // YAML owner path. Groups, proxies and rules are first-class Profile
        // owners in Clash Verge and are persisted by the same native
        // save_profile_file command. YAML scripts are allowed; JavaScript
        // scripts remain excluded because this endpoint validates YAML.
        "workspace" => {
            matches!(item_type, "merge" | "local" | "remote" | "rules" | "proxies" | "groups")
                || (item_type == "script" && (file.ends_with(".yaml") || file.ends_with(".yml")))
        }
        _ => false,
    }
}

fn profile_file_affects_runtime(profiles: &IProfiles, owner_uid: &str) -> bool {
    let Some(current_uid) = profiles.get_current() else {
        return false;
    };
    if current_uid.as_str() == owner_uid {
        return true;
    }
    let Ok(active) = profiles.get_item(current_uid) else {
        return false;
    };
    [
        active.current_merge(),
        active.current_script(),
        active.current_rules(),
        active.current_proxies(),
        active.current_groups(),
    ]
    .into_iter()
    .flatten()
    .any(|uid| uid.as_str() == owner_uid)
}

async fn update_profile_file(owner_uid: String, body: ProfileFileBody) -> (warp::http::StatusCode, serde_json::Value) {
    if !is_safe_adapter_id(&owner_uid)
        || !matches!(body.kind.as_str(), "merge" | "override" | "rules" | "workspace")
        || body.content.len() > 2 * 1024 * 1024
    {
        return (
            warp::http::StatusCode::BAD_REQUEST,
            serde_json::json!({"ok": false, "error": "invalid profile file request"}),
        );
    }
    let (item, affects_runtime) = {
        let profiles = Config::profiles().await.latest_arc();
        let item = match profiles.get_item(&owner_uid) {
            Ok(item) => item.clone(),
            Err(error) => {
                return (
                    warp::http::StatusCode::NOT_FOUND,
                    serde_json::json!({"ok": false, "error": error.to_string()}),
                );
            }
        };
        (item, profile_file_affects_runtime(&profiles, &owner_uid))
    };
    if !profile_file_kind_matches(&item, body.kind.as_str()) {
        return (
            warp::http::StatusCode::BAD_REQUEST,
            serde_json::json!({"ok": false, "error": "profile owner type does not match requested mutation kind"}),
        );
    }
    let original = match item.read_file().await {
        Ok(content) => content.to_string(),
        Err(error) => {
            return (
                warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({"ok": false, "error": error.to_string()}),
            );
        }
    };
    if content_fingerprint(&original) != body.expected_fingerprint.as_str() {
        return (
            warp::http::StatusCode::CONFLICT,
            serde_json::json!({"ok": false, "error": "PROFILE_FILE_CHANGED_SINCE_PREVIEW"}),
        );
    }
    let outcome = match crate::cmd::save_profile_file(owner_uid.clone(), Some(body.content.clone().into())).await {
        Ok(outcome) => outcome,
        Err(error) => {
            return (
                warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({"ok": false, "error": error.to_string()}),
            );
        }
    };
    if !outcome.is_valid() {
        return (
            warp::http::StatusCode::UNPROCESSABLE_ENTITY,
            serde_json::json!({"ok": false, "error": outcome.to_string(), "rollbackVerified": true}),
        );
    }
    let persisted = item.read_file().await.ok().map(|content| content.to_string());
    let verified = persisted.as_deref() == Some(body.content.as_str());
    if !verified {
        let rollback_outcome = crate::cmd::save_profile_file(owner_uid.clone(), Some(original.clone().into())).await;
        let rollback_verified = rollback_outcome.is_ok()
            && item
                .read_file()
                .await
                .ok()
                .is_some_and(|content| content.as_str() == original);
        return (
            warp::http::StatusCode::INTERNAL_SERVER_ERROR,
            serde_json::json!({
                "ok": false,
                "error": "profile file persistence verification failed",
                "rollbackVerified": rollback_verified,
            }),
        );
    }
    let gui_refresh_emitted = schedule_profile_refresh(owner_uid.clone());
    (
        warp::http::StatusCode::OK,
        serde_json::json!({
            "ok": true,
            "ownerUid": owner_uid,
            "kind": body.kind,
            "previousFingerprint": content_fingerprint(&original),
            "persistedFingerprint": content_fingerprint(&body.content),
            "runtimeApplied": affects_runtime,
            "verified": true,
            "guiRefreshEmitted": gui_refresh_emitted,
        }),
    )
}

fn adapter_routes(token: String) -> warp::filters::BoxedFilter<(impl warp::Reply,)> {
    let auth = warp::header::optional::<String>("authorization").map(move |header| adapter_authorized(header, &token));

    // GET /adapter/v1/health
    let health = warp::path!("adapter" / "v1" / "health")
        .and(warp::path::end())
        .and(warp::get())
        .and(auth.clone())
        .and_then(|authorized: bool| async move {
            let reply = if !authorized {
                adapter_reply(
                    warp::http::StatusCode::UNAUTHORIZED,
                    serde_json::json!({"ok": false, "error": "UNAUTHORIZED"}),
                )
            } else {
                adapter_reply(
                    warp::http::StatusCode::OK,
                    serde_json::json!({
                        "ok": true,
                        "protocolVersion": "v1",
                        "vergeVersion": env!("CARGO_PKG_VERSION"),
                        "adapterBuildId": adapter_build_id(),
                        "capabilities": [
                            "profiles.list",
                            "profiles.activate",
                            "profiles.refresh",
                            "profiles.metadata-update",
                            "profiles.merge-update",
                            "profiles.override-update",
                            "profiles.rules-add",
                            "profiles.rules-remove",
                            "config.workspace-apply",
                            "proxies.select-persistent",
                            "settings.allow-lan",
                            "settings.auto-close-connection",
                            "settings.clash-patch",
                            // v1.1: Verge Preferences (per v2.3.1 §6 v1.1-C line 867)
                            "settings.verge-preferences",
                            "settings.verge-preferences-read",
                            "settings.verge-preferences-write",
                            "settings.verge-hotkeys-write",
                            "operations.status",
                            "operations.commit",
                            "operations.rollback",
                        ],
                    }),
                )
            };
            Ok::<_, warp::Rejection>(reply)
        });

    // GET /adapter/v1/profiles
    let profiles = warp::path!("adapter" / "v1" / "profiles")
        .and(warp::path::end())
        .and(warp::get())
        .and(auth.clone())
        .and_then(|authorized: bool| async move {
            let reply = if !authorized {
                adapter_reply(
                    warp::http::StatusCode::UNAUTHORIZED,
                    serde_json::json!({"ok": false, "error": "UNAUTHORIZED"}),
                )
            } else {
                match crate::cmd::get_profiles().await {
                    Ok(value) => adapter_reply(
                        warp::http::StatusCode::OK,
                        serde_json::json!({"ok": true, "profiles": value}),
                    ),
                    Err(error) => adapter_reply(
                        warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                        serde_json::json!({"ok": false, "error": error}),
                    ),
                }
            };
            Ok::<_, warp::Rejection>(reply)
        });

    // POST /adapter/v1/profiles/{uid}/activate
    // Body: { rollbackAfterMs?: number }
    // Creates a lease, switches profile, returns lease info.
    let activate = warp::path!("adapter" / "v1" / "profiles" / String / "activate")
        .and(warp::path::end())
        .and(warp::post())
        .and(auth.clone())
        .and(warp::body::content_length_limit(1024))
        .and(warp::body::json::<ActivateBody>())
        .and_then(|uid: String, authorized: bool, body: ActivateBody| async move {
            if !authorized {
                return Ok::<_, warp::Rejection>(adapter_reply(
                    warp::http::StatusCode::UNAUTHORIZED,
                    serde_json::json!({"ok": false, "error": "UNAUTHORIZED"}),
                ));
            }

            // P0-3.6: Block new activations during recovery
            if adapter_write_blocked() {
                return Ok::<_, warp::Rejection>(adapter_reply(
                    warp::http::StatusCode::SERVICE_UNAVAILABLE,
                    serde_json::json!({
                        "ok": false,
                        "error": "recovery in progress, please retry later"
                    }),
                ));
            }
            let _mutation = match try_acquire_adapter_mutation() {
                Some(guard) => guard,
                None => {
                    return Ok::<_, warp::Rejection>(adapter_reply(
                        warp::http::StatusCode::CONFLICT,
                        serde_json::json!({"ok": false, "error": "ADAPTER_MUTATION_BUSY"}),
                    ));
                }
            };

            // Get current profile UID as previous_uid
            let profiles = Config::profiles().await;
            let profiles_data = profiles.data_arc();
            let previous_uid: std::string::String = match &profiles_data.current {
                Some(s) => s.to_string(),
                None => std::string::String::new(),
            };
            drop(profiles_data);

            if previous_uid.is_empty() {
                return Ok::<_, warp::Rejection>(adapter_reply(
                    warp::http::StatusCode::CONFLICT,
                    serde_json::json!({"ok": false, "error": "no current profile to rollback to"}),
                ));
            }

            let target_uid: std::string::String = uid.to_string();
            if !is_safe_adapter_id(&target_uid) {
                return Ok::<_, warp::Rejection>(adapter_reply(
                    warp::http::StatusCode::BAD_REQUEST,
                    serde_json::json!({"ok": false, "error": "invalid profile UID"}),
                ));
            }
            if adapter_rate_limited("activate", &target_uid, Duration::from_secs(1)) {
                return Ok::<_, warp::Rejection>(adapter_reply(
                    warp::http::StatusCode::TOO_MANY_REQUESTS,
                    serde_json::json!({"ok": false, "error": "profile activation rate limit exceeded"}),
                ));
            }
            let _uid_operation = match try_acquire_adapter_uid_operation(&target_uid) {
                Some(guard) => guard,
                None => {
                    return Ok::<_, warp::Rejection>(adapter_reply(
                        warp::http::StatusCode::CONFLICT,
                        serde_json::json!({"ok": false, "error": "UID_OPERATION_BUSY"}),
                    ));
                }
            };
            let rollback_ms = body
                .rollback_after_ms
                .unwrap_or(adapter_lease::DEFAULT_ROLLBACK_AFTER_MS);

            // Prepare lease before switching
            let lease = match adapter_lease::prepare_lease(&previous_uid, &target_uid, rollback_ms) {
                Ok(l) => l,
                Err(e) => {
                    let message = e.to_string();
                    let status = if message.contains("CONFLICT") {
                        warp::http::StatusCode::CONFLICT
                    } else if message.contains("recovery in progress") {
                        warp::http::StatusCode::SERVICE_UNAVAILABLE
                    } else {
                        warp::http::StatusCode::INTERNAL_SERVER_ERROR
                    };
                    return Ok::<_, warp::Rejection>(adapter_reply(
                        status,
                        serde_json::json!({"ok": false, "error": message}),
                    ));
                }
            };

            // Switch profile (preserve original patch logic)
            let patch_result = crate::cmd::patch_profiles_config_by_profile_index(uid).await;
            match patch_result {
                Ok(outcome) if outcome.is_valid() => {
                    let current = read_current_profile_uid().await;
                    if current.as_str() != target_uid.as_str() {
                        let _ = rollback_lease_with_verify(&lease).await;
                        return Ok::<_, warp::Rejection>(adapter_reply(
                            warp::http::StatusCode::CONFLICT,
                            serde_json::json!({
                                "ok": false,
                                "error": "target profile activation was not verified",
                                "expectedProfileUid": target_uid,
                                "currentProfileUid": current,
                            }),
                        ));
                    }
                    match adapter_lease::arm_lease(&lease.operation_id) {
                        Ok(armed) => {
                            logging!(
                                info,
                                Type::Setup,
                                "Adapter audit action=profiles.activate profileUid={} operationId={} state=PENDING_COMMIT",
                                armed.target_profile_uid,
                                armed.operation_id
                            );
                            Ok::<_, warp::Rejection>(adapter_reply(
                                warp::http::StatusCode::OK,
                                serde_json::json!({
                                    "ok": true,
                                    "operationId": armed.operation_id,
                                    "previousProfileUid": armed.previous_profile_uid,
                                    "targetProfileUid": armed.target_profile_uid,
                                    "deadline": armed.deadline,
                                    "state": armed.state,
                                }),
                            ))
                        }
                        Err(error) => {
                            let _ = rollback_lease_with_verify(&lease).await;
                            Ok::<_, warp::Rejection>(adapter_reply(
                                warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                                serde_json::json!({"ok": false, "error": error.to_string()}),
                            ))
                        }
                    }
                }
                Ok(outcome) => {
                    let _ = rollback_lease_with_verify(&lease).await;
                    Ok::<_, warp::Rejection>(adapter_reply(
                        warp::http::StatusCode::CONFLICT,
                        serde_json::json!({"ok": false, "profileUid": target_uid, "outcome": outcome.to_string()}),
                    ))
                }
                Err(error) => {
                    let _ = rollback_lease_with_verify(&lease).await;
                    Ok::<_, warp::Rejection>(adapter_reply(
                        warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                        serde_json::json!({"ok": false, "profileUid": target_uid, "error": error}),
                    ))
                }
            }
        });

    // POST /adapter/v1/profiles/{uid}/refresh
    let refresh = warp::path!("adapter" / "v1" / "profiles" / String / "refresh")
        .and(warp::path::end())
        .and(warp::post())
        .and(auth.clone())
        .and_then(|uid: String, authorized: bool| async move {
            if !authorized {
                return Ok::<_, warp::Rejection>(adapter_reply(
                    warp::http::StatusCode::UNAUTHORIZED,
                    serde_json::json!({"ok": false, "error": "UNAUTHORIZED"}),
                ));
            }
            if adapter_write_blocked() {
                return Ok::<_, warp::Rejection>(adapter_reply(
                    warp::http::StatusCode::SERVICE_UNAVAILABLE,
                    serde_json::json!({
                        "ok": false,
                        "error": "recovery in progress, please retry later"
                    }),
                ));
            }
            let _mutation = match try_acquire_adapter_mutation() {
                Some(guard) => guard,
                None => {
                    return Ok::<_, warp::Rejection>(adapter_reply(
                        warp::http::StatusCode::CONFLICT,
                        serde_json::json!({"ok": false, "error": "ADAPTER_MUTATION_BUSY"}),
                    ));
                }
            };
            if !is_safe_adapter_id(&uid) {
                return Ok::<_, warp::Rejection>(adapter_reply(
                    warp::http::StatusCode::BAD_REQUEST,
                    serde_json::json!({"ok": false, "error": "invalid profile UID"}),
                ));
            }
            if adapter_rate_limited("refresh", &uid, Duration::from_secs(30)) {
                return Ok::<_, warp::Rejection>(adapter_reply(
                    warp::http::StatusCode::TOO_MANY_REQUESTS,
                    serde_json::json!({"ok": false, "error": "profile refresh rate limit exceeded"}),
                ));
            }
            let _uid_operation = match try_acquire_adapter_uid_operation(&uid) {
                Some(guard) => guard,
                None => {
                    return Ok::<_, warp::Rejection>(adapter_reply(
                        warp::http::StatusCode::CONFLICT,
                        serde_json::json!({"ok": false, "error": "UID_OPERATION_BUSY"}),
                    ));
                }
            };

            let reply = match crate::cmd::update_profile(uid.clone(), None).await {
                Ok(()) => {
                    logging!(
                        info,
                        Type::Setup,
                        "Adapter audit action=profiles.refresh profileUid={} result=success",
                        uid
                    );
                    adapter_reply(
                        warp::http::StatusCode::OK,
                        serde_json::json!({"ok": true, "profileUid": uid}),
                    )
                }
                Err(error) => {
                    logging!(
                        warn,
                        Type::Setup,
                        "Adapter audit action=profiles.refresh profileUid={} result=failed",
                        uid
                    );
                    adapter_reply(
                        warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                        serde_json::json!({"ok": false, "profileUid": uid, "error": error}),
                    )
                }
            };
            Ok::<_, warp::Rejection>(reply)
        });

    // POST /adapter/v1/proxies/select
    // Atomically synchronizes Mihomo runtime, Verge in-memory profile state,
    // profiles.yaml, GUI refresh events, tray state, and optional connection cleanup.
    let select_proxy = warp::path!("adapter" / "v1" / "proxies" / "select")
        .and(warp::path::end())
        .and(warp::post())
        .and(auth.clone())
        .and(warp::body::content_length_limit(4096))
        .and(warp::body::json::<SelectProxyBody>())
        .and_then(|authorized: bool, body: SelectProxyBody| async move {
            if !authorized {
                return Ok::<_, warp::Rejection>(adapter_reply(
                    warp::http::StatusCode::UNAUTHORIZED,
                    serde_json::json!({"ok": false, "error": "UNAUTHORIZED"}),
                ));
            }
            if adapter_write_blocked() {
                return Ok::<_, warp::Rejection>(adapter_reply(
                    warp::http::StatusCode::SERVICE_UNAVAILABLE,
                    serde_json::json!({"ok": false, "error": "recovery in progress, please retry later"}),
                ));
            }
            if adapter_rate_limited("select-proxy", &body.group, Duration::from_millis(500)) {
                return Ok::<_, warp::Rejection>(adapter_reply(
                    warp::http::StatusCode::TOO_MANY_REQUESTS,
                    serde_json::json!({"ok": false, "error": "proxy selection rate limit exceeded"}),
                ));
            }
            let _mutation = match try_acquire_adapter_mutation() {
                Some(guard) => guard,
                None => {
                    return Ok::<_, warp::Rejection>(adapter_reply(
                        warp::http::StatusCode::CONFLICT,
                        serde_json::json!({"ok": false, "error": "ADAPTER_MUTATION_BUSY"}),
                    ));
                }
            };
            let (status, response) = select_proxy_and_sync(body).await;
            Ok::<_, warp::Rejection>(adapter_reply(status, response))
        });

    // POST /adapter/v1/settings/allow-lan
    let allow_lan = warp::path!("adapter" / "v1" / "settings" / "allow-lan")
        .and(warp::path::end())
        .and(warp::post())
        .and(auth.clone())
        .and(warp::body::content_length_limit(256))
        .and(warp::body::json::<BooleanSettingBody>())
        .and_then(|authorized: bool, body: BooleanSettingBody| async move {
            if !authorized {
                return Ok::<_, warp::Rejection>(adapter_reply(
                    warp::http::StatusCode::UNAUTHORIZED,
                    serde_json::json!({"ok": false, "error": "UNAUTHORIZED"}),
                ));
            }
            if adapter_write_blocked() {
                return Ok::<_, warp::Rejection>(adapter_reply(
                    warp::http::StatusCode::SERVICE_UNAVAILABLE,
                    serde_json::json!({"ok": false, "error": "recovery in progress, please retry later"}),
                ));
            }
            let _mutation = match try_acquire_adapter_mutation() {
                Some(guard) => guard,
                None => {
                    return Ok::<_, warp::Rejection>(adapter_reply(
                        warp::http::StatusCode::CONFLICT,
                        serde_json::json!({"ok": false, "error": "ADAPTER_MUTATION_BUSY"}),
                    ));
                }
            };
            let (status, response) = set_allow_lan(body.value).await;
            Ok::<_, warp::Rejection>(adapter_reply(status, response))
        });

    // POST /adapter/v1/settings/auto-close-connection
    let auto_close_connection = warp::path!("adapter" / "v1" / "settings" / "auto-close-connection")
        .and(warp::path::end())
        .and(warp::post())
        .and(auth.clone())
        .and(warp::body::content_length_limit(256))
        .and(warp::body::json::<BooleanSettingBody>())
        .and_then(|authorized: bool, body: BooleanSettingBody| async move {
            if !authorized {
                return Ok::<_, warp::Rejection>(adapter_reply(
                    warp::http::StatusCode::UNAUTHORIZED,
                    serde_json::json!({"ok": false, "error": "UNAUTHORIZED"}),
                ));
            }
            if adapter_write_blocked() {
                return Ok::<_, warp::Rejection>(adapter_reply(
                    warp::http::StatusCode::SERVICE_UNAVAILABLE,
                    serde_json::json!({"ok": false, "error": "recovery in progress, please retry later"}),
                ));
            }
            let _mutation = match try_acquire_adapter_mutation() {
                Some(guard) => guard,
                None => {
                    return Ok::<_, warp::Rejection>(adapter_reply(
                        warp::http::StatusCode::CONFLICT,
                        serde_json::json!({"ok": false, "error": "ADAPTER_MUTATION_BUSY"}),
                    ));
                }
            };
            let (status, response) = set_auto_close_connection(body.value).await;
            Ok::<_, warp::Rejection>(adapter_reply(status, response))
        });

    // POST /adapter/v1/settings/clash
    // Uses Clash Verge's own draft/apply/persist pipeline. Only a fixed
    // allowlist of settings is accepted, and the previewed current value must
    // still match before the mutation starts.
    let clash_setting = warp::path!("adapter" / "v1" / "settings" / "clash")
        .and(warp::path::end())
        .and(warp::post())
        .and(auth.clone())
        .and(warp::body::content_length_limit(64 * 1024))
        .and(warp::body::json::<ClashSettingBody>())
        .and_then(|authorized: bool, body: ClashSettingBody| async move {
            if !authorized {
                return Ok::<_, warp::Rejection>(adapter_reply(
                    warp::http::StatusCode::UNAUTHORIZED,
                    serde_json::json!({"ok": false, "error": "UNAUTHORIZED"}),
                ));
            }
            if adapter_write_blocked() {
                return Ok::<_, warp::Rejection>(adapter_reply(
                    warp::http::StatusCode::SERVICE_UNAVAILABLE,
                    serde_json::json!({"ok": false, "error": "recovery in progress, please retry later"}),
                ));
            }
            if adapter_rate_limited("setting", body.setting.as_str(), Duration::from_millis(500)) {
                return Ok::<_, warp::Rejection>(adapter_reply(
                    warp::http::StatusCode::TOO_MANY_REQUESTS,
                    serde_json::json!({"ok": false, "error": "setting mutation rate limit exceeded", "retryAfterMs": 550}),
                ));
            }
            let _mutation = match try_acquire_adapter_mutation() {
                Some(guard) => guard,
                None => {
                    return Ok::<_, warp::Rejection>(adapter_reply(
                        warp::http::StatusCode::CONFLICT,
                        serde_json::json!({"ok": false, "error": "ADAPTER_MUTATION_BUSY"}),
                    ));
                }
            };
            let (status, response) = set_clash_setting(body).await;
            Ok::<_, warp::Rejection>(adapter_reply(status, response))
        });

    // POST /adapter/v1/profiles/{uid}/metadata
    // Patches only the explicit metadata allowlist through Verge's own
    // profile store. The caller must supply the values it previewed.
    let profile_metadata = warp::path!("adapter" / "v1" / "profiles" / String / "metadata")
        .and(warp::path::end())
        .and(warp::post())
        .and(auth.clone())
        .and(warp::body::content_length_limit(64 * 1024))
        .and(warp::body::json::<ProfileMetadataBody>())
        .and_then(|uid: String, authorized: bool, body: ProfileMetadataBody| async move {
            if !authorized {
                return Ok::<_, warp::Rejection>(adapter_reply(
                    warp::http::StatusCode::UNAUTHORIZED,
                    serde_json::json!({"ok": false, "error": "UNAUTHORIZED"}),
                ));
            }
            if adapter_write_blocked() {
                return Ok::<_, warp::Rejection>(adapter_reply(
                    warp::http::StatusCode::SERVICE_UNAVAILABLE,
                    serde_json::json!({"ok": false, "error": "recovery in progress, please retry later"}),
                ));
            }
            if adapter_rate_limited("profile-metadata", &uid, Duration::from_millis(500)) {
                return Ok::<_, warp::Rejection>(adapter_reply(
                    warp::http::StatusCode::TOO_MANY_REQUESTS,
                    serde_json::json!({"ok": false, "error": "profile metadata rate limit exceeded", "retryAfterMs": 550}),
                ));
            }
            let _mutation = match try_acquire_adapter_mutation() {
                Some(guard) => guard,
                None => {
                    return Ok::<_, warp::Rejection>(adapter_reply(
                        warp::http::StatusCode::CONFLICT,
                        serde_json::json!({"ok": false, "error": "ADAPTER_MUTATION_BUSY"}),
                    ));
                }
            };
            let _uid_operation = match try_acquire_adapter_uid_operation(&uid) {
                Some(guard) => guard,
                None => {
                    return Ok::<_, warp::Rejection>(adapter_reply(
                        warp::http::StatusCode::CONFLICT,
                        serde_json::json!({"ok": false, "error": "UID_OPERATION_BUSY"}),
                    ));
                }
            };
            let (status, response) = update_profile_metadata(uid, body).await;
            Ok::<_, warp::Rejection>(adapter_reply(status, response))
        });

    // POST /adapter/v1/profile-files/{uid}
    // Saves Merge/Override/Rules/workspace YAML through Verge's native
    // validator, runtime apply path, and rollback-on-failure path.
    let profile_file = warp::path!("adapter" / "v1" / "profile-files" / String)
        .and(warp::path::end())
        .and(warp::post())
        .and(auth.clone())
        .and(warp::body::content_length_limit(3 * 1024 * 1024))
        .and(warp::body::json::<ProfileFileBody>())
        .and_then(|uid: String, authorized: bool, body: ProfileFileBody| async move {
            if !authorized {
                return Ok::<_, warp::Rejection>(adapter_reply(
                    warp::http::StatusCode::UNAUTHORIZED,
                    serde_json::json!({"ok": false, "error": "UNAUTHORIZED"}),
                ));
            }
            if adapter_write_blocked() {
                return Ok::<_, warp::Rejection>(adapter_reply(
                    warp::http::StatusCode::SERVICE_UNAVAILABLE,
                    serde_json::json!({"ok": false, "error": "recovery in progress, please retry later"}),
                ));
            }
            if adapter_rate_limited("profile-file", &uid, Duration::from_millis(750)) {
                return Ok::<_, warp::Rejection>(adapter_reply(
                    warp::http::StatusCode::TOO_MANY_REQUESTS,
                    serde_json::json!({"ok": false, "error": "profile file rate limit exceeded", "retryAfterMs": 800}),
                ));
            }
            let _mutation = match try_acquire_adapter_mutation() {
                Some(guard) => guard,
                None => {
                    return Ok::<_, warp::Rejection>(adapter_reply(
                        warp::http::StatusCode::CONFLICT,
                        serde_json::json!({"ok": false, "error": "ADAPTER_MUTATION_BUSY"}),
                    ));
                }
            };
            let _uid_operation = match try_acquire_adapter_uid_operation(&uid) {
                Some(guard) => guard,
                None => {
                    return Ok::<_, warp::Rejection>(adapter_reply(
                        warp::http::StatusCode::CONFLICT,
                        serde_json::json!({"ok": false, "error": "UID_OPERATION_BUSY"}),
                    ));
                }
            };
            let (status, response) = update_profile_file(uid, body).await;
            Ok::<_, warp::Rejection>(adapter_reply(status, response))
        });

    // GET /adapter/v1/operations/{operationId}
    let operation_status = warp::path!("adapter" / "v1" / "operations" / String)
        .and(warp::path::end())
        .and(warp::get())
        .and(auth.clone())
        .and_then(|op_id: String, authorized: bool| async move {
            if !authorized {
                return Ok::<_, warp::Rejection>(adapter_reply(
                    warp::http::StatusCode::UNAUTHORIZED,
                    serde_json::json!({"ok": false, "error": "UNAUTHORIZED"}),
                ));
            }

            let operation_id: std::string::String = op_id.to_string();
            if !is_safe_adapter_id(&operation_id) {
                return Ok::<_, warp::Rejection>(adapter_reply(
                    warp::http::StatusCode::BAD_REQUEST,
                    serde_json::json!({"ok": false, "error": "invalid operation ID"}),
                ));
            }
            match adapter_lease::get_lease(&operation_id) {
                Some(lease) => {
                    Ok::<_, warp::Rejection>(adapter_reply(warp::http::StatusCode::OK, lease_success_json(&lease)))
                }
                None => Ok::<_, warp::Rejection>(adapter_reply(
                    warp::http::StatusCode::NOT_FOUND,
                    serde_json::json!({"ok": false, "error": "operation not found"}),
                )),
            }
        });

    // POST /adapter/v1/operations/{operationId}/commit
    let operation_commit = warp::path!("adapter" / "v1" / "operations" / String / "commit")
        .and(warp::path::end())
        .and(warp::post())
        .and(auth.clone())
        .and_then(|op_id: String, authorized: bool| async move {
            if !authorized {
                return Ok::<_, warp::Rejection>(adapter_reply(
                    warp::http::StatusCode::UNAUTHORIZED,
                    serde_json::json!({"ok": false, "error": "UNAUTHORIZED"}),
                ));
            }

            // P0-3.6: Block commits during recovery (lease may be in process of rollback)
            if adapter_write_blocked() {
                return Ok::<_, warp::Rejection>(adapter_reply(
                    warp::http::StatusCode::SERVICE_UNAVAILABLE,
                    serde_json::json!({
                        "ok": false,
                        "error": "recovery in progress, please retry later"
                    }),
                ));
            }

            let operation_id: std::string::String = op_id.to_string();
            if !is_safe_adapter_id(&operation_id) {
                return Ok::<_, warp::Rejection>(adapter_reply(
                    warp::http::StatusCode::BAD_REQUEST,
                    serde_json::json!({"ok": false, "error": "invalid operation ID"}),
                ));
            }
            match adapter_lease::commit_lease(&operation_id) {
                Ok(lease) => {
                    logging!(
                        info,
                        Type::Setup,
                        "Adapter audit action=operations.commit operationId={} result=success",
                        lease.operation_id
                    );
                    Ok::<_, warp::Rejection>(adapter_reply(warp::http::StatusCode::OK, lease_success_json(&lease)))
                }
                Err(e) => {
                    let msg = e.to_string();
                    let status = if msg.contains("not found") {
                        warp::http::StatusCode::NOT_FOUND
                    } else {
                        warp::http::StatusCode::CONFLICT
                    };
                    Ok::<_, warp::Rejection>(adapter_reply(status, serde_json::json!({"ok": false, "error": msg})))
                }
            }
        });

    // POST /adapter/v1/operations/{operationId}/rollback
    let operation_rollback = warp::path!("adapter" / "v1" / "operations" / String / "rollback")
        .and(warp::path::end())
        .and(warp::post())
        .and(auth.clone())
        .and_then(|op_id: String, authorized: bool| async move {
            if !authorized {
                return Ok::<_, warp::Rejection>(adapter_reply(
                    warp::http::StatusCode::UNAUTHORIZED,
                    serde_json::json!({"ok": false, "error": "UNAUTHORIZED"}),
                ));
            }

            // P0-3.6: Block rollback during recovery (recovery task is rolling back leases)
            if adapter_write_blocked() {
                return Ok::<_, warp::Rejection>(adapter_reply(
                    warp::http::StatusCode::SERVICE_UNAVAILABLE,
                    serde_json::json!({
                        "ok": false,
                        "error": "recovery in progress, please retry later"
                    }),
                ));
            }

            let operation_id: std::string::String = op_id.to_string();
            if !is_safe_adapter_id(&operation_id) {
                return Ok::<_, warp::Rejection>(adapter_reply(
                    warp::http::StatusCode::BAD_REQUEST,
                    serde_json::json!({"ok": false, "error": "invalid operation ID"}),
                ));
            }

            // Get lease to find previous_profile_uid
            let lease = match adapter_lease::get_lease(&operation_id) {
                Some(l) => l,
                None => {
                    return Ok::<_, warp::Rejection>(adapter_reply(
                        warp::http::StatusCode::NOT_FOUND,
                        serde_json::json!({"ok": false, "error": "operation not found"}),
                    ));
                }
            };

            // Can only rollback PendingCommit leases
            if lease.state != adapter_lease::LeaseState::PendingCommit {
                return Ok::<_, warp::Rejection>(adapter_reply(
                    warp::http::StatusCode::CONFLICT,
                    serde_json::json!({"ok": false, "error": "lease is not in PENDING_COMMIT state", "state": lease.state}),
                ));
            }
            let _mutation = match try_acquire_adapter_mutation() {
                Some(guard) => guard,
                None => {
                    return Ok::<_, warp::Rejection>(adapter_reply(
                        warp::http::StatusCode::CONFLICT,
                        serde_json::json!({"ok": false, "error": "ADAPTER_MUTATION_BUSY"}),
                    ));
                }
            };

            // P0-3.4: Switch profile back to previous and re-verify
            let success = rollback_lease_with_verify(&lease).await;
            if success {
                let rolled = adapter_lease::get_lease(&operation_id).unwrap_or(lease);
                Ok::<_, warp::Rejection>(adapter_reply(
                    warp::http::StatusCode::OK,
                    lease_success_json(&rolled),
                ))
            } else {
                Ok::<_, warp::Rejection>(adapter_reply(
                    warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                    serde_json::json!({
                        "ok": false,
                        "error": "rollback failed, lease marked as ROLLBACK_FAILED"
                    }),
                ))
            }
        });

    // v1.1-A: GET /adapter/v1/settings/verge-preferences (read-only)
    let verge_preferences_get = warp::path!("adapter" / "v1" / "settings" / "verge-preferences")
        .and(warp::path::end())
        .and(warp::get())
        .and(auth.clone())
        .and_then(|authorized: bool| async move {
            if !authorized {
                return Ok::<_, warp::Rejection>(adapter_reply(
                    warp::http::StatusCode::UNAUTHORIZED,
                    serde_json::json!({"ok": false, "error": "UNAUTHORIZED"}),
                ));
            }
            let (status, response) = get_verge_preferences().await;
            Ok::<_, warp::Rejection>(adapter_reply(status, response))
        });

    // v1.1-B: POST /adapter/v1/settings/verge-preferences (write)
    let verge_preferences_set = warp::path!("adapter" / "v1" / "settings" / "verge-preferences")
        .and(warp::path::end())
        .and(warp::post())
        .and(auth.clone())
        .and(warp::body::content_length_limit(64 * 1024))
        .and(warp::body::json::<VergePreferencesBody>())
        .and_then(|authorized: bool, body: VergePreferencesBody| async move {
            if !authorized {
                return Ok::<_, warp::Rejection>(adapter_reply(
                    warp::http::StatusCode::UNAUTHORIZED,
                    serde_json::json!({"ok": false, "error": "UNAUTHORIZED"}),
                ));
            }
            if adapter_write_blocked() {
                return Ok::<_, warp::Rejection>(adapter_reply(
                    warp::http::StatusCode::SERVICE_UNAVAILABLE,
                    serde_json::json!({"ok": false, "error": "recovery in progress, please retry later"}),
                ));
            }
            let _mutation = match try_acquire_adapter_mutation() {
                Some(guard) => guard,
                None => {
                    return Ok::<_, warp::Rejection>(adapter_reply(
                        warp::http::StatusCode::CONFLICT,
                        serde_json::json!({
                            "ok": false,
                            "errorCode": "BUSY",
                            "error": "ADAPTER_MUTATION_BUSY"
                        }),
                    ));
                }
            };
            let (status, response) = set_verge_preferences(body).await;
            Ok::<_, warp::Rejection>(adapter_reply(status, response))
        });

    // v1.1-B: POST /adapter/v1/settings/hotkeys (write)
    let hotkeys_set = warp::path!("adapter" / "v1" / "settings" / "hotkeys")
        .and(warp::path::end())
        .and(warp::post())
        .and(auth.clone())
        .and(warp::body::content_length_limit(64 * 1024))
        .and(warp::body::json::<HotkeysBody>())
        .and_then(|authorized: bool, body: HotkeysBody| async move {
            if !authorized {
                return Ok::<_, warp::Rejection>(adapter_reply(
                    warp::http::StatusCode::UNAUTHORIZED,
                    serde_json::json!({"ok": false, "error": "UNAUTHORIZED"}),
                ));
            }
            if adapter_write_blocked() {
                return Ok::<_, warp::Rejection>(adapter_reply(
                    warp::http::StatusCode::SERVICE_UNAVAILABLE,
                    serde_json::json!({"ok": false, "error": "recovery in progress, please retry later"}),
                ));
            }
            let _mutation = match try_acquire_adapter_mutation() {
                Some(guard) => guard,
                None => {
                    return Ok::<_, warp::Rejection>(adapter_reply(
                        warp::http::StatusCode::CONFLICT,
                        serde_json::json!({
                            "ok": false,
                            "errorCode": "BUSY",
                            "error": "ADAPTER_MUTATION_BUSY"
                        }),
                    ));
                }
            };
            let (status, response) = set_hotkeys(body).await;
            Ok::<_, warp::Rejection>(adapter_reply(status, response))
        });

    health
        .or(profiles)
        .or(activate)
        .or(refresh)
        .or(select_proxy)
        .or(allow_lan)
        .or(auto_close_connection)
        .or(clash_setting)
        .or(verge_preferences_get)
        .or(verge_preferences_set)
        .or(hotkeys_set)
        .or(profile_metadata)
        .or(profile_file)
        .or(operation_status)
        .or(operation_commit)
        .or(operation_rollback)
        .boxed()
}

// 关闭 embedded server 的信号发送端
static SHUTDOWN_SENDER: OnceCell<Mutex<Option<oneshot::Sender<()>>>> = OnceCell::new();

/// check whether there is already exists
pub async fn check_singleton() -> Result<()> {
    let port = IVerge::get_singleton_port();
    if is_port_in_use(port) {
        let client = ClientBuilder::new().timeout(Duration::from_millis(500)).build()?;
        // 需要确保 Send
        #[allow(clippy::needless_collect)]
        let argvs: Vec<std::string::String> = std::env::args().collect();
        if argvs.len() > 1 {
            #[cfg(not(target_os = "macos"))]
            {
                let param = argvs[1].as_str();
                if param.starts_with("clash:") {
                    client
                        .get(format!("http://127.0.0.1:{port}/commands/scheme?param={param}"))
                        .send()
                        .await?;
                }
            }
        } else {
            client
                .get(format!("http://127.0.0.1:{port}/commands/visible"))
                .send()
                .await?;
        }
        logging!(error, Type::Window, "failed to setup singleton listen server");
        bail!("app exists");
    }
    Ok(())
}

/// The embed server only be used to implement singleton process
/// maybe it can be used as pac server later
pub fn embed_server() {
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    #[allow(clippy::expect_used)]
    SHUTDOWN_SENDER
        .set(Mutex::new(Some(shutdown_tx)))
        .expect("failed to set shutdown signal for embedded server");
    let port = IVerge::get_singleton_port();

    let visible = warp::path!("commands" / "visible").and_then(|| async {
        logging!(info, Type::Window, "检测到从单例模式恢复应用窗口");
        if !lightweight::exit_lightweight_mode().await {
            WindowManager::show_main_window().await;
        } else {
            logging!(error, Type::Window, "轻量模式退出失败，无法恢复应用窗口");
        };
        Ok::<_, warp::Rejection>(warp::reply::with_status::<std::string::String>(
            "ok".to_string(),
            warp::http::StatusCode::OK,
        ))
    });

    let pac = warp::path!("commands" / "pac").and_then(|| async move {
        let verge_config = Config::verge().await;
        let clash_config = Config::clash().await;

        let pac_content = verge_config
            .data_arc()
            .pac_file_content
            .clone()
            .unwrap_or_else(|| DEFAULT_PAC.into());

        let pac_port = verge_config
            .data_arc()
            .verge_mixed_port
            .unwrap_or_else(|| clash_config.data_arc().get_mixed_port());
        let processed_content = pac_content.replace("%mixed-port%", &format!("{pac_port}"));
        Ok::<_, warp::Rejection>(
            warp::http::Response::builder()
                .header("Content-Type", "application/x-ns-proxy-autoconfig")
                .body(processed_content)
                .unwrap_or_default(),
        )
    });

    // Use map instead of and_then to avoid Send issues
    let scheme = warp::path!("commands" / "scheme")
        .and(warp::query::<QueryParam>())
        .and_then(|query: QueryParam| async move {
            AsyncHandler::spawn(|| async move {
                logging_error!(Type::Setup, resolve::resolve_scheme(&query.param).await);
            });
            Ok::<_, warp::Rejection>(warp::reply::with_status::<std::string::String>(
                "ok".to_string(),
                warp::http::StatusCode::OK,
            ))
        });

    let commands = visible.or(scheme).or(pac).boxed();

    // v0.5-D P1-1: fail-closed token resolution.
    // resolve_adapter_token() returns Result<String>; on error (credentials file
    // missing/invalid AND env var not set/too short), we log a warning and use
    // an empty token, which causes all adapter requests to be unauthorized.
    let adapter_token: std::string::String = match adapter_credentials::resolve_adapter_token() {
        Ok(token) => token,
        Err(e) => {
            logging!(warn, Type::Setup, "Clash Verge adapter disabled: {}", e);
            std::string::String::new()
        }
    };
    if adapter_token.len() < 32 {
        logging!(
            warn,
            Type::Setup,
            "Clash Verge adapter disabled: token must be at least 32 characters (set credentials file or {})",
            ADAPTER_TOKEN_ENV
        );
    }

    // v0.5-D P0-3.1 / P0-3.6: Recover pending leases BEFORE registering routes.
    //
    // recover_leases_on_startup() sets recovery_in_progress = true and returns
    // the list of PENDING_COMMIT leases that need rollback. The async rollback
    // task is spawned before adapter_routes() is registered, so the activate
    // handler will reject new activations with 503 while recovery is in progress.
    //
    // If recovery fails (e.g., corrupted lease file), we keep the recovery flag
    // set (fail-closed) to block all write operations until the issue is resolved.
    let recovery_result: Option<Vec<adapter_lease::LeaseRecord>> = match adapter_lease::recover_leases_on_startup() {
        Ok(list) => {
            for lease in &list {
                logging!(
                    warn,
                    Type::Setup,
                    "Recovered pending lease: operationId={}, previousProfileUid={}, targetProfileUid={}, deadline={}",
                    lease.operation_id,
                    lease.previous_profile_uid,
                    lease.target_profile_uid,
                    lease.deadline
                );
            }
            Some(list)
        }
        Err(e) => {
            logging!(
                error,
                Type::Setup,
                "Failed to recover leases on startup (adapter write endpoints blocked): {}",
                e
            );
            None
        }
    };

    // P0-3.1: Spawn async recovery task to rollback each PENDING_COMMIT lease
    // with re-verify, then end recovery (clears the flag, allowing new activations).
    match recovery_result {
        Some(needs_rollback) if !needs_rollback.is_empty() => {
            logging!(
                warn,
                Type::Setup,
                "Starting async rollback for {} pending lease(s)",
                needs_rollback.len()
            );
            AsyncHandler::spawn(move || async move {
                while !resolve::is_resolve_done() {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                let mut all_recovered = true;
                for lease in &needs_rollback {
                    all_recovered &= rollback_lease_with_verify(lease).await;
                }
                if all_recovered {
                    adapter_lease::end_recovery();
                    logging!(info, Type::Setup, "Lease recovery completed, new activations allowed");
                } else {
                    logging!(
                        error,
                        Type::Setup,
                        "Lease recovery failed; adapter write endpoints remain blocked"
                    );
                }
            });
        }
        Some(_) => adapter_lease::end_recovery(),
        None => {}
    }

    let commands = commands.or(adapter_routes(adapter_token.into())).boxed();

    // v0.5-D P0-3.4: Background task to scan and auto-rollback expired leases
    // every 5 seconds. Uses rollback_lease_with_verify to switch profile back
    // and re-verify before marking the lease as rolled back.
    AsyncHandler::spawn(|| async move {
        while !resolve::is_resolve_done() {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        loop {
            interval.tick().await;
            let expired = adapter_lease::scan_expired_leases();
            for lease in expired {
                logging!(
                    warn,
                    Type::Setup,
                    "Lease expired, auto-rolling back: operationId={}",
                    lease.operation_id
                );
                let _ = rollback_lease_with_verify(&lease).await;
            }
        }
    });

    AsyncHandler::spawn(move || async move {
        warp::serve(commands)
            .bind(([127, 0, 0, 1], port))
            .await
            .graceful(async {
                shutdown_rx.await.ok();
            })
            .run()
            .await;
    });
}

pub fn shutdown_embedded_server() {
    logging!(info, Type::Window, "shutting down embedded server");
    if let Some(sender) = SHUTDOWN_SENDER.get()
        && let Some(sender) = sender.lock().take()
    {
        sender.send(()).ok();
    }
}

#[cfg(test)]
mod adapter_tests {
    use super::{
        HotkeysBody, PreferencesRollbackEvidence, VergePreferencesBody, accelerator_is_system_reserved,
        adapter_authorized, adapter_build_id, adapter_lease, adapter_routes, canonical_accelerator_variants,
        hotkeys_vec_to_mapping, is_safe_adapter_id, is_safe_adapter_label, lease_success_json, mapping_to_hotkeys_vec,
        preference_effective_timing, profile_file_kind_matches, runtime_value_matches_change, selected_proxy,
        try_acquire_adapter_mutation, try_acquire_adapter_uid_operation, validate_hotkey_mapping,
        validate_preferences_body, with_selected_proxy,
    };
    use crate::config::{IVerge, IVergeTheme, PrfItem, PrfSelected};

    const TOKEN: &str = "0123456789abcdef0123456789abcdef";

    #[test]
    fn start_page_is_effective_on_next_app_launch() {
        assert_eq!(preference_effective_timing("start_page"), "NEXT_LAUNCH");
        assert_eq!(preference_effective_timing("language"), "IMMEDIATE");
    }

    #[test]
    fn adapter_requires_a_strong_configured_token() {
        assert!(!adapter_authorized(Some("Bearer ".into()), ""));
        assert!(!adapter_authorized(Some("Bearer short".into()), "short"));
    }

    #[test]
    fn adapter_rejects_missing_or_wrong_credentials() {
        assert!(!adapter_authorized(None, TOKEN));
        assert!(!adapter_authorized(Some("Basic ignored".into()), TOKEN));
        assert!(!adapter_authorized(
            Some("Bearer 0123456789abcdef0123456789abcdee".into()),
            TOKEN,
        ));
    }

    #[test]
    fn adapter_accepts_the_exact_bearer_token() {
        assert!(adapter_authorized(Some(format!("Bearer {TOKEN}").into()), TOKEN));
    }

    #[test]
    fn health_build_id_comes_from_the_packaged_adapter_manifest() {
        assert_eq!(adapter_build_id(), "v1.0.0-rc.1-unsigned.1-v1.1-preferences-v7");
    }

    #[test]
    fn preferences_rollback_requires_all_three_verification_layers() {
        let fully_verified = PreferencesRollbackEvidence {
            memory_verified: true,
            persisted_verified: true,
            side_effect_restore_succeeded: true,
        };
        assert!(fully_verified.verified());

        for incomplete in [
            PreferencesRollbackEvidence {
                memory_verified: false,
                persisted_verified: true,
                side_effect_restore_succeeded: true,
            },
            PreferencesRollbackEvidence {
                memory_verified: true,
                persisted_verified: false,
                side_effect_restore_succeeded: true,
            },
            PreferencesRollbackEvidence {
                memory_verified: true,
                persisted_verified: true,
                side_effect_restore_succeeded: false,
            },
        ] {
            assert!(!incomplete.verified());
        }
    }

    #[test]
    fn adapter_ids_are_bounded_and_path_safe() {
        assert!(is_safe_adapter_id("profile_01-SG"));
        assert!(!is_safe_adapter_id(""));
        assert!(!is_safe_adapter_id("../profile"));
        assert!(!is_safe_adapter_id("profile/name"));
        assert!(!is_safe_adapter_id(&"a".repeat(121)));
    }

    #[test]
    fn runtime_change_comparison_accepts_mihomo_normalization_and_omitted_false_defaults() {
        let actual = serde_json::json!({"stack": "Mixed", "mtu": 1500});
        let desired = serde_json::json!({"stack": "mixed", "strict-route": false});
        let expected = serde_json::json!({"stack": "mixed", "strict-route": true});
        assert!(runtime_value_matches_change(Some(&actual), &desired, Some(&expected)));
    }

    #[test]
    fn runtime_change_comparison_rejects_a_changed_boolean_that_did_not_apply() {
        let actual = serde_json::json!({"strict-route": false});
        let desired = serde_json::json!({"strict-route": true});
        let expected = serde_json::json!({"strict-route": false});
        assert!(!runtime_value_matches_change(Some(&actual), &desired, Some(&expected)));
    }

    #[test]
    fn workspace_profile_file_kind_accepts_structured_yaml_owners_only() {
        for item_type in ["merge", "local", "remote", "rules", "proxies", "groups"] {
            let item = PrfItem {
                itype: Some(item_type.into()),
                file: Some(format!("{item_type}.yaml").into()),
                ..Default::default()
            };
            assert!(profile_file_kind_matches(&item, "workspace"), "{item_type}");
        }

        let yaml_script = PrfItem {
            itype: Some("script".into()),
            file: Some("override.yaml".into()),
            ..Default::default()
        };
        let js_script = PrfItem {
            itype: Some("script".into()),
            file: Some("override.js".into()),
            ..Default::default()
        };
        assert!(profile_file_kind_matches(&yaml_script, "workspace"));
        assert!(!profile_file_kind_matches(&js_script, "workspace"));
    }

    #[test]
    fn proxy_labels_allow_real_unicode_names_but_reject_controls() {
        assert!(is_safe_adapter_label("新加坡-02 | Hysteria2"));
        assert!(!is_safe_adapter_label(""));
        assert!(!is_safe_adapter_label("GLOBAL\nspoofed"));
        assert!(!is_safe_adapter_label(&"节".repeat(257)));
    }

    #[test]
    fn selected_proxy_update_preserves_other_groups_and_replaces_target() {
        let original = vec![
            PrfSelected {
                name: Some("GLOBAL".into()),
                now: Some("old".into()),
            },
            PrfSelected {
                name: Some("Streaming".into()),
                now: Some("US".into()),
            },
        ];
        let updated = with_selected_proxy(Some(original), "GLOBAL", "新加坡-02");
        assert_eq!(selected_proxy(Some(&updated), "GLOBAL").as_deref(), Some("新加坡-02"));
        assert_eq!(selected_proxy(Some(&updated), "Streaming").as_deref(), Some("US"));
        assert_eq!(updated.len(), 2);
    }

    #[test]
    fn global_mutation_guard_serializes_live_state_changes() {
        let held = try_acquire_adapter_mutation().expect("first mutation should acquire global guard");
        assert!(try_acquire_adapter_mutation().is_none());
        drop(held);
        assert!(try_acquire_adapter_mutation().is_some());
    }

    #[test]
    fn operation_success_response_uses_flat_v1_contract() {
        let lease = adapter_lease::LeaseRecord {
            operation_id: "op_contract_1".into(),
            previous_profile_uid: "profile-a".into(),
            target_profile_uid: "profile-b".into(),
            created_at: 10,
            deadline: 30_010,
            rollback_after_ms: 30_000,
            state: adapter_lease::LeaseState::PendingCommit,
            updated_at: 20,
            reason: None,
        };

        let response = lease_success_json(&lease);
        assert_eq!(response["ok"], true);
        assert_eq!(response["operationId"], "op_contract_1");
        assert_eq!(response["previousProfileUid"], "profile-a");
        assert_eq!(response["targetProfileUid"], "profile-b");
        assert_eq!(response["state"], "PENDING_COMMIT");
        assert!(response.get("operation").is_none());
    }

    #[test]
    fn uid_operation_guard_blocks_cross_action_concurrency_until_drop() {
        let uid = "uid-operation-guard-test";
        let held = try_acquire_adapter_uid_operation(uid).expect("first operation should acquire UID");

        let same_uid = std::thread::spawn(move || try_acquire_adapter_uid_operation(uid).is_none());
        assert!(same_uid.join().expect("guard test thread should finish"));

        let other = try_acquire_adapter_uid_operation("uid-operation-guard-other")
            .expect("a different UID should remain independently available");
        drop(other);

        drop(held);
        let reacquired = try_acquire_adapter_uid_operation(uid).expect("dropping the guard must release the UID");
        drop(reacquired);
    }

    fn valid_preferences_body() -> serde_json::Value {
        serde_json::json!({
            "patch": { "language": "zh" },
            "expectedCurrent": { "language": "en" },
            "expectedOwnerFingerprint": "0123456789abcdef0123456789abcdef"
        })
    }

    #[test]
    fn preferences_dto_accepts_only_typed_allowlisted_fields() {
        let body =
            serde_json::from_value::<VergePreferencesBody>(valid_preferences_body()).expect("valid restricted DTO");
        validate_preferences_body(&body).expect("valid semantics");

        for invalid in [
            serde_json::json!({
                "patch": { "language": "zh", "enable_system_proxy": true },
                "expectedCurrent": { "language": "en", "enable_system_proxy": false },
                "expectedOwnerFingerprint": "0123456789abcdef0123456789abcdef"
            }),
            serde_json::json!({
                "patch": { "language": null },
                "expectedCurrent": { "language": "en" },
                "expectedOwnerFingerprint": "0123456789abcdef0123456789abcdef"
            }),
            serde_json::json!({
                "patch": { "language": "zh" },
                "expectedCurrent": { "language": "en" },
                "expectedOwnerFingerprint": "0123456789abcdef0123456789abcdef",
                "arbitraryPatch": {}
            }),
        ] {
            assert!(serde_json::from_value::<VergePreferencesBody>(invalid).is_err());
        }
    }

    #[test]
    fn preferences_validation_binds_expected_fields_and_real_enums() {
        let missing_expected = serde_json::from_value::<VergePreferencesBody>(serde_json::json!({
            "patch": { "language": "zh", "theme_mode": "dark" },
            "expectedCurrent": { "language": "en" },
            "expectedOwnerFingerprint": "0123456789abcdef0123456789abcdef"
        }))
        .expect("typed DTO");
        assert!(validate_preferences_body(&missing_expected).is_err());

        let invalid_enum = serde_json::from_value::<VergePreferencesBody>(serde_json::json!({
            "patch": { "language": "xx" },
            "expectedCurrent": { "language": "en" },
            "expectedOwnerFingerprint": "0123456789abcdef0123456789abcdef"
        }))
        .expect("typed DTO");
        assert!(validate_preferences_body(&invalid_enum).is_err());

        let data_url_font = serde_json::from_value::<VergePreferencesBody>(serde_json::json!({
            "patch": { "font_family": "data:text/css,body{}" },
            "expectedCurrent": { "font_family": "Arial" },
            "expectedOwnerFingerprint": "0123456789abcdef0123456789abcdef"
        }))
        .expect("typed DTO");
        assert!(validate_preferences_body(&data_url_font).is_err());
    }

    #[test]
    fn theme_patch_accepts_explicit_null_and_collapses_an_empty_theme() {
        let body = serde_json::from_value::<VergePreferencesBody>(serde_json::json!({
            "patch": { "primary_color": null },
            "expectedCurrent": { "primary_color": "#112233" },
            "expectedOwnerFingerprint": "0123456789abcdef0123456789abcdef"
        }))
        .expect("theme null is an explicit reset, not a malformed value");
        validate_preferences_body(&body).expect("theme reset should be valid");

        let current = IVerge {
            theme_setting: Some(IVergeTheme {
                primary_color: Some("#112233".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let desired = body.patch.desired_theme_setting(&current);
        assert!(matches!(desired, Some(None)));
        assert_eq!(body.patch.as_json_map()["primary_color"], serde_json::Value::Null);
    }

    #[test]
    fn theme_reset_preserves_non_allowlisted_existing_css() {
        let body = serde_json::from_value::<VergePreferencesBody>(serde_json::json!({
            "patch": { "primary_color": null },
            "expectedCurrent": { "primary_color": "#112233" },
            "expectedOwnerFingerprint": "0123456789abcdef0123456789abcdef"
        }))
        .expect("valid reset DTO");
        let current = IVerge {
            theme_setting: Some(IVergeTheme {
                primary_color: Some("#112233".into()),
                css_injection: Some("body { opacity: 1; }".into()),
                ..Default::default()
            }),
            ..Default::default()
        };

        let desired = body
            .patch
            .desired_theme_setting(&current)
            .expect("theme was changed")
            .expect("non-allowlisted CSS keeps the theme object present");
        assert!(desired.primary_color.is_none());
        assert_eq!(desired.css_injection.as_deref(), Some("body { opacity: 1; }"));
    }

    #[test]
    fn hotkey_mapping_parser_rejects_malformed_unknown_reserved_and_duplicate_entries() {
        for entries in [
            vec!["missing-comma".into()],
            vec!["quit,CommandOrControl+Shift+Q".into()],
            vec!["open_or_close_dashboard,Command+Q".into()],
            vec!["open_or_close_dashboard,Cmd+Q".into()],
            vec!["open_or_close_dashboard,Meta+Q".into()],
            vec!["open_or_close_dashboard,Command+Space".into()],
            vec!["open_or_close_dashboard,CommandOrControl+Space".into()],
            vec!["open_or_close_dashboard,Command+Tab".into()],
            vec![
                "open_or_close_dashboard,CommandOrControl+Shift+V".into(),
                "toggle_system_proxy,CommandOrControl+Shift+V".into(),
            ],
            vec![
                "open_or_close_dashboard,CommandOrControl+Shift+J".into(),
                "toggle_system_proxy,Cmd+Shift+J".into(),
            ],
            vec![
                "open_or_close_dashboard,CommandOrControl+Shift+V".into(),
                "open_or_close_dashboard,CommandOrControl+Shift+P".into(),
            ],
        ] {
            assert!(hotkeys_vec_to_mapping(&entries).is_err());
        }

        let valid = hotkeys_vec_to_mapping(&[
            "toggle_system_proxy,CmdOrCtrl+Shift+B".into(),
            "clash_mode_rule,CmdOrCtrl+Shift+R".into(),
            "clash_mode_direct,CmdOrCtrl+Shift+D".into(),
            "clash_mode_global,CmdOrCtrl+Shift+G".into(),
            "open_or_close_dashboard,CmdOrCtrl+Shift+W".into(),
        ])
        .expect("valid real 2.5.1 hotkeys");
        assert_eq!(valid.len(), 5);
    }

    #[test]
    fn system_reserved_hotkeys_are_alias_safe() {
        for accelerator in [
            "Command+Q",
            "Cmd+Q",
            "Meta+Q",
            "Command+Space",
            "Cmd+Space",
            "CommandOrControl+Space",
            "Command+Tab",
            "Command+Option+Escape",
            "Command+Option+Space",
            "Control+Space",
            "Control+Option+Space",
        ] {
            assert!(accelerator_is_system_reserved(accelerator), "{accelerator}");
        }
        assert!(!accelerator_is_system_reserved("CommandOrControl+Option+Shift+J"));
        assert_eq!(
            canonical_accelerator_variants("CmdOrCtrl+Shift+J"),
            vec!["command+shift+j", "control+shift+j"]
        );
    }

    #[test]
    fn hotkey_mapping_serialization_preserves_existing_order() {
        let current = vec![
            "toggle_system_proxy,CmdOrCtrl+Shift+B".into(),
            "clash_mode_rule,CmdOrCtrl+Shift+R".into(),
            "open_or_close_dashboard,CmdOrCtrl+Shift+W".into(),
        ];
        let mapping = std::collections::BTreeMap::from([
            ("open_or_close_dashboard".into(), "CmdOrCtrl+Shift+U".into()),
            ("clash_mode_rule".into(), "CmdOrCtrl+Shift+R".into()),
            ("toggle_system_proxy".into(), "CmdOrCtrl+Shift+B".into()),
            ("toggle_tun_mode".into(), "CmdOrCtrl+Shift+T".into()),
        ]);

        let serialized = mapping_to_hotkeys_vec(&mapping, &current).expect("valid mapping must serialize");
        assert_eq!(
            serialized,
            vec![
                "toggle_system_proxy,CmdOrCtrl+Shift+B",
                "clash_mode_rule,CmdOrCtrl+Shift+R",
                "open_or_close_dashboard,CmdOrCtrl+Shift+U",
                "toggle_tun_mode,CmdOrCtrl+Shift+T",
            ]
        );
    }

    #[test]
    fn hotkeys_dto_is_closed_and_requires_real_owner_fingerprint() {
        let body = serde_json::from_value::<HotkeysBody>(serde_json::json!({
            "mapping": { "open_or_close_dashboard": "CommandOrControl+Shift+V" },
            "enableGlobalHotkey": true,
            "expectedCurrentMapping": {},
            "expectedEnableGlobal": true,
            "expectedOwnerFingerprint": "0123456789abcdef0123456789abcdef"
        }))
        .expect("valid hotkeys DTO");
        validate_hotkey_mapping(&body.mapping).expect("valid mapping");

        let unknown = serde_json::json!({
            "mapping": {},
            "enableGlobalHotkey": true,
            "expectedCurrentMapping": {},
            "expectedEnableGlobal": true,
            "expectedOwnerFingerprint": "0123456789abcdef0123456789abcdef",
            "patch": {}
        });
        assert!(serde_json::from_value::<HotkeysBody>(unknown).is_err());
    }

    #[tokio::test]
    async fn health_advertises_authoritative_preferences_capability() {
        let response = warp::test::request()
            .method("GET")
            .path("/adapter/v1/health")
            .header("authorization", format!("Bearer {TOKEN}"))
            .reply(&adapter_routes(TOKEN.into()))
            .await;
        assert_eq!(response.status(), warp::http::StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(response.body()).expect("health JSON");
        let capabilities = body["capabilities"].as_array().expect("capabilities");
        assert!(capabilities.iter().any(|value| value == "settings.verge-preferences"));
    }

    #[tokio::test]
    async fn preferences_route_rejects_unknown_dto_before_mutation() {
        let mut invalid = valid_preferences_body();
        invalid["patch"]["enable_system_proxy"] = serde_json::Value::Bool(true);
        let response = warp::test::request()
            .method("POST")
            .path("/adapter/v1/settings/verge-preferences")
            .header("authorization", format!("Bearer {TOKEN}"))
            .json(&invalid)
            .reply(&adapter_routes(TOKEN.into()))
            .await;
        assert_eq!(response.status(), warp::http::StatusCode::BAD_REQUEST);
    }
}
