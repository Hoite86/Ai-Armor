#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use chrono::{Duration, Utc};
use core_detect::{
    detect_sensitive, regex_matches_example, suggest_regex_from_example, CustomPattern,
    DetectorConfig,
};
use core_tokenize::{extract_tokens, protect_text, restore_text};
use core_vault::{TtlOption, Vault};
use parking_lot::Mutex;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::{collections::HashSet, fs, path::PathBuf, sync::Arc};
use tauri::{
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    Emitter, Manager,
};
use uuid::Uuid;

const MAX_CLIPBOARD_CHARS: usize = 100_000;
const MAX_TERM_COUNT: usize = 200;
const MAX_TERM_LEN: usize = 120;
const MAX_PATTERN_COUNT: usize = 100;
const MAX_PATTERN_NAME: usize = 64;
const MAX_PATTERN_REGEX: usize = 256;
const MAX_PATTERN_SAMPLE: usize = 120;
const MAX_UPDATE_URL_LEN: usize = 200;
const MAX_VERIFY_INPUT_B64_LEN: usize = 512;
const MAX_PATH_LEN: usize = 260;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UserPattern {
    name: String,
    regex: String,
    enabled: bool,
    word_boundary: bool,
    sample: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SettingsData {
    tos_accepted: bool,
    high_risk_only: bool,
    offer_toast_only_when_sensitive: bool,
    ttl_hours: i64,
    sensitive_terms: Vec<String>,
    ignored_apps: HashSet<String>,
    user_patterns: Vec<UserPattern>,
    #[serde(default)]
    update_portal_url: String,
}

impl Default for SettingsData {
    fn default() -> Self {
        Self {
            tos_accepted: false,
            high_risk_only: false,
            offer_toast_only_when_sensitive: true,
            ttl_hours: 24,
            sensitive_terms: vec![],
            ignored_apps: HashSet::new(),
            user_patterns: vec![],
            update_portal_url: String::new(),
        }
    }
}

#[derive(Default)]
struct RuntimeState {
    pause_until: Option<chrono::DateTime<Utc>>,
    undo: Option<(chrono::DateTime<Utc>, String)>,
    last_clipboard_hash: Option<String>,
    internal_write_until: Option<chrono::DateTime<Utc>>,
}

struct AppState {
    settings: SettingsData,
    settings_path: PathBuf,
    runtime: RuntimeState,
}

#[derive(Debug, Serialize)]
struct ToastPayload {
    mode: &'static str,
    message: String,
}

#[derive(Debug, Deserialize)]
struct SuggestRegexInput {
    name: String,
    example: String,
    boundary: bool,
}

#[derive(Debug, Serialize)]
struct SuggestRegexOutput {
    regex: String,
    passes_example: bool,
}

#[derive(Debug, Deserialize)]
struct VerifyUpdateInput {
    file_path: String,
    expected_sha256: String,
    signature_b64: String,
    public_key_b64: String,
}

#[derive(Debug, Serialize)]
struct VerifyUpdateOutput {
    hash_ok: bool,
    signature_ok: bool,
}
fn main() {
    let mut builder = tauri::Builder::default();
    if cfg!(debug_assertions) {
        tracing_subscriber::fmt().with_env_filter("info").init();
    }

    builder
        .setup(move |app| {
            let data_dir = app.path().app_data_dir().unwrap_or(PathBuf::from("."));
            fs::create_dir_all(&data_dir)?;

            let settings_path = data_dir.join("settings.json");
            let settings = load_settings(&settings_path);
            let app_state = Arc::new(Mutex::new(AppState {
                settings,
                settings_path,
                runtime: RuntimeState::default(),
            }));
            app.manage(app_state.clone());

            let vault = Vault::open(data_dir.join("vault.db"), data_dir.join("vault.key"))?;
            vault.purge_expired()?;
            app.manage(Mutex::new(vault));

            setup_tray(app)?;
            #[cfg(target_os = "windows")]
            start_windows_clipboard_listener(app.handle().clone());
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_settings,
            save_settings,
            get_tos_status,
            accept_tos,
            suggest_regex,
            add_user_pattern,
            remove_user_pattern,
            protect_for_ai,
            restore_details,
            dismiss_toast,
            pause_detection,
            resume_detection,
            purge_everything,
            never_for_app,
            undo_last,
            verify_update_artifact
        ])
        .run(tauri::generate_context!())
        .expect("error while running AI Armor");
}

fn setup_tray(app: &mut tauri::App) -> tauri::Result<()> {
    let pause5 = MenuItem::with_id(
        app,
        "pause_5",
        "Pause detection for 5 minutes",
        true,
        None::<&str>,
    )?;
    let pause30 = MenuItem::with_id(
        app,
        "pause_30",
        "Pause detection for 30 minutes",
        true,
        None::<&str>,
    )?;
    let resume = MenuItem::with_id(app, "resume", "Resume detection", true, None::<&str>)?;
    let disable_here = MenuItem::with_id(
        app,
        "disable_here",
        "Disable in this app...",
        true,
        None::<&str>,
    )?;
    let manage_ignored = MenuItem::with_id(
        app,
        "manage_ignored",
        "Manage ignored apps...",
        true,
        None::<&str>,
    )?;
    let high_risk = MenuItem::with_id(
        app,
        "high_risk",
        "High-risk only: On/Off",
        true,
        None::<&str>,
    )?;
    let purge = MenuItem::with_id(app, "purge", "Purge everything now", true, None::<&str>)?;
    let settings = MenuItem::with_id(app, "settings", "Settings", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
    let menu = Menu::with_items(
        app,
        &[
            &pause5,
            &pause30,
            &resume,
            &disable_here,
            &manage_ignored,
            &high_risk,
            &purge,
            &settings,
            &quit,
        ],
    )?;

    TrayIconBuilder::new()
        .menu(&menu)
        .on_menu_event(|app, ev| {
            let app_state = app.state::<Arc<Mutex<AppState>>>();
            let mut st = app_state.lock();
            match ev.id.as_ref() {
                "pause_5" => st.runtime.pause_until = Some(Utc::now() + Duration::minutes(5)),
                "pause_30" => st.runtime.pause_until = Some(Utc::now() + Duration::minutes(30)),
                "resume" => st.runtime.pause_until = None,
                "high_risk" => {
                    st.settings.high_risk_only = !st.settings.high_risk_only;
                    persist_settings(&st);
                }
                "disable_here" => {
                    if let Some(proc_name) =
                        current_foreground_process_name().and_then(|p| normalize_process_name(&p))
                    {
                        st.settings.ignored_apps.insert(proc_name);
                        persist_settings(&st);
                    }
                }
                "purge" => {
                    let vault = app.state::<Mutex<Vault>>();
                    let _ = vault.lock().purge_all();
                }
                "settings" => {
                    let _ = app.emit(
                        "toast",
                        ToastPayload {
                            mode: "settings",
                            message: "Open Settings from app window".into(),
                        },
                    );
                }
                "quit" => std::process::exit(0),
                _ => {}
            }
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                let _ = tray.app_handle().emit(
                    "toast",
                    ToastPayload {
                        mode: "info",
                        message: "AI Armor is running locally".into(),
                    },
                );
            }
        })
        .build(app)?;
    Ok(())
}

#[tauri::command]
fn get_tos_status(app: tauri::AppHandle) -> bool {
    let state = app.state::<Arc<Mutex<AppState>>>();
    state.lock().settings.tos_accepted
}

#[tauri::command]
fn accept_tos(app: tauri::AppHandle) {
    let state = app.state::<Arc<Mutex<AppState>>>();
    let mut s = state.lock();
    s.settings.tos_accepted = true;
    persist_settings(&s);
}

#[tauri::command]
fn get_settings(app: tauri::AppHandle) -> SettingsData {
    let state = app.state::<Arc<Mutex<AppState>>>();
    state.lock().settings.clone()
}

#[tauri::command]
fn save_settings(app: tauri::AppHandle, settings: SettingsData) -> Result<(), String> {
    let state = app.state::<Arc<Mutex<AppState>>>();
    let mut s = state.lock();
    s.settings = normalize_settings(settings)?;
    persist_settings(&s);
    Ok(())
}

#[tauri::command]
fn suggest_regex(input: SuggestRegexInput) -> SuggestRegexOutput {
    let clean_example = input.example.trim();
    if clean_example.is_empty() || clean_example.len() > MAX_PATTERN_SAMPLE {
        return SuggestRegexOutput {
            regex: String::new(),
            passes_example: false,
        };
    }

    let mut regex = suggest_regex_from_example(clean_example);
    if input.boundary {
        regex = format!(
            r"\b(?:{})\b",
            regex.trim_start_matches('^').trim_end_matches('$')
        );
    }
    let passes = regex_matches_example(&regex, clean_example);
    let _ = input.name;
    SuggestRegexOutput {
        regex,
        passes_example: passes,
    }
}

#[tauri::command]
fn add_user_pattern(app: tauri::AppHandle, pattern: UserPattern) -> Result<(), String> {
    let normalized = normalize_pattern(pattern)?;
    let state = app.state::<Arc<Mutex<AppState>>>();
    let mut s = state.lock();
    s.settings
        .user_patterns
        .retain(|p| p.name != normalized.name);
    if s.settings.user_patterns.len() >= MAX_PATTERN_COUNT {
        return Err("Pattern limit reached. Remove one and try again.".into());
    }
    s.settings.user_patterns.push(normalized);
    persist_settings(&s);
    Ok(())
}

#[tauri::command]
fn remove_user_pattern(app: tauri::AppHandle, name: String) -> Result<(), String> {
    let state = app.state::<Arc<Mutex<AppState>>>();
    let mut s = state.lock();
    s.settings.user_patterns.retain(|p| p.name != name.trim());
    persist_settings(&s);
    Ok(())
}

#[tauri::command]
fn protect_for_ai(app: tauri::AppHandle, text: String) -> Result<String, String> {
    if text.chars().count() > MAX_CLIPBOARD_CHARS {
        return Ok(text);
    }

    let app_state = app.state::<Arc<Mutex<AppState>>>();
    let mut state = app_state.lock();
    if !state.settings.tos_accepted || is_paused(&state.runtime) {
        return Ok(text);
    }

    if let Some(proc_name) =
        current_foreground_process_name().and_then(|p| normalize_process_name(&p))
    {
        if state.settings.ignored_apps.contains(&proc_name) {
            return Ok(text);
        }
    }

    let cfg = DetectorConfig {
        terms: state.settings.sensitive_terms.clone(),
        term_word_boundary: true,
        custom_patterns: state
            .settings
            .user_patterns
            .iter()
            .map(|p| CustomPattern {
                name: p.name.clone(),
                regex: p.regex.clone(),
                word_boundary: p.word_boundary,
                enabled: p.enabled,
            })
            .collect(),
    };

    let mut entities = detect_sensitive(&text, &cfg);
    if state.settings.high_risk_only {
        entities.retain(|e| e.kind.high_risk() && e.confidence >= 0.8);
    }
    if entities.is_empty() {
        return Ok(text);
    }

    let output = protect_text(&text, &entities, Uuid::new_v4());
    let vault = app.state::<Mutex<Vault>>();
    let ttl = match state.settings.ttl_hours {
        1 => TtlOption::OneHour,
        168 => TtlOption::SevenDays,
        _ => TtlOption::OneDay,
    };
    let rec = vault
        .lock()
        .store_session(&output.session_tag, &output.mappings, ttl, None)
        .map_err(|e| e.to_string())?;

    state.runtime.undo = Some((Utc::now(), text));
    state.runtime.internal_write_until = Some(Utc::now() + Duration::seconds(2));
    state.runtime.last_clipboard_hash = Some(hex::encode(sha2::Sha256::digest(
        output.protected_text.as_bytes(),
    )));
    let _ = app.emit(
        "toast",
        ToastPayload {
            mode: "confirm",
            message: format!("Protected {} items. Undo or Settings.", rec.item_count),
        },
    );
    Ok(output.protected_text)
}

#[tauri::command]
fn restore_details(app: tauri::AppHandle, text: String) -> Result<String, String> {
    if text.chars().count() > MAX_CLIPBOARD_CHARS {
        return Ok(text);
    }

    let app_state = app.state::<Arc<Mutex<AppState>>>();
    let mut state = app_state.lock();
    if !state.settings.tos_accepted {
        return Ok(text);
    }
    let vault = app.state::<Mutex<Vault>>();
    let mappings = vault
        .lock()
        .load_mappings_for_restore(&text)
        .map_err(|e| e.to_string())?;
    if mappings.is_empty() {
        return Ok(text);
    }
    let restored = restore_text(&text, &mappings);
    state.runtime.undo = Some((Utc::now(), text));
    state.runtime.internal_write_until = Some(Utc::now() + Duration::seconds(2));
    state.runtime.last_clipboard_hash =
        Some(hex::encode(sha2::Sha256::digest(restored.as_bytes())));
    let _ = app.emit(
        "toast",
        ToastPayload {
            mode: "confirm",
            message: format!("Restored {} items. Undo or Purge map.", mappings.len()),
        },
    );
    Ok(restored)
}

#[tauri::command]
fn verify_update_artifact(input: VerifyUpdateInput) -> Result<VerifyUpdateOutput, String> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let file_path = input.file_path.trim();
    if file_path.is_empty() || file_path.len() > MAX_PATH_LEN {
        return Err("File path is required and must be <= 260 characters.".into());
    }
    if !is_valid_sha256_hex(&input.expected_sha256) {
        return Err("Expected SHA-256 must be a 64-character hex string.".into());
    }
    if input.public_key_b64.len() > MAX_VERIFY_INPUT_B64_LEN
        || input.signature_b64.len() > MAX_VERIFY_INPUT_B64_LEN
    {
        return Err("Key/signature input too large.".into());
    }

    let data = fs::read(file_path).map_err(|e| format!("Unable to read file: {e}"))?;
    if data.len() > 50 * 1024 * 1024 {
        return Err("Update artifact too large for local verification (50MB cap).".into());
    }

    let expected = input.expected_sha256.trim().to_lowercase();
    let actual = hex::encode(sha2::Sha256::digest(&data));
    let hash_ok = actual == expected;

    let pub_bytes = STANDARD
        .decode(input.public_key_b64.trim())
        .map_err(|_| "Invalid public key encoding".to_string())?;
    let sig_bytes = STANDARD
        .decode(input.signature_b64.trim())
        .map_err(|_| "Invalid signature encoding".to_string())?;

    let vk = VerifyingKey::from_bytes(
        pub_bytes
            .as_slice()
            .try_into()
            .map_err(|_| "Invalid public key size".to_string())?,
    )
    .map_err(|_| "Invalid public key".to_string())?;
    let sig = Signature::from_slice(&sig_bytes).map_err(|_| "Invalid signature".to_string())?;
    let signature_ok = vk.verify(&data, &sig).is_ok();

    Ok(VerifyUpdateOutput {
        hash_ok,
        signature_ok,
    })
}

#[tauri::command]
fn undo_last(app: tauri::AppHandle) -> Result<Option<String>, String> {
    let state = app.state::<Arc<Mutex<AppState>>>();
    let mut s = state.lock();
    if let Some((ts, value)) = s.runtime.undo.take() {
        if Utc::now() - ts <= Duration::minutes(2) {
            return Ok(Some(value));
        }
    }
    Ok(None)
}

#[tauri::command]
fn dismiss_toast() {}

#[tauri::command]
fn pause_detection(app: tauri::AppHandle, minutes: i64) {
    let state = app.state::<Arc<Mutex<AppState>>>();
    state.lock().runtime.pause_until = Some(Utc::now() + Duration::minutes(minutes));
}

#[tauri::command]
fn resume_detection(app: tauri::AppHandle) {
    let state = app.state::<Arc<Mutex<AppState>>>();
    state.lock().runtime.pause_until = None;
}

#[tauri::command]
fn purge_everything(app: tauri::AppHandle) -> Result<(), String> {
    let vault = app.state::<Mutex<Vault>>();
    vault.lock().purge_all().map_err(|e| e.to_string())
}

#[tauri::command]
fn never_for_app(app: tauri::AppHandle, process_name: String) {
    let state = app.state::<Arc<Mutex<AppState>>>();
    let mut s = state.lock();
    if let Some(proc_name) = normalize_process_name(&process_name) {
        s.settings.ignored_apps.insert(proc_name);
        persist_settings(&s);
    }
}

fn is_paused(state: &RuntimeState) -> bool {
    state.pause_until.map(|ts| ts > Utc::now()).unwrap_or(false)
}

fn load_settings(path: &PathBuf) -> SettingsData {
    fs::read_to_string(path)
        .ok()
        .and_then(|v| serde_json::from_str::<SettingsData>(&v).ok())
        .and_then(|s| normalize_settings(s).ok())
        .unwrap_or_default()
}

fn persist_settings(state: &AppState) {
    if let Ok(v) = serde_json::to_string_pretty(&state.settings) {
        let _ = fs::write(&state.settings_path, v);
    }
}

fn normalize_settings(mut settings: SettingsData) -> Result<SettingsData, String> {
    settings.ttl_hours = match settings.ttl_hours {
        1 | 24 | 168 => settings.ttl_hours,
        _ => 24,
    };

    settings.sensitive_terms = settings
        .sensitive_terms
        .into_iter()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty() && v.len() <= MAX_TERM_LEN)
        .take(MAX_TERM_COUNT)
        .collect();

    settings.ignored_apps = settings
        .ignored_apps
        .into_iter()
        .filter_map(|v| normalize_process_name(&v))
        .take(200)
        .collect();

    let mut normalized_patterns = Vec::new();
    for p in settings.user_patterns.into_iter().take(MAX_PATTERN_COUNT) {
        if let Ok(np) = normalize_pattern(p) {
            normalized_patterns.push(np);
        }
    }
    settings.user_patterns = normalized_patterns;

    settings.update_portal_url = settings.update_portal_url.trim().to_string();
    if settings.update_portal_url.len() > MAX_UPDATE_URL_LEN {
        settings.update_portal_url.truncate(MAX_UPDATE_URL_LEN);
    }
    if !settings.update_portal_url.is_empty()
        && !(settings.update_portal_url.starts_with("https://")
            || settings.update_portal_url.starts_with("http://"))
    {
        settings.update_portal_url.clear();
    }

    Ok(settings)
}

fn normalize_pattern(pattern: UserPattern) -> Result<UserPattern, String> {
    let name = pattern.name.trim();
    if name.is_empty() || name.len() > MAX_PATTERN_NAME {
        return Err("Pattern name must be 1-64 characters.".into());
    }

    let sample = pattern.sample.trim();
    if sample.is_empty() || sample.len() > MAX_PATTERN_SAMPLE {
        return Err("Pattern sample must be 1-120 characters.".into());
    }

    let regex_src = pattern.regex.trim();
    if regex_src.is_empty() || regex_src.len() > MAX_PATTERN_REGEX {
        return Err("Regex must be 1-256 characters.".into());
    }

    if !is_safe_regex(regex_src) {
        return Err("Regex rejected by safety policy (unsupported or risky construct).".into());
    }

    let compiled = Regex::new(regex_src).map_err(|_| "Regex is invalid.".to_string())?;
    if !compiled.is_match(sample) {
        return Err("Regex does not match the provided example sample.".into());
    }

    Ok(UserPattern {
        name: name.to_string(),
        regex: regex_src.to_string(),
        enabled: pattern.enabled,
        word_boundary: pattern.word_boundary,
        sample: sample.to_string(),
    })
}

fn is_safe_regex(re: &str) -> bool {
    let banned = [
        "(?=", "(?!", "(?<=", "(?<!", "\\p", "\\P", "(?R", "(?0", "(?&",
    ];
    if banned.iter().any(|needle| re.contains(needle)) {
        return false;
    }
    let group_count = re.matches('(').count();
    let alternation_count = re.matches('|').count();
    group_count <= 24 && alternation_count <= 16
}

fn is_valid_sha256_hex(value: &str) -> bool {
    let v = value.trim();
    v.len() == 64 && v.as_bytes().iter().all(|b| b.is_ascii_hexdigit())
}

fn normalize_process_name(value: &str) -> Option<String> {
    let v = value.trim();
    if v.is_empty() || v.len() > 260 {
        return None;
    }
    let clean: String = v
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        .collect();
    if clean.is_empty() {
        None
    } else {
        Some(clean)
    }
}

fn should_skip_clipboard_event(
    now: chrono::DateTime<Utc>,
    text: &str,
    runtime: &RuntimeState,
) -> bool {
    if text.trim().is_empty() || text.chars().count() > MAX_CLIPBOARD_CHARS {
        return true;
    }
    if let Some(ts) = runtime.internal_write_until {
        if ts > now {
            return true;
        }
    }
    let h = hex::encode(sha2::Sha256::digest(text.as_bytes()));
    runtime.last_clipboard_hash.as_ref() == Some(&h)
}

fn maybe_emit_clipboard_toast(app: &tauri::AppHandle, text: &str) {
    let app_state = app.state::<Arc<Mutex<AppState>>>();
    let mut state = app_state.lock();
    if !state.settings.tos_accepted || is_paused(&state.runtime) {
        return;
    }

    if let Some(proc_name) =
        current_foreground_process_name().and_then(|p| normalize_process_name(&p))
    {
        if state.settings.ignored_apps.contains(&proc_name) {
            return;
        }
    }

    if should_skip_clipboard_event(Utc::now(), text, &state.runtime) {
        return;
    }
    let h = hex::encode(sha2::Sha256::digest(text.as_bytes()));
    state.runtime.last_clipboard_hash = Some(h);

    if !extract_tokens(text).is_empty() {
        let _ = app.emit(
            "toast",
            ToastPayload {
                mode: "suggest-restore",
                message: "AI Armor tokens detected. Restore details?".into(),
            },
        );
        return;
    }

    let cfg = DetectorConfig {
        terms: state.settings.sensitive_terms.clone(),
        term_word_boundary: true,
        custom_patterns: state
            .settings
            .user_patterns
            .iter()
            .map(|p| CustomPattern {
                name: p.name.clone(),
                regex: p.regex.clone(),
                word_boundary: p.word_boundary,
                enabled: p.enabled,
            })
            .collect(),
    };
    let mut entities = detect_sensitive(text, &cfg);
    if state.settings.high_risk_only {
        entities.retain(|e| e.kind.high_risk() && e.confidence >= 0.8);
    }
    if entities.is_empty() {
        return;
    }

    let _ = app.emit(
        "toast",
        ToastPayload {
            mode: "suggest-protect",
            message: format!(
                "Sensitive content detected ({} items). Protect for AI?",
                entities.len()
            ),
        },
    );
}

#[cfg(target_os = "windows")]
fn current_foreground_process_name() -> Option<String> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
    use windows::Win32::UI::WindowsAndMessaging::{GetForegroundWindow, GetWindowThreadProcessId};

    use windows::core::PWSTR;
    unsafe {
        let hwnd = GetForegroundWindow();
        if hwnd.is_invalid() {
            return None;
        }
        let mut pid = 0;
        GetWindowThreadProcessId(hwnd, Some(&mut pid));
        if pid == 0 {
            return None;
        }
        let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let mut size = 260u32;
        let mut buffer = vec![0u16; size as usize];
        let ok = windows::Win32::System::Threading::QueryFullProcessImageNameW(
            process,
            0,
            PWSTR(buffer.as_mut_ptr()),
            &mut size,
        );
        let _ = CloseHandle(process);
        if ok.is_ok() {
            let full = String::from_utf16_lossy(&buffer[..size as usize]);
            return full.rsplit('\\').next().map(|s| s.to_string());
        }
        None
    }
}

#[cfg(not(target_os = "windows"))]
fn current_foreground_process_name() -> Option<String> {
    None
}

#[cfg(target_os = "windows")]
fn start_windows_clipboard_listener(app: tauri::AppHandle) {
    std::thread::spawn(move || {
        use windows::core::PCWSTR;
        use windows::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
        use windows::Win32::UI::WindowsAndMessaging::{
            AddClipboardFormatListener, CreateWindowExW, DefWindowProcW, DispatchMessageW,
            GetMessageW, RegisterClassW, TranslateMessage, CS_HREDRAW, CS_VREDRAW, HMENU,
            HWND_MESSAGE, MSG, WM_CLIPBOARDUPDATE, WNDCLASSW,
        };

        unsafe extern "system" fn wndproc(
            hwnd: HWND,
            msg: u32,
            wparam: WPARAM,
            lparam: LPARAM,
        ) -> LRESULT {
            DefWindowProcW(hwnd, msg, wparam, lparam)
        }

        unsafe {
            let class_name: Vec<u16> = "AIArmorClipboardListener"
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();
            let wc = WNDCLASSW {
                style: CS_HREDRAW | CS_VREDRAW,
                lpfnWndProc: Some(wndproc),
                lpszClassName: PCWSTR(class_name.as_ptr()),
                ..Default::default()
            };
            let _ = RegisterClassW(&wc);

            let hwnd = CreateWindowExW(
                Default::default(),
                PCWSTR(class_name.as_ptr()),
                PCWSTR(class_name.as_ptr()),
                Default::default(),
                0,
                0,
                0,
                0,
                HWND_MESSAGE,
                HMENU::default(),
                None,
                None,
            );
            if hwnd.0 == 0 {
                return;
            }

            let _ = AddClipboardFormatListener(hwnd);

            let mut msg = MSG::default();
            while GetMessageW(&mut msg, None, 0, 0).into() {
                if msg.message == WM_CLIPBOARDUPDATE {
                    if let Ok(mut cb) = arboard::Clipboard::new() {
                        if let Ok(text) = cb.get_text() {
                            maybe_emit_clipboard_toast(&app, &text);
                        }
                    }
                }
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
    });
}

#[cfg(not(target_os = "windows"))]
fn start_windows_clipboard_listener(_app: tauri::AppHandle) {}

#[cfg(test)]
mod runtime_tests {
    use super::*;

    #[test]
    fn clipboard_skip_for_empty_and_large() {
        let rt = RuntimeState::default();
        assert!(should_skip_clipboard_event(Utc::now(), "", &rt));
        let huge = "a".repeat(MAX_CLIPBOARD_CHARS + 1);
        assert!(should_skip_clipboard_event(Utc::now(), &huge, &rt));
    }

    #[test]
    fn clipboard_skip_for_duplicate_hash() {
        let text = "hello sensitive";
        let rt = RuntimeState {
            last_clipboard_hash: Some(hex::encode(sha2::Sha256::digest(text.as_bytes()))),
            ..Default::default()
        };
        assert!(should_skip_clipboard_event(Utc::now(), text, &rt));
    }

    #[test]
    fn clipboard_skip_during_internal_write_cooldown() {
        let rt = RuntimeState {
            internal_write_until: Some(Utc::now() + Duration::seconds(2)),
            ..Default::default()
        };
        assert!(should_skip_clipboard_event(Utc::now(), "new text", &rt));
    }

    #[test]
    fn validate_sha256_hex_input() {
        assert!(is_valid_sha256_hex(&"a".repeat(64)));
        assert!(!is_valid_sha256_hex("xyz"));
        assert!(!is_valid_sha256_hex(&"g".repeat(64)));
    }

    #[test]
    fn normalize_process_name_sanitizes_controls() {
        let value = " chrome.exe\n\t";
        assert_eq!(normalize_process_name(value).as_deref(), Some("chrome.exe"));
        assert!(normalize_process_name("***").is_none());
    }

    #[test]
    fn safe_regex_limits_excessive_grouping() {
        let noisy = (0..30).map(|_| "(a)").collect::<String>();
        assert!(!is_safe_regex(&noisy));
        assert!(is_safe_regex(r"^foo-[0-9]{2}$"));
    }
}
