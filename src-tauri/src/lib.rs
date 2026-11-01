mod transaction;
mod system_fixes;
mod system_settings;
mod udp_fix;
mod helper;
mod repair_commands;
mod redact;
mod pac;
mod browser;
mod check;
mod checks;
mod context;
mod i18n;
mod intel;
mod model;
mod net;
mod platform;
mod region;
mod report;
mod scan;

use std::sync::Mutex;

use model::{RegionSummary, ScanReport};
use tauri::{Emitter, Manager};

struct AppState {
    browser: Mutex<Option<browser::Hub>>,
    region: Mutex<Option<String>>,
    last_report: Mutex<Option<ScanReport>>,
    plans: Mutex<std::collections::BTreeMap<String, transaction::FixPlan>>,
    locks: std::sync::Arc<transaction::LockManager>,
}

#[tauri::command]
fn list_regions() -> Vec<RegionSummary> {
    region::summaries()
}

#[tauri::command]
async fn run_scan(app: tauri::AppHandle, region_id: String) -> Result<ScanReport, String> {
    *app.state::<AppState>().region.lock().map_err(|e|e.to_string())? = Some(region_id.clone());
    let ready_app = app.clone();
    let report_app = app.clone();
    let prepared = scan::execute_with(&region_id, move |hub| {
        let url = hub.public_url();
        if let Ok(mut guard) = ready_app.state::<AppState>().browser.lock() { *guard = Some(hub); }
        let _ = ready_app.emit("browser-ready", url);
    }, move |report| { let _ = app.emit("report-updated", report); }).await?;
    *report_app.state::<AppState>().last_report.lock().map_err(|e|e.to_string())? = Some(prepared.report.clone());
    Ok(prepared.report)
}

#[tauri::command]
fn render_markdown(report: ScanReport, lang: String) -> String {
    report::markdown(&report, &lang)
}

#[tauri::command]
fn write_export(app: tauri::AppHandle, file_name: String, contents: String) -> Result<String, String> {
    use tauri::Manager;
    let dir = app.path().download_dir().or_else(|_| app.path().home_dir()).map_err(|err| err.to_string())?;
    std::fs::create_dir_all(&dir).map_err(|err| err.to_string())?;
    let mut safe = String::new();
    for ch in file_name.chars() {
        if ch.is_ascii_alphanumeric() || ch == '.' || ch == '-' || ch == '_' {
            safe.push(ch);
        }
    }
    if safe.is_empty() {
        safe = "aienv-report.json".into();
    }
    let path = dir.join(safe);
    std::fs::write(&path, contents).map_err(|err| err.to_string())?;
    Ok(path.display().to_string())
}

#[tauri::command]
fn reopen_browser(state: tauri::State<'_, AppState>) -> Result<String, String> {
    let guard = state.browser.lock().map_err(|err| err.to_string())?;
    let hub = guard.as_ref().ok_or("Run a scan first so the local browser page is available.")?;
    let url = hub.url.clone();
    let opened = browser::open_url(&url);
    if opened {
        Ok(hub.public_url())
    } else {
        Err("Could not open the browser page.".into())
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    if let Some(code) = helper::entry() { std::process::exit(code); }
    tauri::Builder::default()
        .manage(AppState { browser: Mutex::new(None), region: Mutex::new(None), last_report: Mutex::new(None), plans: Mutex::new(Default::default()), locks: Default::default() })
        .invoke_handler(tauri::generate_handler![list_regions, run_scan, render_markdown, write_export, reopen_browser, repair_commands::open_location_settings, repair_commands::plan_fix, repair_commands::plan_fix_all_failed, repair_commands::apply_plan, repair_commands::backup, repair_commands::list_backups, repair_commands::restore, repair_commands::restore_all])
        .run(tauri::generate_context!())
        .expect("error while running AIEnv");
}
