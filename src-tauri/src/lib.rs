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
use scan::PreparedScan;

struct AppState {
    browser: Mutex<Option<browser::Hub>>,
}

#[tauri::command]
fn list_regions() -> Vec<RegionSummary> {
    region::summaries()
}

#[tauri::command]
async fn run_scan(state: tauri::State<'_, AppState>, region_id: String) -> Result<ScanReport, String> {
    let prepared: PreparedScan = scan::execute(&region_id).await?;
    if let Ok(mut guard) = state.browser.lock() {
        *guard = Some(prepared.hub);
    }
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
        Err(format!("Could not open the browser. The page is at {url}"))
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(AppState { browser: Mutex::new(None) })
        .invoke_handler(tauri::generate_handler![list_regions, run_scan, render_markdown, write_export, reopen_browser])
        .run(tauri::generate_context!())
        .expect("error while running AIEnv");
}
