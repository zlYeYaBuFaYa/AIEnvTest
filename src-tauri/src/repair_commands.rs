use crate::{transaction::*, helper::{OsAdapter, allowlist}, AppState, model::{ScanReport, Status}};
use tauri::Manager;
use serde::Serialize;
fn engine(app:&tauri::AppHandle)->Result<Engine<OsAdapter>,String> {
    let dir=app.path().app_data_dir().map_err(|e|e.to_string())?;
    Ok(Engine{adapter:OsAdapter{dir:dir.clone()},dir,locks:app.state::<AppState>().locks.clone(),allowed:allowlist()})
}
#[derive(Serialize)]
pub struct PlanView { id:String, check_id:String, requires_admin:bool, preview:Vec<ChangePreview>, guidance:Option<crate::system_fixes::GuidancePlan> }
fn remember(app:&tauri::AppHandle,plan:FixPlan)->Result<PlanView,String> {
    let view=PlanView{guidance:None,id:plan.id.clone(),check_id:plan.check_id.clone(),requires_admin:plan.requires_admin,preview:plan.preview.iter().map(|p|ChangePreview{resource:p.resource.clone(),before:crate::redact::redact_text(&p.before),after:crate::redact::redact_text(&p.after)}).collect()};
    let state=app.state::<AppState>();let mut plans=state.plans.lock().map_err(|e|e.to_string())?;
    if plans.len() >= 128 { if let Some(key)=plans.keys().next().cloned() {plans.remove(&key);} }
    plans.insert(plan.id.clone(),plan);Ok(view)
}
#[tauri::command]
pub fn plan_fix(app:tauri::AppHandle,check_id:String)->Result<Option<PlanView>,String> {
    if check_id=="location" {return Ok(Some(PlanView{id:"location-settings".into(),check_id,requires_admin:false,preview:vec![],guidance:Some(crate::system_fixes::GuidancePlan::LocationSettings)}))}
    let adapter=engine(&app)?.adapter;
    let plan=match check_id.as_str() {
        "hosts"=>hosts_plan(&adapter)?,
        "clock"=>crate::system_fixes::ntp_plan(&adapter)?,
        "timezone"=>{
            let region=app.state::<AppState>().region.lock().map_err(|e|e.to_string())?.clone().ok_or("repair.scanRequired")?;
            crate::system_fixes::timezone_plan(&adapter,crate::system_fixes::Os::current(),crate::region::find(&region).ok_or("Unknown region")?)?
        },
        _=>return Ok(None),
    };
    plan.map(|p|remember(&app,p)).transpose()
}
#[tauri::command]
pub fn plan_fix_all_failed(app:tauri::AppHandle)->Result<Vec<PlanView>,String> {
    let ids=app.state::<AppState>().last_report.lock().map_err(|e|e.to_string())?.as_ref().map(|r|r.checks.iter().filter(|c|c.status==Status::Fail && matches!(c.id.as_str(),"hosts"|"timezone"|"clock")).map(|c|c.id.clone()).collect::<Vec<_>>()).unwrap_or_default();
    ids.into_iter().filter_map(|id|plan_fix(app.clone(),id).transpose()).collect()
}
#[derive(Serialize)]
pub struct Update { transactions:Vec<FixReport>, report:Option<ScanReport>, scan_error:Option<String> }
async fn refresh(app:tauri::AppHandle,transactions:Vec<FixReport>)->Result<Update,String> {
    let region=app.state::<AppState>().region.lock().map_err(|e|e.to_string())?.clone();
    let (report,scan_error)=match crate::run_scan(app,region.unwrap_or_else(||"us".into())).await {
        Ok(report)=>(Some(report),None),Err(e)=>(None,Some(e)),
    };
    Ok(Update{transactions,report,scan_error})
}
#[tauri::command]
pub async fn apply_plan(app:tauri::AppHandle,plan_id:String)->Result<Update,String> {
    let plan=app.state::<AppState>().plans.lock().map_err(|e|e.to_string())?.remove(&plan_id).ok_or("Unknown or expired plan")?;
    let engine=engine(&app)?;let result=tauri::async_runtime::spawn_blocking(move||engine.apply(&plan)).await.map_err(|e|e.to_string())??;
    refresh(app,vec![result]).await
}
#[tauri::command]
pub async fn backup(app:tauri::AppHandle,check_id:String)->Result<BackupSummary,String> {
    let resources=match check_id.as_str() {"hosts"=>vec![ResourceId::File(hosts_path())],"timezone"=>vec![ResourceId::Timezone],"clock"=>vec![ResourceId::Ntp],_=>return Err("No resources registered for this check".into())};
    let engine=engine(&app)?;let b=tauri::async_runtime::spawn_blocking(move||engine.backup(&check_id,&resources)).await.map_err(|e|e.to_string())??;
    Ok(BackupSummary{id:b.id,created_at:b.created_at,check_id:b.check_id,scope:b.scope,integrity:true})
}
#[tauri::command]
pub fn list_backups(app:tauri::AppHandle)->Result<Vec<BackupSummary>,String>{engine(&app)?.list()}
#[tauri::command]
pub async fn restore(app:tauri::AppHandle,backup_id:String)->Result<Update,String> {
    let engine=engine(&app)?;let result=tauri::async_runtime::spawn_blocking(move||engine.restore(&backup_id)).await.map_err(|e|e.to_string())??;
    refresh(app,vec![result]).await
}
#[tauri::command]
pub async fn restore_all(app:tauri::AppHandle)->Result<Update,String> {
    let engine=engine(&app)?;let results=tauri::async_runtime::spawn_blocking(move||engine.restore_all()).await.map_err(|e|e.to_string())??;refresh(app,results).await
}

#[tauri::command]
pub fn open_location_settings()->Result<(),String> {crate::system_fixes::open_location_settings()}
