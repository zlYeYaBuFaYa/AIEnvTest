//! Transaction boundary. UI supplies opaque IDs, never executable plans.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, fs::{self, OpenOptions}, io::Write, path::{Path, PathBuf}, sync::Mutex};
type Result<T> = std::result::Result<T, String>;
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(tag="kind", content="value", deny_unknown_fields)]
pub enum ResourceId { File(PathBuf), Registry(String), Timezone, Dns(String) }
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag="type", deny_unknown_fields)]
pub enum FixStep {
    WriteFile { path: PathBuf, contents: String },
    RemoveFile { path: PathBuf },
    SetRegistry { key: String, name: String, value: String },
    RunCommand { program: String, args: Vec<String>, undo: Box<FixStep> },
    SetTimezone { zone: String },
    SetDns { iface: String, servers: Vec<String> },
}
impl FixStep { fn resource(&self) -> Result<ResourceId> { match self {
    Self::WriteFile{path,..}|Self::RemoveFile{path} => Ok(ResourceId::File(path.clone())),
    _ => Err("Operation is not enabled in this release".into()),
} } }
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangePreview { pub resource: ResourceId, pub before: String, pub after: String }
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixPlan { pub id: String, pub check_id: String, pub steps: Vec<FixStep>, pub requires_admin: bool, pub resources: Vec<ResourceId>, pub preview: Vec<ChangePreview> }
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag="state", content="value", deny_unknown_fields)]
pub enum PreviousValue { Absent, Text(String) }
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupEntry { pub resource: ResourceId, pub previous_value: PreviousValue }
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Backup { pub schema_version: u32, pub id: String, pub created_at: String, pub os: String, pub os_version: String, pub app_version: String, pub check_id: String, pub scope: Vec<ResourceId>, pub entries: Vec<BackupEntry>, pub sha256: String }
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupSummary { pub id: String, pub created_at: String, pub check_id: String, pub scope: Vec<ResourceId>, pub integrity: bool }
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepStatus { pub index: usize, pub status: String, pub error: Option<String> }
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixReport { pub backup_id: String, pub success: bool, pub steps: Vec<StepStatus> }
fn id() -> String { let mut bytes=[0u8;16]; getrandom::fill(&mut bytes).expect("OS randomness"); format!("{}-{}", chrono::Utc::now().format("%Y%m%dT%H%M%S%.9f"), bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()) }
fn digest<T: Serialize>(value: &T) -> Result<String> {
    // serde_json::Value uses sorted BTreeMap keys (preserve_order is disabled).
    let canonical = serde_json::to_vec(&serde_json::to_value(value).map_err(|e|e.to_string())?).map_err(|e|e.to_string())?;
    Ok(format!("{:x}", Sha256::digest(canonical)))
}
impl Backup {
    fn seal(&mut self) -> Result<()> { self.sha256.clear(); self.sha256=digest(self)?; Ok(()) }
    pub fn verify(&self) -> Result<()> { let mut copy=self.clone(); copy.seal()?; if self.schema_version!=1 || copy.sha256!=self.sha256 { return Err("Backup integrity or schema mismatch".into()); } Ok(()) }
}
pub fn atomic_write(path: &Path, contents: &[u8]) -> Result<()> {
    let parent=path.parent().ok_or("Missing parent")?; fs::create_dir_all(parent).map_err(|e|e.to_string())?;
    let temp=parent.join(format!(".{}.tmp",id()));
    let result=(|| { let mut options=OpenOptions::new(); options.write(true).create_new(true);
        #[cfg(unix)] { use std::os::unix::fs::OpenOptionsExt; options.mode(0o600); }
        let mut file=options.open(&temp).map_err(|e|e.to_string())?;
        file.write_all(contents).and_then(|_|file.sync_all()).map_err(|e|e.to_string())?;
        fs::rename(&temp,path).map_err(|e|e.to_string())?;
        #[cfg(unix)] fs::File::open(parent).and_then(|d|d.sync_all()).map_err(|e|e.to_string())?;
        Ok(()) })();
    if result.is_err() { let _=fs::remove_file(temp); } result
}
pub fn hosts_path() -> PathBuf {
    #[cfg(windows)] { PathBuf::from(r"C:\Windows\System32\drivers\etc\hosts") }
    #[cfg(not(windows))] { PathBuf::from("/etc/hosts") }
}
pub fn validate(plan: &FixPlan, allowed: &BTreeSet<ResourceId>) -> Result<()> {
    let scope: BTreeSet<_>=plan.resources.iter().cloned().collect();
    if scope.is_empty() || scope.len()!=plan.resources.len() || !scope.is_subset(allowed) { return Err("Resource outside allowlist".into()); }
    for step in &plan.steps { if !scope.contains(&step.resource()?) { return Err("Step outside plan scope".into()); } }
    if plan.steps.is_empty() { return Err("Empty plan".into()); } Ok(())
}
pub trait SystemAdapter: Send + Sync {
    fn read(&self, resource: &ResourceId) -> Result<PreviousValue>;
    fn write(&self, resource: &ResourceId, value: &PreviousValue) -> Result<()>;
    /// One privileged batch, including rollback, per transaction.
    fn batch(&self, plan: &FixPlan, before: &[BackupEntry]) -> Result<Vec<StepStatus>> { Ok(apply_steps(self,plan,before)) }
}
fn value(step: &FixStep) -> Result<PreviousValue> { match step { FixStep::WriteFile{contents,..}=>Ok(PreviousValue::Text(contents.clone())), FixStep::RemoveFile{..}=>Ok(PreviousValue::Absent), _=>Err("Unsupported step".into()) } }
fn apply_steps<A: SystemAdapter + ?Sized>(adapter: &A, plan: &FixPlan, before: &[BackupEntry]) -> Vec<StepStatus> {
    let mut statuses: Vec<StepStatus> = Vec::new();
    let mut applied = Vec::new();
    let mut expected: std::collections::BTreeMap<_,_> = before.iter().map(|e|(e.resource.clone(),e.previous_value.clone())).collect();
    for (index, step) in plan.steps.iter().enumerate() {
        let mut pending = None;
        let result: Result<()> = (|| {
            let resource = step.resource()?;
            let next = value(step)?;
            let previous = expected.get(&resource).cloned().ok_or("Resource missing from backup")?;
            if adapter.read(&resource)? != previous { return Err("Resource changed since backup".into()); }
            // Retain this even if write fails after partially changing the resource.
            pending = Some((resource.clone(), previous));
            adapter.write(&resource, &next)?;
            expected.insert(resource, next);
            Ok(())
        })();
        match result {
            Ok(()) => {
                applied.push(pending.take().expect("successful write has a prior value"));
                statuses.push(StepStatus {index, status:"applied".into(), error:None});
            }
            Err(mut error) => {
                let mut status = "failed";
                if let Some((resource, previous)) = pending {
                    if let Err(rollback_error) = adapter.write(&resource, &previous) {
                        status = "rollback_failed";
                        error = format!("{error}; rollback: {rollback_error}");
                    }
                }
                statuses.push(StepStatus {index, status:status.into(), error:Some(error)});
                for (rollback_index, (resource, previous)) in applied.into_iter().enumerate().rev() {
                    let result = adapter.write(&resource, &previous);
                    statuses[rollback_index].status = if result.is_ok() {"rolled_back"} else {"rollback_failed"}.into();
                    statuses[rollback_index].error = result.err();
                }
                for skipped in index+1..plan.steps.len() {
                    statuses.push(StepStatus {index:skipped, status:"skipped".into(), error:None});
                }
                break;
            }
        }
    }
    statuses
}

#[derive(Default)]
pub struct LockManager { held: Mutex<BTreeSet<ResourceId>> }
pub struct ResourceGuard<'a> { manager: &'a LockManager, resources: Vec<ResourceId>, file: fs::File }
impl LockManager {
    pub fn acquire<'a>(&'a self, dir: &Path, resources: &[ResourceId]) -> Result<ResourceGuard<'a>> {
        fs::create_dir_all(dir).map_err(|e|e.to_string())?;
        let mut held=self.held.lock().map_err(|e|e.to_string())?;
        if resources.iter().any(|r|held.contains(r)) { return Err("Resources are busy".into()); }
        // OS-owned file lock releases on crash; conservative cross-instance serialization.
        let file=OpenOptions::new().create(true).truncate(false).read(true).write(true).open(dir.join("transaction.lock")).map_err(|e|e.to_string())?;
        file.try_lock().map_err(|_|"Another transaction is active".to_string())?;
        held.extend(resources.iter().cloned()); Ok(ResourceGuard{manager:self,resources:resources.to_vec(),file})
    }
}
impl Drop for ResourceGuard<'_> { fn drop(&mut self) { if let Ok(mut held)=self.manager.held.lock() { for r in &self.resources { held.remove(r); } } let _=self.file.unlock(); } }
pub struct Engine<A: SystemAdapter> { pub dir: PathBuf, pub adapter: A, pub locks: std::sync::Arc<LockManager>, pub allowed: BTreeSet<ResourceId> }
impl<A: SystemAdapter> Engine<A> {
    fn snapshot(&self, check_id: &str, resources: &[ResourceId]) -> Result<Backup> {
        let entries=resources.iter().map(|r|Ok(BackupEntry{resource:r.clone(),previous_value:self.adapter.read(r)?})).collect::<Result<Vec<_>>>()?;
        let mut backup=Backup{schema_version:1,id:id(),created_at:chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Nanos,true),os:std::env::consts::OS.into(),os_version:os_version(),app_version:env!("CARGO_PKG_VERSION").into(),check_id:check_id.into(),scope:resources.to_vec(),entries,sha256:String::new()}; backup.seal()?; Ok(backup)
    }
    fn save(&self, backup: &Backup) -> Result<()> { atomic_write(&self.dir.join("backups").join(format!("{}.json",backup.id)), &serde_json::to_vec(backup).map_err(|e|e.to_string())?) }
    pub fn backup(&self, check_id: &str, resources: &[ResourceId]) -> Result<Backup> {
        if resources.is_empty() || resources.iter().cloned().collect::<BTreeSet<_>>().len()!=resources.len() || resources.iter().any(|r|!self.allowed.contains(r)) { return Err("Resource outside allowlist".into()); }
        let _guard=self.locks.acquire(&self.dir,resources)?; let backup=self.snapshot(check_id,resources)?; self.save(&backup)?; Ok(backup)
    }
    pub fn apply(&self, plan: &FixPlan) -> Result<FixReport> {
        validate(plan,&self.allowed)?; let _guard=self.locks.acquire(&self.dir,&plan.resources)?;
        let backup=self.snapshot(&plan.check_id,&plan.resources)?;
        // Refuse stale previews before elevation or mutation.
        for preview in &plan.preview { let current=backup.entries.iter().find(|e|e.resource==preview.resource).ok_or("Invalid preview")?; if display_value(&current.previous_value)!=preview.before { return Err("Plan is stale; create a new preview".into()); } }
        self.save(&backup)?; let steps=self.adapter.batch(plan,&backup.entries)?;
        Ok(FixReport{backup_id:backup.id,success:steps.iter().all(|s|s.status=="applied"),steps})
    }
    pub fn load(&self, backup_id: &str) -> Result<Backup> {
        if backup_id.is_empty() || !backup_id.chars().all(|c|c.is_ascii_alphanumeric()||c=='-'||c=='.') || backup_id.contains("..") { return Err("Invalid backup ID".into()); }
        let backup:Backup=serde_json::from_slice(&fs::read(self.dir.join("backups").join(format!("{backup_id}.json"))).map_err(|e|e.to_string())?).map_err(|e|e.to_string())?;
        backup.verify()?; if backup.id!=backup_id || backup.os!=std::env::consts::OS { return Err("Backup platform or identity mismatch".into()); } Ok(backup)
    }
    pub fn list(&self) -> Result<Vec<BackupSummary>> {
        let dir=self.dir.join("backups"); if !dir.exists(){return Ok(vec![])}
        let mut summaries=Vec::new();
        for entry in fs::read_dir(dir).map_err(|e|e.to_string())? { let path=entry.map_err(|e|e.to_string())?.path(); if path.extension().and_then(|s|s.to_str())!=Some("json"){continue}
            let file_id=path.file_stem().unwrap_or_default().to_string_lossy().to_string();
            let parsed=fs::read(&path).ok().and_then(|b|serde_json::from_slice::<Backup>(&b).ok());
            summaries.push(if let Some(b)=parsed { BackupSummary{id:file_id.clone(),created_at:b.created_at,check_id:b.check_id,scope:b.scope,integrity:self.load(&file_id).is_ok()} } else { BackupSummary{id:file_id,created_at:String::new(),check_id:String::new(),scope:vec![],integrity:false} });
        } summaries.sort_by(|a,b|b.created_at.cmp(&a.created_at).then(b.id.cmp(&a.id))); Ok(summaries)
    }
    fn restore_locked(&self, backup: &Backup) -> Result<FixReport> {
        backup.verify()?;
        let resources:BTreeSet<_>=backup.entries.iter().map(|e|e.resource.clone()).collect();
        if resources!=backup.scope.iter().cloned().collect() || resources.len()!=backup.entries.len() { return Err("Invalid backup scope".into()); }
        let steps=backup.entries.iter().map(|e|match (&e.resource,&e.previous_value) { (ResourceId::File(path),PreviousValue::Text(contents))=>Ok(FixStep::WriteFile{path:path.clone(),contents:contents.clone()}), (ResourceId::File(path),PreviousValue::Absent)=>Ok(FixStep::RemoveFile{path:path.clone()}), _=>Err("Unsupported backup resource".into()) }).collect::<Result<Vec<_>>>()?;
        let plan=FixPlan{id:id(),check_id:backup.check_id.clone(),steps,resources:backup.scope.clone(),requires_admin:true,preview:vec![]}; validate(&plan,&self.allowed)?;
        let before=self.snapshot(&backup.check_id,&backup.scope)?;
        // Recovery journal for a failed restore, excluded from normal history/restore_all.
        atomic_write(&self.dir.join("recovery").join(format!("{}.json",before.id)), &serde_json::to_vec(&before).map_err(|e|e.to_string())?)?;
        let steps=self.adapter.batch(&plan,&before.entries)?; Ok(FixReport{backup_id:backup.id.clone(),success:steps.iter().all(|s|s.status=="applied"),steps})
    }
    pub fn restore(&self, backup_id: &str) -> Result<FixReport> { let backup=self.load(backup_id)?; let _guard=self.locks.acquire(&self.dir,&backup.scope)?; self.restore_locked(&backup) }
    pub fn restore_all(&self) -> Result<Vec<FixReport>> {
        let summaries = self.list()?;
        let backups = summaries.iter().map(|s| self.load(&s.id)).collect::<Result<Vec<_>>>()?;
        if backups.is_empty() { return Ok(vec![]); }
        let resources = backups.iter().flat_map(|b| b.scope.clone()).collect::<BTreeSet<_>>().into_iter().collect::<Vec<_>>();
        let _guard = self.locks.acquire(&self.dir, &resources)?;
        let mut steps = Vec::new();
        let mut ranges = Vec::new();
        for backup in &backups {
            let start = steps.len();
            let scope: BTreeSet<_> = backup.scope.iter().cloned().collect();
            if scope != backup.entries.iter().map(|e|e.resource.clone()).collect() || scope.len()!=backup.entries.len() {
                return Err("Invalid backup scope".into());
            }
            for entry in &backup.entries {
                steps.push(match (&entry.resource, &entry.previous_value) {
                    (ResourceId::File(path), PreviousValue::Text(contents)) => FixStep::WriteFile {path:path.clone(), contents:contents.clone()},
                    (ResourceId::File(path), PreviousValue::Absent) => FixStep::RemoveFile {path:path.clone()},
                    _ => return Err("Unsupported backup resource".into()),
                });
            }
            ranges.push((start, steps.len()));
        }
        // The entire going-home operation is one elevated batch and one rollback scope.
        let plan = FixPlan {id:id(), check_id:"restore_all".into(), steps, requires_admin:true, resources, preview:vec![]};
        validate(&plan, &self.allowed)?;
        let before = self.snapshot("restore_all", &plan.resources)?;
        atomic_write(&self.dir.join("recovery").join(format!("{}.json",before.id)), &serde_json::to_vec(&before).map_err(|e|e.to_string())?)?;
        let statuses = self.adapter.batch(&plan, &before.entries)?;
        let success = statuses.iter().all(|s|s.status=="applied");
        Ok(backups.iter().zip(ranges).map(|(backup,(start,end))| FixReport {
            backup_id:backup.id.clone(), success,
            steps:statuses.iter().filter(|s|s.index>=start && s.index<end).cloned().map(|mut s|{s.index-=start;s}).collect(),
        }).collect())
    }

}
fn os_version() -> String {
    #[cfg(unix)] let output=std::process::Command::new("uname").arg("-r").output();
    #[cfg(windows)] let output=std::process::Command::new("cmd").args(["/C","ver"]).output();
    output.ok().filter(|o|o.status.success()).map(|o|String::from_utf8_lossy(&o.stdout).trim().to_string()).unwrap_or_else(||"unknown".into())
}
pub fn display_value(value: &PreviousValue) -> String { match value { PreviousValue::Absent=>"∅".into(), PreviousValue::Text(s)=>s.clone() } }
pub fn hosts_plan(adapter: &impl SystemAdapter) -> Result<Option<FixPlan>> {
    let path=hosts_path(); let resource=ResourceId::File(path.clone());
    let previous=adapter.read(&resource)?; let PreviousValue::Text(before)=previous else {return Err("Hosts file is absent".into())};
    let after=clean_hosts(&before); if before==after {return Ok(None)}
    Ok(Some(FixPlan{id:id(),check_id:"hosts".into(),steps:vec![FixStep::WriteFile{path,contents:after.clone()}],requires_admin:true,resources:vec![resource.clone()],preview:vec![ChangePreview{resource,before,after}]}))
}
pub fn clean_hosts(input: &str) -> String {
    let mut output=String::new();
    for line in input.split_inclusive('\n') {
        let body=line.split('#').next().unwrap_or(""); let fields:Vec<_>=body.split_whitespace().collect();
        let target=|s:&str| { let name=s.trim_end_matches('.').to_ascii_lowercase(); ["claude.ai","anthropic.com"].iter().any(|d|name==*d||name.ends_with(&format!(".{d}"))) };
        if fields.len()<2 || !fields[1..].iter().any(|s|target(s)) {output.push_str(line);continue}
        let remaining=fields[1..].iter().filter(|s|!target(s)).copied().collect::<Vec<_>>();
        if !remaining.is_empty() {output.push_str(fields[0]);output.push('\t');output.push_str(&remaining.join(" ")); if let Some((_,comment))=line.split_once('#') {output.push_str(" #");output.push_str(comment.trim_end_matches(['\r','\n']));} if line.ends_with('\n'){output.push('\n');} }
        else if let Some((_,comment))=line.split_once('#') {output.push('#');output.push_str(comment);}
    } output
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, atomic::{AtomicUsize,Ordering}};
    use std::collections::BTreeMap;
    struct Temp(PathBuf);
    impl Temp {fn new()->Self {let path=std::env::temp_dir().join(format!("aienv-test-{}",id()));fs::create_dir_all(&path).unwrap();Self(path)}}
    impl Drop for Temp {fn drop(&mut self){let _=fs::remove_dir_all(&self.0);}}
    #[derive(Default)] struct Fake {
        values:Mutex<BTreeMap<ResourceId,PreviousValue>>,
        writes:AtomicUsize, fail_at:AtomicUsize, batches:AtomicUsize,
        fail_extra:Mutex<BTreeSet<usize>>,
        log:Mutex<Vec<(ResourceId,PreviousValue)>>,
    }
    impl SystemAdapter for Fake {
        fn read(&self,r:&ResourceId)->Result<PreviousValue>{Ok(self.values.lock().unwrap().get(r).cloned().unwrap_or(PreviousValue::Absent))}
        fn write(&self,r:&ResourceId,v:&PreviousValue)->Result<()> {
            let n=self.writes.fetch_add(1,Ordering::SeqCst)+1;
            self.values.lock().unwrap().insert(r.clone(),v.clone()); // fail after a partial mutation
            self.log.lock().unwrap().push((r.clone(),v.clone()));
            if n==self.fail_at.load(Ordering::SeqCst) || self.fail_extra.lock().unwrap().contains(&n){return Err("injected partial failure".into())} Ok(())
        }
        fn batch(&self,p:&FixPlan,b:&[BackupEntry])->Result<Vec<StepStatus>>{self.batches.fetch_add(1,Ordering::SeqCst);Ok(apply_steps(self,p,b))}
    }
    fn resource(name:&str)->ResourceId {ResourceId::File(PathBuf::from(name))}
    fn engine(temp:&Temp)->Engine<Fake>{Engine{dir:temp.0.clone(),adapter:Fake::default(),locks:Arc::default(),allowed:[resource("a"),resource("b"),ResourceId::File(hosts_path())].into_iter().collect()}}
    fn plan()->FixPlan {FixPlan{id:id(),check_id:"fake".into(),steps:vec![FixStep::WriteFile{path:"a".into(),contents:"new-a".into()},FixStep::WriteFile{path:"b".into(),contents:"new-b".into()}],requires_admin:true,resources:vec![resource("a"),resource("b")],preview:vec![]}}
    fn seed(engine:&Engine<Fake>){engine.adapter.values.lock().unwrap().insert(resource("a"),PreviousValue::Text("old-a".into()));}
    #[test] fn mid_plan_failure_rolls_back_reverse_and_absence(){let temp=Temp::new();let e=engine(&temp);seed(&e);e.adapter.fail_at.store(2,Ordering::SeqCst);let report=e.apply(&plan()).unwrap();assert!(!report.success);assert_eq!(report.steps[0].status,"rolled_back");assert_eq!(e.adapter.read(&resource("a")).unwrap(),PreviousValue::Text("old-a".into()));assert_eq!(e.adapter.read(&resource("b")).unwrap(),PreviousValue::Absent);let log=e.adapter.log.lock().unwrap();assert_eq!(log[2].0,resource("b"));assert_eq!(log[3].0,resource("a"));assert_eq!(e.adapter.batches.load(Ordering::SeqCst),1);assert_eq!(e.list().unwrap().len(),1);}
    #[test] fn tampered_backup_rejected_without_writes(){let temp=Temp::new();let e=engine(&temp);let b=e.backup("fake",&[resource("a")]).unwrap();let path=e.dir.join("backups").join(format!("{}.json",b.id));let mut edited=b.clone();edited.entries[0].previous_value=PreviousValue::Text("tampered".into());fs::write(path,serde_json::to_vec(&edited).unwrap()).unwrap();assert!(e.restore(&b.id).is_err());assert_eq!(e.adapter.writes.load(Ordering::SeqCst),0);assert!(!e.list().unwrap()[0].integrity);}
    #[test] fn lock_contention_and_release(){let temp=Temp::new();let locks=LockManager::default();let other=LockManager::default();let guard=locks.acquire(&temp.0,&[resource("a")]).unwrap();assert!(locks.acquire(&temp.0,&[resource("a")]).is_err());assert!(other.acquire(&temp.0,&[resource("a")]).is_err());drop(guard);assert!(other.acquire(&temp.0,&[resource("a")]).is_ok());}
    #[test] fn atomic_write_replaces_and_cleans_temp_on_failure(){let temp=Temp::new();let path=temp.0.join("backup.json");atomic_write(&path,b"first").unwrap();atomic_write(&path,b"second").unwrap();assert_eq!(fs::read(&path).unwrap(),b"second");let directory=temp.0.join("directory");fs::create_dir(&directory).unwrap();assert!(atomic_write(&directory,b"bad").is_err());assert!(directory.is_dir());assert!(fs::read_dir(&temp.0).unwrap().all(|e|!e.unwrap().file_name().to_string_lossy().ends_with(".tmp")));}
    #[test] fn restore_all_newest_first_without_adding_history(){let temp=Temp::new();let e=engine(&temp);seed(&e);let first=e.backup("fake",&[resource("a")]).unwrap();e.adapter.values.lock().unwrap().insert(resource("a"),PreviousValue::Text("middle".into()));let mut second=e.backup("fake",&[resource("a")]).unwrap();second.created_at="9999-01-01T00:00:00Z".into();second.seal().unwrap();e.save(&second).unwrap();e.adapter.values.lock().unwrap().insert(resource("a"),PreviousValue::Text("latest".into()));let reports=e.restore_all().unwrap();assert_eq!(reports.iter().map(|r|r.backup_id.as_str()).collect::<Vec<_>>(),vec![second.id.as_str(),first.id.as_str()]);assert_eq!(e.adapter.read(&resource("a")).unwrap(),PreviousValue::Text("old-a".into()));assert_eq!(e.list().unwrap().len(),2);assert_eq!(e.adapter.batches.load(Ordering::SeqCst),1);assert_eq!(e.restore_all().unwrap().len(),2);}
    #[test] fn restore_failure_rolls_back_restore_itself(){let temp=Temp::new();let e=engine(&temp);seed(&e);let backup=e.backup("fake",&plan().resources).unwrap();e.adapter.values.lock().unwrap().insert(resource("a"),PreviousValue::Text("present-a".into()));e.adapter.values.lock().unwrap().insert(resource("b"),PreviousValue::Text("present-b".into()));e.adapter.fail_at.store(2,Ordering::SeqCst);let report=e.restore(&backup.id).unwrap();assert!(!report.success);assert_eq!(e.adapter.read(&resource("a")).unwrap(),PreviousValue::Text("present-a".into()));assert_eq!(e.adapter.read(&resource("b")).unwrap(),PreviousValue::Text("present-b".into()));}
    #[test] fn demo_hosts_end_to_end(){let temp=Temp::new();let e=engine(&temp);let hosts=ResourceId::File(hosts_path());let before="# comment claude.ai\n127.0.0.1 localhost CLAUDE.AI api.anthropic.com # keep\n0.0.0.0 claude.ai.evil\n0.0.0.0 claude.ai\n";e.adapter.values.lock().unwrap().insert(hosts.clone(),PreviousValue::Text(before.into()));let p=hosts_plan(&e.adapter).unwrap().unwrap();assert_eq!(p.preview[0].after,"# comment claude.ai\n127.0.0.1\tlocalhost # keep\n0.0.0.0 claude.ai.evil\n");let report=e.apply(&p).unwrap();assert!(report.success);assert!(hosts_plan(&e.adapter).unwrap().is_none());assert!(e.restore(&report.backup_id).unwrap().success);assert_eq!(e.adapter.read(&hosts).unwrap(),PreviousValue::Text(before.into()));}
    #[test] fn stale_preview_does_not_mutate(){let temp=Temp::new();let e=engine(&temp);let mut p=plan();p.preview=vec![ChangePreview{resource:resource("a"),before:"old".into(),after:"new".into()}];assert!(e.apply(&p).is_err());assert!(e.list().unwrap().is_empty());assert_eq!(e.adapter.writes.load(Ordering::SeqCst),0);}
    #[test] fn invalid_restore_all_is_preflighted(){let temp=Temp::new();let e=engine(&temp);let b=e.backup("fake",&[resource("a")]).unwrap();fs::write(e.dir.join("backups").join(format!("{}.json",b.id)),b"not json").unwrap();assert!(e.restore_all().is_err());assert_eq!(e.adapter.writes.load(Ordering::SeqCst),0);assert_eq!(e.list().unwrap().len(),1);}
    #[test] fn canonical_integrity_ignores_json_key_order(){let temp=Temp::new();let e=engine(&temp);let b=e.backup("fake",&[resource("a")]).unwrap();let bytes=serde_json::to_string_pretty(&b).unwrap();let parsed:Backup=serde_json::from_str(&bytes).unwrap();parsed.verify().unwrap();}
    #[test] fn restore_all_failure_rolls_back_the_whole_batch() {
        let temp=Temp::new();let e=engine(&temp);seed(&e);
        e.backup("fake",&[resource("a")]).unwrap();
        e.adapter.values.lock().unwrap().insert(resource("a"),PreviousValue::Text("middle".into()));
        let mut newer=e.backup("fake",&[resource("a")]).unwrap();newer.created_at="9999-01-01T00:00:00Z".into();newer.seal().unwrap();e.save(&newer).unwrap();
        e.adapter.values.lock().unwrap().insert(resource("a"),PreviousValue::Text("current".into()));
        e.adapter.fail_at.store(2,Ordering::SeqCst);
        let reports=e.restore_all().unwrap();assert_eq!(reports.len(),2);assert!(reports.iter().all(|r|!r.success));
        assert_eq!(e.adapter.read(&resource("a")).unwrap(),PreviousValue::Text("current".into()));assert_eq!(e.adapter.batches.load(Ordering::SeqCst),1);
    }
    #[test] fn failed_snapshot_or_backup_storage_prevents_writes() {
        struct Unreadable;
        impl SystemAdapter for Unreadable {
            fn read(&self,_:&ResourceId)->Result<PreviousValue>{Err("read denied".into())}
            fn write(&self,_:&ResourceId,_:&PreviousValue)->Result<()>{panic!("must not write after failed snapshot")}
        }
        let temp=Temp::new();let unreadable=Engine{dir:temp.0.clone(),adapter:Unreadable,locks:Arc::default(),allowed:plan().resources.into_iter().collect()};
        assert!(unreadable.apply(&plan()).is_err());assert!(!temp.0.join("backups").exists());
        let e=engine(&temp);fs::write(temp.0.join("backups"),"blocks backup storage").unwrap();assert!(e.apply(&plan()).is_err());assert_eq!(e.adapter.writes.load(Ordering::SeqCst),0);
    }
    #[test] fn atomic_readers_never_observe_partial_json() {
        let temp=Temp::new();let path=temp.0.join("snapshot.json");let bytes=serde_json::to_vec(&vec!["payload";1000]).unwrap();atomic_write(&path,&bytes).unwrap();
        std::thread::scope(|scope| {let writer=scope.spawn(|| {for _ in 0..20 {atomic_write(&path,&bytes).unwrap();}});for _ in 0..100 {let observed=fs::read(&path).unwrap();assert!(serde_json::from_slice::<Vec<String>>(&observed).is_ok());}writer.join().unwrap();});
    }

    #[test] fn rollback_failures_are_reported_per_step() {
        let temp=Temp::new();let e=engine(&temp);seed(&e);
        e.adapter.fail_at.store(2,Ordering::SeqCst);e.adapter.fail_extra.lock().unwrap().extend([3,4]);
        let report=e.apply(&plan()).unwrap();assert!(!report.success);assert_eq!(report.steps.len(),2);
        assert!(report.steps.iter().all(|s|s.status=="rollback_failed"));assert!(e.load(&report.backup_id).is_ok());
    }
    #[test] fn failed_observation_during_apply_does_not_write() {
        struct Flaky {reads:AtomicUsize}
        impl SystemAdapter for Flaky {
            fn read(&self,_:&ResourceId)->Result<PreviousValue>{if self.reads.fetch_add(1,Ordering::SeqCst)>=2 {Err("cannot observe".into())}else{Ok(PreviousValue::Absent)}}
            fn write(&self,_:&ResourceId,_:&PreviousValue)->Result<()>{panic!("read failure must not trigger a write")}
        }
        let temp=Temp::new();let e=Engine{dir:temp.0.clone(),adapter:Flaky{reads:AtomicUsize::new(0)},locks:Arc::default(),allowed:plan().resources.into_iter().collect()};
        let report=e.apply(&plan()).unwrap();assert!(!report.success);assert_eq!(report.steps[0].status,"failed");assert_eq!(report.steps[1].status,"skipped");
    }

    #[test] fn unknown_backup_fields_cannot_bypass_integrity() {
        let temp=Temp::new();let e=engine(&temp);let b=e.backup("fake",&[resource("a")]).unwrap();
        let mut json=serde_json::to_value(&b).unwrap();json["unrecognized"]=serde_json::json!("tampered");
        fs::write(e.dir.join("backups").join(format!("{}.json",b.id)),serde_json::to_vec(&json).unwrap()).unwrap();
        assert!(e.load(&b.id).is_err());assert!(!e.list().unwrap()[0].integrity);
    }

}
