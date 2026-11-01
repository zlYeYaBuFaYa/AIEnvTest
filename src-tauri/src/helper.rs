//! Narrow elevated entry point. Hash binds argv to immutable request bytes;
//! it is integrity checking, not a substitute for the fixed operation allowlist.
use crate::transaction::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, fs, path::{Path, PathBuf}, process::Command};
type Result<T> = std::result::Result<T,String>;
pub fn allowlist() -> BTreeSet<ResourceId> { [ResourceId::File(hosts_path()), ResourceId::Timezone, ResourceId::Ntp].into_iter().collect() }
#[derive(Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
struct Request { version:u32, plan:FixPlan, before:Vec<BackupEntry> }
#[derive(Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
struct Response { digest:String, result:Result<Vec<StepStatus>> }
pub struct OsAdapter { pub dir:PathBuf }
struct LocalAdapter;
fn read_file(resource:&ResourceId)->Result<PreviousValue> {
    if resource == &ResourceId::Ntp { return crate::system_fixes::read_ntp(); }
    if resource == &ResourceId::Timezone { return crate::system_fixes::read_timezone(); }
    if !allowlist().contains(resource) {return Err("Read outside allowlist".into())}
    let ResourceId::File(path)=resource else {return Err("Unsupported resource".into())};
    match fs::read_to_string(path) {Ok(text)=>Ok(PreviousValue::Text(text)),Err(e) if e.kind()==std::io::ErrorKind::NotFound=>Ok(PreviousValue::Absent),Err(e)=>Err(e.to_string())}
}
impl SystemAdapter for LocalAdapter {
    fn read(&self,r:&ResourceId)->Result<PreviousValue>{read_file(r)}
    fn write(&self,r:&ResourceId,v:&PreviousValue)->Result<()> {
        if !allowlist().contains(r){return Err("Write outside allowlist".into())}
        if r == &ResourceId::Ntp { return crate::system_fixes::write_ntp(v); }
        if r == &ResourceId::Timezone { return crate::system_fixes::write_timezone(v); }
        let ResourceId::File(path)=r else {return Err("Unsupported resource".into())};
        if fs::symlink_metadata(path).is_ok_and(|m|m.file_type().is_symlink() || !m.is_file()) {return Err("Hosts must be a regular file".into())}
        match v {PreviousValue::Text(s)=>fs::write(path,s).map_err(|e|e.to_string()),PreviousValue::Absent=>match fs::remove_file(path){Ok(())=>Ok(()),Err(e) if e.kind()==std::io::ErrorKind::NotFound=>Ok(()),Err(e)=>Err(e.to_string())}}
    }
}
impl SystemAdapter for OsAdapter {
    fn read(&self,r:&ResourceId)->Result<PreviousValue>{read_file(r)}
    fn write(&self,_:&ResourceId,_:&PreviousValue)->Result<()> {Err("Writes require an elevated transaction".into())}
    fn batch(&self,plan:&FixPlan,before:&[BackupEntry])->Result<Vec<StepStatus>> {
        validate(plan,&allowlist())?;
        if !plan.requires_admin && plan.resources.iter().all(|r|r == &ResourceId::Timezone) { return LocalAdapter.batch(plan,before); }
        let request=Request{version:1,plan:plan.clone(),before:before.to_vec()};
        let bytes=serde_json::to_vec(&request).map_err(|e|e.to_string())?;
        let hash=format!("{:x}",Sha256::digest(&bytes));
        let dir=self.dir.join("helper"); fs::create_dir_all(&dir).map_err(|e|e.to_string())?;
        #[cfg(unix)] {use std::os::unix::fs::PermissionsExt;fs::set_permissions(&dir,fs::Permissions::from_mode(0o700)).map_err(|e|e.to_string())?;}
        let mut random=[0;16];getrandom::fill(&mut random).map_err(|e|e.to_string())?;
        let name=random.iter().map(|b|format!("{b:02x}")).collect::<String>();
        let path=dir.join(format!("{name}.json")); let result_path=path.with_extension("result.json");
        atomic_write(&path,&bytes)?;
        // Precreate the output as the caller. The helper never creates privileged output paths.
        if let Err(error)=atomic_write(&result_path,b"") {let _=fs::remove_file(&path);return Err(error)}
        let result=(|| { elevate(&path,&hash)?; let response:Response=serde_json::from_slice(&fs::read(&result_path).map_err(|e|e.to_string())?).map_err(|e|e.to_string())?; if response.digest!=hash{return Err("Helper response mismatch".into())} response.result })();
        let _=fs::remove_file(&path); let _=fs::remove_file(result_path); result
    }
}
#[cfg(any(test, target_os="macos"))]
pub fn sh_quote(value:&str)->String {format!("'{}'",value.replace('\'',"'\"'\"'"))}
#[cfg(any(test, target_os="windows"))]
pub fn powershell_quote(value:&str)->String {format!("'{}'",value.replace('\'',"''"))}
#[cfg(any(test, target_os="macos"))]
pub fn applescript_quote(value:&str)->String {format!("\"{}\"",value.replace('\\',"\\\\").replace('"',"\\\""))}
fn elevate(path:&Path,hash:&str)->Result<()> {
    let exe=std::env::current_exe().map_err(|e|e.to_string())?;
    #[cfg(target_os="linux")]
    let status=match Command::new("pkexec").arg(&exe).arg("--helper").arg(path).arg(hash).status() {
        Err(e) if e.kind()==std::io::ErrorKind::NotFound=>Command::new("sudo").arg("-n").arg("--").arg(&exe).arg("--helper").arg(path).arg(hash).status(),
        other=>other,
    };
    #[cfg(target_os="macos")]
    let status={ let shell=format!("{} --helper {} {}",sh_quote(&exe.to_string_lossy()),sh_quote(&path.to_string_lossy()),sh_quote(hash)); Command::new("osascript").arg("-e").arg(format!("do shell script {} with administrator privileges",applescript_quote(&shell))).status() };
    #[cfg(target_os="windows")]
    let status={
        // Start-Process joins ArgumentList into a Windows command line. Paths cannot contain double quotes.
        let args=format!("--helper \"{}\" {}",path.display(),hash);
        let script=format!("$p = Start-Process -FilePath {} -ArgumentList {} -Verb RunAs -Wait -PassThru; exit $p.ExitCode",powershell_quote(&exe.to_string_lossy()),powershell_quote(&args));
        Command::new("powershell").args(["-NoProfile","-NonInteractive","-Command",&script]).status()
    };
    let status=status.map_err(|e|format!("Needs administrator authorization: {e}"))?;
    if !status.success(){return Err("Needs administrator authorization, or helper failed".into())} Ok(())
}
fn validate_request(request:&Request)->Result<()> {
    if request.version!=1{return Err("Unknown helper schema".into())} validate(&request.plan,&allowlist())?;
    let resources:BTreeSet<_>=request.before.iter().map(|e|e.resource.clone()).collect();
    if resources!=request.plan.resources.iter().cloned().collect() || resources.len()!=request.before.len(){return Err("Invalid helper snapshot scope".into())} Ok(())
}
fn decode_request(bytes: &[u8], expected: &str) -> Result<Request> {
    if bytes.len()>4*1024*1024 {return Err("Plan too large".into())}
    if format!("{:x}",Sha256::digest(bytes))!=expected {return Err("Helper integrity mismatch".into())}
    let request:Request=serde_json::from_slice(bytes).map_err(|e|e.to_string())?;
    validate_request(&request)?; Ok(request)
}
fn open_result(path:&Path, request:&fs::File)->Result<fs::File> {
    let metadata=fs::symlink_metadata(path).map_err(|e|e.to_string())?;
    if !metadata.is_file() || metadata.file_type().is_symlink(){return Err("Helper output must be a regular caller-owned file".into())}
    let mut options=fs::OpenOptions::new();options.read(true).write(true);
    #[cfg(windows)] {use std::os::windows::fs::OpenOptionsExt;options.share_mode(0).custom_flags(0x00200000);}
    let output=options.open(path).map_err(|e|e.to_string())?;
    let actual=output.metadata().map_err(|e|e.to_string())?;
    #[cfg(unix)] {
        use std::os::unix::fs::MetadataExt;
        let owner=request.metadata().map_err(|e|e.to_string())?.uid();
        if actual.uid()!=owner || actual.nlink()!=1 || actual.ino()!=metadata.ino() || actual.dev()!=metadata.dev() {
            return Err("Helper output ownership or identity mismatch".into());
        }
    }
    #[cfg(windows)] {
        use std::os::windows::fs::MetadataExt;
        if actual.file_attributes() & 0x400 != 0 {return Err("Reparse points are not helper outputs".into())}
        let _=request;
    }
    if actual.len()!=0 {return Err("Helper output must be empty".into())}
    Ok(output)
}
/// Called before Tauri initializes. Never invoke in ordinary tests.
pub fn entry()->Option<i32> {
    let mut args=std::env::args_os().skip(1); if args.next().as_deref()!=Some(std::ffi::OsStr::new("--helper")){return None}
    let result:Result<()>=(|| {let path=PathBuf::from(args.next().ok_or("Missing plan")?); let expected=args.next().ok_or("Missing digest")?.to_string_lossy().to_string(); if args.next().is_some(){return Err("Unexpected arguments".into())}
        use std::io::Read;
        let file=fs::File::open(&path).map_err(|e|e.to_string())?;
        if !file.metadata().map_err(|e|e.to_string())?.is_file(){return Err("Helper plan must be a regular file".into())}
        let result_path=path.with_extension("result.json");
        let mut output=open_result(&result_path,&file)?;
        let mut bytes=Vec::new();file.take(4*1024*1024+1).read_to_end(&mut bytes).map_err(|e|e.to_string())?;
        let request=decode_request(&bytes,&expected)?;let hash=expected;
        // Re-read under elevation to detect changes since backup; never overwrite a stale snapshot.
        for entry in &request.before {if LocalAdapter.read(&entry.resource)?!=entry.previous_value{return Err("Resource changed since backup".into())}}
        let response=Response{digest:hash,result:LocalAdapter.batch(&request.plan,&request.before)};
        use std::io::Write;
        output.write_all(&serde_json::to_vec(&response).map_err(|e|e.to_string())?).and_then(|_|output.sync_all()).map_err(|e|e.to_string())?;
        Ok(()) })();
    Some(if result.is_ok(){0}else{eprintln!("Helper rejected transaction: {}",result.unwrap_err());1})
}
#[cfg(test)] mod tests {
    use super::*;
    #[test] fn quoting(){assert_eq!(sh_quote("a'b;$()"),"'a'\"'\"'b;$()'");assert_eq!(powershell_quote("a'b;$()"),"'a''b;$()'");assert_eq!(applescript_quote("a\"b\\c"),"\"a\\\"b\\\\c\"");}
    #[test] fn rejects_paths_and_commands(){let mut p=FixPlan{id:"x".into(),check_id:"hosts".into(),resources:vec![ResourceId::File(PathBuf::from("/tmp/evil"))],steps:vec![FixStep::WriteFile{path:PathBuf::from("/tmp/evil"),contents:String::new()}],requires_admin:true,preview:vec![]};assert!(validate(&p,&allowlist()).is_err());p.resources=allowlist().into_iter().collect();p.steps=vec![FixStep::RunCommand{program:"sh".into(),args:vec![],undo:Box::new(FixStep::SetTimezone{zone:"UTC".into()})}];assert!(validate(&p,&allowlist()).is_err());}
    #[test] fn helper_integrity_scope_and_types() {
        let resource=ResourceId::File(hosts_path());
        let request=Request{version:1,plan:FixPlan{id:"test".into(),check_id:"hosts".into(),steps:vec![FixStep::WriteFile{path:hosts_path(),contents:"fake".into()}],requires_admin:true,resources:vec![resource.clone()],preview:vec![]},before:vec![BackupEntry{resource,previous_value:PreviousValue::Absent}]};
        let bytes=serde_json::to_vec(&request).unwrap();let hash=format!("{:x}",Sha256::digest(&bytes));
        assert!(decode_request(&bytes,&hash).is_ok());assert!(decode_request(&bytes,"bad").is_err());
        let mut request=request;request.before.clear();assert!(validate_request(&request).is_err());
        for step in [FixStep::SetRegistry{key:"HKLM".into(),name:"x".into(),value:"x".into()},FixStep::SetDns{iface:"eth0".into(),servers:vec![]},FixStep::SetTimezone{zone:"--invalid".into()},FixStep::WriteFile{path:hosts_path().join("../evil"),contents:String::new()}] {request.plan.steps=vec![step];assert!(validate(&request.plan,&allowlist()).is_err());}
    }
    #[test] fn enabled_system_steps_are_scoped() {
        for (resource,step) in [(ResourceId::Timezone,FixStep::SetTimezone{zone:"Asia/Tokyo".into()}),(ResourceId::Ntp,FixStep::SetNtp{enabled:true})] {
            let plan=FixPlan{id:"typed".into(),check_id:"system".into(),resources:vec![resource.clone()],steps:vec![step],requires_admin:true,preview:vec![]};
            assert!(validate(&plan,&allowlist()).is_ok());
            let mut wrong=plan;wrong.resources=vec![ResourceId::File(hosts_path())];
            assert!(validate(&wrong,&allowlist()).is_err());
        }
    }
    #[cfg(unix)]
    #[test] fn shell_quote_roundtrip() {
        for input in ["", "a'b", "$(printf injected); `printf injected`", "a\nb\tc", "\\ \" * ?"] {
            let output=Command::new("sh").args(["-c",&format!("printf %s {}",sh_quote(input))]).output().unwrap();assert!(output.status.success());assert_eq!(String::from_utf8(output.stdout).unwrap(),input);
        }
    }

    #[test] fn helper_output_is_precreated_and_empty() {
        let mut random=[0;16];getrandom::fill(&mut random).unwrap();let dir=std::env::temp_dir().join(format!("aienv-helper-test-{:x}",Sha256::digest(random)));fs::create_dir(&dir).unwrap();
        let request=dir.join("request.json");fs::write(&request,b"fake request").unwrap();let request=fs::File::open(request).unwrap();let output=dir.join("output.json");
        assert!(open_result(&output,&request).is_err());fs::write(&output,b"").unwrap();assert!(open_result(&output,&request).is_ok());
        fs::write(&output,b"already used").unwrap();assert!(open_result(&output,&request).is_err());fs::remove_dir_all(dir).unwrap();
    }
    #[cfg(unix)]
    #[test] fn helper_output_rejects_links() {
        let mut random=[0;16];getrandom::fill(&mut random).unwrap();let dir=std::env::temp_dir().join(format!("aienv-helper-links-{:x}",Sha256::digest(random)));fs::create_dir(&dir).unwrap();
        let request=dir.join("request.json");fs::write(&request,b"fake request").unwrap();let request=fs::File::open(request).unwrap();let target=dir.join("target");fs::write(&target,b"").unwrap();let output=dir.join("output.json");
        std::os::unix::fs::symlink(&target,&output).unwrap();assert!(open_result(&output,&request).is_err());fs::remove_file(&output).unwrap();
        fs::hard_link(&target,&output).unwrap();assert!(open_result(&output,&request).is_err());assert!(fs::read(&target).unwrap().is_empty());fs::remove_dir_all(dir).unwrap();
    }

}
