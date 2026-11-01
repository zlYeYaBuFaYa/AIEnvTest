//! Fixed command recipes. No shell, arbitrary programs, or UI-supplied argv.
use crate::{region::RegionPreset, transaction::*};
use std::{process::{Command, Stdio}, time::{Duration, Instant}};
type Result<T> = std::result::Result<T, String>;
#[derive(Clone, Copy, Debug)]
pub enum Os { Linux, Mac, Windows }
impl Os {
    pub fn current() -> Self {
        if cfg!(target_os="windows") {Self::Windows} else if cfg!(target_os="macos") {Self::Mac} else {Self::Linux}
    }
}
#[derive(Debug, PartialEq)]
pub struct Recipe { pub program: &'static str, pub args: Vec<String> }
fn recipe(program: &'static str, args: &[&str]) -> Recipe {Recipe {program, args:args.iter().map(|s|s.to_string()).collect()}}
pub fn valid_zone(zone: &str) -> bool {
    // Also accept previously installed zones for restoration, including tzutil's DST suffix.
    !zone.is_empty() && zone.len() <= 128 && zone.as_bytes()[0].is_ascii_alphanumeric() && zone.trim()==zone && !zone.contains("..") && zone.bytes().all(|c|c.is_ascii_alphanumeric() || b"/_+- .()".contains(&c))
}
pub fn timezone_recipe(os: Os, zone: Option<&str>) -> Result<Recipe> {
    if zone.is_some_and(|z|!valid_zone(z)) {return Err("repair.timezoneInvalid".into())}
    Ok(match (os, zone) {
        (Os::Linux,None)=>recipe("timedatectl", &["show","--property=Timezone","--value"]),
        (Os::Linux,Some(z))=>recipe("timedatectl", &["set-timezone",z]),
        (Os::Mac,None)=>recipe("systemsetup", &["-gettimezone"]),
        (Os::Mac,Some(z))=>recipe("systemsetup", &["-settimezone",z]),
        (Os::Windows,None)=>recipe("tzutil", &["/g"]),
        (Os::Windows,Some(z))=>recipe("tzutil", &["/s",z]),
    })
}
fn run(recipe: Recipe) -> Result<String> {
    // Bound runtime, require successful exit, and never include raw command output in errors.
    let executable=match recipe.program {
        "timedatectl"=>"/usr/bin/timedatectl", "systemctl"=>"/usr/bin/systemctl",
        "systemsetup"=>"/usr/sbin/systemsetup", "sntp"=>"/usr/bin/sntp", "open"=>"/usr/bin/open",
        "gnome-control-center"=>"/usr/bin/gnome-control-center",
        "tzutil"=>r"C:\Windows\System32\tzutil.exe", "w32tm"=>r"C:\Windows\System32\w32tm.exe",
        "powershell"=>r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "explorer.exe"=>r"C:\Windows\explorer.exe",
        _=>return Err("Command outside fixed allowlist".into()),
    };
    let mut child=Command::new(executable).args(recipe.args).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().map_err(|_|"repair.commandUnavailable".to_string())?;
    let start=Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success()=>break,
            Ok(Some(_))=>return Err("repair.commandFailed".into()),
            Ok(None) if start.elapsed()<Duration::from_secs(15)=>std::thread::sleep(Duration::from_millis(20)),
            _=>{let _=child.kill();let _=child.wait();return Err("repair.commandTimeout".into())}
        }
    }
    let output=child.wait_with_output().map_err(|_|"repair.invalidCommandOutput".to_string())?;
    String::from_utf8(output.stdout).map_err(|_|"repair.invalidCommandOutput".into())
}
pub fn read_timezone() -> Result<PreviousValue> {
    #[cfg(target_os="macos")] {
        // systemsetup -gettimezone itself requires root on modern macOS.
        let path=std::fs::read_link("/etc/localtime").map_err(|_|"repair.timezoneUnavailable".to_string())?;
        let text=path.to_string_lossy();
        let zone=text.split_once("/zoneinfo/").map(|(_,z)|z).ok_or("repair.timezoneUnavailable")?;
        if !valid_zone(zone) {return Err("repair.timezoneUnavailable".into())}
        return Ok(PreviousValue::Text(zone.into()));
    }
    #[cfg(not(target_os="macos"))] {
    let output=run(timezone_recipe(Os::current(),None)?)?;
    let zone=output.trim().strip_prefix("Time Zone: ").unwrap_or(output.trim());
    if !valid_zone(zone) {return Err("repair.timezoneUnavailable".into())}
    Ok(PreviousValue::Text(zone.into()))
    }
}
pub fn write_timezone(value: &PreviousValue) -> Result<()> {
    let PreviousValue::Text(zone)=value else {return Err("repair.timezoneInvalid".into())};
    run(timezone_recipe(Os::current(),Some(zone))?)?;
    if read_timezone()? != *value {return Err("repair.timezoneVerify".into())} Ok(())
}
pub fn preset_zone(os: Os, region: &RegionPreset) -> Result<String> {
    let primary=region.timezones.first().ok_or("Preset has no timezone")?;
    if matches!(os,Os::Windows) {
        crate::platform::windows_zones::WINDOWS_ZONES.iter()
            .find(|(_,territory,zones)| *territory==region.country && zones.split_whitespace().any(|z|z==primary))
            .map(|(windows,_,_)|windows.to_string()).ok_or_else(||"repair.timezoneMapping".into())
    } else {Ok(primary.clone())}
}
pub fn timezone_plan(adapter: &impl SystemAdapter, os: Os, region: &RegionPreset) -> Result<Option<FixPlan>> {
    let before=adapter.read(&ResourceId::Timezone)?;
    let PreviousValue::Text(current)=&before else {return Err("repair.timezoneUnavailable".into())};
    let after=preset_zone(os,region)?;
    if &after==current {return Ok(None)}
    let mut bytes=[0u8;16];getrandom::fill(&mut bytes).map_err(|e|e.to_string())?;
    Ok(Some(FixPlan{id:bytes.iter().map(|b|format!("{b:02x}")).collect(),check_id:"timezone".into(),steps:vec![FixStep::SetTimezone{zone:after.clone()}],requires_admin:!matches!(os,Os::Windows),resources:vec![ResourceId::Timezone],preview:vec![ChangePreview{resource:ResourceId::Timezone,before:display_value(&before),after}]}))
}
#[cfg(test)] mod tests {
    use super::*;
    use std::{collections::BTreeSet, sync::Mutex};
    struct Fake(Mutex<PreviousValue>);
    impl SystemAdapter for Fake {
        fn read(&self,_:&ResourceId)->Result<PreviousValue>{Ok(self.0.lock().unwrap().clone())}
        fn write(&self,_:&ResourceId,v:&PreviousValue)->Result<()>{*self.0.lock().unwrap()=v.clone();Ok(())}
    }
    #[test] fn timezone_all_os_presets_backup_restore() {
        for os in [Os::Linux,Os::Mac,Os::Windows] {for region in crate::region::catalog() {
            let mut random=[0;16];getrandom::fill(&mut random).unwrap();
            let dir=std::env::temp_dir().join(format!("aienv-zone-{:x}",u128::from_ne_bytes(random)));
            let engine=Engine{dir:dir.clone(),adapter:Fake(Mutex::new(PreviousValue::Text("UTC".into()))),locks:Default::default(),allowed:BTreeSet::from([ResourceId::Timezone])};
            let plan=timezone_plan(&engine.adapter,os,region).unwrap().unwrap();
            assert_eq!(plan.requires_admin,!matches!(os,Os::Windows));
            let command=timezone_recipe(os,Some(&plan.preview[0].after)).unwrap();
            assert_eq!(command.program,match os {Os::Linux=>"timedatectl",Os::Mac=>"systemsetup",Os::Windows=>"tzutil"});
            assert_eq!(command.args,vec![match os {Os::Linux=>"set-timezone",Os::Mac=>"-settimezone",Os::Windows=>"/s"}.to_string(),preset_zone(os,region).unwrap()]);
            let report=engine.apply(&plan).unwrap();assert!(report.success);
            assert_eq!(engine.load(&report.backup_id).unwrap().entries[0].previous_value,PreviousValue::Text("UTC".into()));
            assert!(engine.restore(&report.backup_id).unwrap().success);
            assert_eq!(engine.adapter.read(&ResourceId::Timezone).unwrap(),PreviousValue::Text("UTC".into()));
            std::fs::remove_dir_all(dir).unwrap();
        }}
    }
    #[test] fn invalid_zones_and_unobserved_state_refused() {
        for zone in ["", "--help", "UTC;id", "UTC\n", "$(id)"] {assert!(timezone_recipe(Os::Linux,Some(zone)).is_err())}
        assert!(timezone_plan(&Fake(Mutex::new(PreviousValue::Absent)),Os::Linux,crate::region::find("us").unwrap()).is_err());
    }
}

pub fn ntp_read_recipe(os: Os) -> Recipe {
    match os {
        Os::Linux=>recipe("timedatectl", &["show","--property=NTP","--value"]),
        Os::Mac=>recipe("systemsetup", &["-getusingnetworktime"]),
        Os::Windows=>recipe("powershell", &["-NoProfile","-NonInteractive","-Command","[Console]::OutputEncoding=[Text.UTF8Encoding]::new(); if ((Get-Service w32time -ErrorAction Stop).Status -eq 'Running') { 'true' } else { 'false' }"]),
    }
}
pub fn ntp_write_recipes(os: Os, enabled: bool) -> Vec<Recipe> {
    match os {
        Os::Linux=>{
            let mut commands=vec![recipe("timedatectl", &["set-ntp",if enabled {"true"} else {"false"}])];
            if enabled {commands.push(recipe("systemctl", &["restart","systemd-timesyncd.service"]))} commands
        },
        Os::Mac=>{
            let mut commands=vec![recipe("systemsetup", &["-setusingnetworktime",if enabled {"on"} else {"off"}])];
            if enabled {commands.push(recipe("sntp", &["-sS","time.apple.com"]))} commands
        },
        Os::Windows=>if enabled {vec![recipe("powershell", &["-NoProfile","-NonInteractive","-Command","$ErrorActionPreference='Stop'; Start-Service w32time"]),recipe("w32tm", &["/resync"])]}
            else {vec![recipe("powershell", &["-NoProfile","-NonInteractive","-Command","$ErrorActionPreference='Stop'; Stop-Service w32time"])]},
    }
}
pub fn read_ntp() -> Result<PreviousValue> {
    let text=run(ntp_read_recipe(Os::current()))?;
    let enabled=match text.trim() {"true"|"yes"|"Network Time: On"=>true,"false"|"no"|"Network Time: Off"=>false,_=>return Err("repair.ntpUnavailable".into())};
    Ok(PreviousValue::Text(enabled.to_string()))
}
pub fn write_ntp(value: &PreviousValue) -> Result<()> {
    let enabled=match value {PreviousValue::Text(s) if s=="true"=>true,PreviousValue::Text(s) if s=="false"=>false,_=>return Err("repair.ntpInvalid".into())};
    for command in ntp_write_recipes(Os::current(),enabled) {run(command)?;}
    if read_ntp()? != *value {return Err("repair.ntpVerify".into())} Ok(())
}
pub fn ntp_plan(adapter: &impl SystemAdapter) -> Result<Option<FixPlan>> {
    let before=adapter.read(&ResourceId::Ntp)?;
    if !matches!(&before,PreviousValue::Text(s) if matches!(s.as_str(),"true"|"false")) {return Err("repair.ntpUnavailable".into())}
    let mut bytes=[0;16];getrandom::fill(&mut bytes).map_err(|e|e.to_string())?;
    Ok(Some(FixPlan{id:bytes.iter().map(|b|format!("{b:02x}")).collect(),check_id:"clock".into(),steps:vec![FixStep::SetNtp{enabled:true}],requires_admin:true,resources:vec![ResourceId::Ntp],preview:vec![ChangePreview{resource:ResourceId::Ntp,before:display_value(&before),after:"true".into()}]}))
}

/// Guidance never enters the privileged helper or claims to have changed state.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(tag="type", rename_all="snake_case")]
pub enum GuidancePlan { LocationSettings }
pub fn location_settings_recipe(os: Os) -> Recipe {
    match os {
        Os::Linux=>recipe("gnome-control-center", &["privacy","location"]),
        Os::Mac=>recipe("open", &["x-apple.systempreferences:com.apple.preference.security?Privacy_LocationServices"]),
        Os::Windows=>recipe("explorer.exe", &["ms-settings:privacy-location"]),
    }
}
pub fn open_location_settings() -> Result<()> {
    let command=location_settings_recipe(Os::current());
    let executable=match Os::current() {Os::Linux=>"/usr/bin/gnome-control-center",Os::Mac=>"/usr/bin/open",Os::Windows=>r"C:\Windows\explorer.exe"};
    let mut child=Command::new(executable).args(command.args).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().map_err(|_|"repair.settingsUnavailable".to_string())?;
    // Settings windows may outlive this invocation. Reap without closing them.
    std::thread::spawn(move || {let _=child.wait();});
    Ok(())
}

#[cfg(test)] mod ntp_tests {
    use super::*;
    use std::sync::Mutex;
    struct Fake(Mutex<PreviousValue>);
    impl SystemAdapter for Fake {
        fn read(&self,_:&ResourceId)->Result<PreviousValue>{Ok(self.0.lock().unwrap().clone())}
        fn write(&self,_:&ResourceId,v:&PreviousValue)->Result<()>{*self.0.lock().unwrap()=v.clone();Ok(())}
    }
    fn roundtrip(os:Os) {
        let mut random=[0;16];getrandom::fill(&mut random).unwrap();let dir=std::env::temp_dir().join(format!("aienv-ntp-{:x}",u128::from_ne_bytes(random)));
        let engine=Engine{dir:dir.clone(),adapter:Fake(Mutex::new(PreviousValue::Text("false".into()))),locks:Default::default(),allowed:[ResourceId::Ntp].into_iter().collect()};
        let commands=ntp_write_recipes(os,true);
        assert_eq!(commands.len(),2);
        assert_eq!(commands[1],match os {Os::Linux=>recipe("systemctl", &["restart","systemd-timesyncd.service"]),Os::Mac=>recipe("sntp", &["-sS","time.apple.com"]),Os::Windows=>recipe("w32tm", &["/resync"])});
        let plan=ntp_plan(&engine.adapter).unwrap().unwrap();assert!(plan.requires_admin);
        let report=engine.apply(&plan).unwrap();assert!(report.success);
        assert_eq!(engine.load(&report.backup_id).unwrap().entries[0].previous_value,PreviousValue::Text("false".into()));
        assert!(engine.restore(&report.backup_id).unwrap().success);
        assert_eq!(engine.adapter.read(&ResourceId::Ntp).unwrap(),PreviousValue::Text("false".into()));
        assert_eq!(ntp_write_recipes(os,false).len(),1);
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test] fn ntp_linux(){roundtrip(Os::Linux)}
    #[test] fn ntp_macos(){roundtrip(Os::Mac)}
    #[test] fn ntp_windows(){roundtrip(Os::Windows)}
    #[test] fn ntp_unobserved_refused(){assert!(ntp_plan(&Fake(Mutex::new(PreviousValue::Absent))).is_err());}
    #[test] fn location_guidance_all_os(){
        assert_eq!(location_settings_recipe(Os::Linux),recipe("gnome-control-center", &["privacy","location"]));
        assert_eq!(location_settings_recipe(Os::Mac),recipe("open", &["x-apple.systempreferences:com.apple.preference.security?Privacy_LocationServices"]));
        assert_eq!(location_settings_recipe(Os::Windows),recipe("explorer.exe", &["ms-settings:privacy-location"]));
    }
}
