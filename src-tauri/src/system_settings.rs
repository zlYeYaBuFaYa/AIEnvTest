//! Fixed, reversible settings. Snapshots preserve absence and automatic DNS.
use crate::{system_fixes::{Os,Recipe,recipe,run}, transaction::*};
use serde::{Serialize,Deserialize};
use serde_json::{Value,json};
type Result<T> = std::result::Result<T,String>;
#[derive(Debug,Clone,Copy,Serialize,Deserialize,PartialEq,Eq,PartialOrd,Ord)]
pub enum Setting { Language, Dns, Ipv6, Proxy, Location, LocationMachine }
impl Setting {pub const ALL:[Self;6]=[Self::Language,Self::Dns,Self::Ipv6,Self::Proxy,Self::Location,Self::LocationMachine];}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Entry {pub id:String,pub values:Vec<String>}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq)]
#[serde(deny_unknown_fields)]
pub struct State {pub entries:Vec<Entry>}
fn encode(state:State)->Result<String>{serde_json::to_string(&state).map_err(|_|"repair.settingsUnknown".into())}
fn decode(text:&str)->Result<State>{serde_json::from_str(text).map_err(|_|"repair.settingsUnknown".into())}
fn entry(id:&str,values:Vec<String>)->Entry{Entry{id:id.into(),values}}
fn ps(script:&str)->Recipe{recipe("powershell", &["-NoProfile","-NonInteractive","-Command",&format!("$ErrorActionPreference='Stop'; [Console]::OutputEncoding=[Text.UTF8Encoding]::new(); {script}")])}
fn quote(s:&str)->String{format!("'{}'",s.replace('\'',"''"))}
fn strings(value:&Value)->Result<Vec<String>>{value.as_array().ok_or("repair.settingsUnknown")?.iter().map(|v|v.as_str().map(str::to_owned).ok_or_else(||"repair.settingsUnknown".into())).collect()}
pub fn requires_admin(r:&ResourceId)->bool {match r {
    ResourceId::Setting(Setting::Language)=>cfg!(target_os="linux"),
    ResourceId::Setting(Setting::Proxy)=>cfg!(target_os="macos"),
    ResourceId::Setting(Setting::Location)=>false,
    ResourceId::Timezone=>!cfg!(windows), _=>true,
}}
pub fn validate_value(setting:Setting,text:&str)->Result<()> {
    if text.len()>1024*1024{return Err("repair.settingsUnknown".into())}
    let state=decode(text)?;
    if state.entries.is_empty()||state.entries.len()>256{return Err("repair.settingsUnknown".into())}
    if setting==Setting::Language {
        let ids=state.entries.iter().map(|e|e.id.as_str()).collect::<std::collections::BTreeSet<_>>();
        if ids==std::collections::BTreeSet::from(["system","/etc/locale.conf","/etc/default/locale"]){
            for e in &state.entries {if e.id!="system" {if e.values.len()>1{return Err("repair.settingsUnknown".into())}for line in e.values.first().map(String::as_str).unwrap_or("").lines(){let line=line.trim();if line.is_empty()||line.starts_with('#'){continue}let (key,value)=line.split_once('=').ok_or("repair.settingsUnknown")?;let value=value.trim().trim_matches(['\'','"']);if !LOCALE_KEYS.contains(&key.trim())||!safe_locale(value){return Err("repair.settingsUnknown".into())}}}}
        }else if ids!=std::collections::BTreeSet::from(["AppleLanguages","AppleLocale"])&&ids!=std::collections::BTreeSet::from(["windows"]){return Err("repair.settingsUnknown".into())}
    }
    let mut ids=std::collections::BTreeSet::new();
    for e in &state.entries {
        if e.id.is_empty() || e.id.len()>256 || e.id.starts_with('-') || e.id.contains(['\n','\r','\0']) || !ids.insert(&e.id) || e.values.iter().any(|v|v.contains('\0')) {return Err("repair.settingsUnknown".into())}
        if setting==Setting::Ipv6 && e.id=="drop-in" {
            if e.values.len()>1{return Err("repair.settingsUnknown".into())}
            for line in e.values.first().map(String::as_str).unwrap_or("").lines(){
                let line=line.trim();if line.is_empty()||line.starts_with('#'){continue}
                let (key,value)=line.split_once('=').ok_or("repair.settingsUnknown")?;
                let iface=key.trim().strip_prefix("net/ipv6/conf/").and_then(|s|s.strip_suffix("/disable_ipv6")).ok_or("repair.settingsUnknown")?;
                if !safe_iface(iface)||!matches!(value.trim(),"0"|"1"){return Err("repair.settingsUnknown".into())}
            }
        }
        if matches!(setting,Setting::Location|Setting::LocationMachine) && (!matches!(e.id.as_str(),"HKCU"|"HKLM") || e.values.len()>1) {return Err("repair.settingsUnknown".into())}
    }
    Ok(())
}
/// Each resource has a closed schema; the helper cannot execute UI-provided code.
pub fn read(setting:Setting)->Result<PreviousValue> {Ok(PreviousValue::Text(encode(read_state(Os::current(),setting)?)?))}
fn mac_services()->Result<Vec<String>> {
    let out=run(recipe("networksetup", &["-listallnetworkservices"]))?;
    let services:Vec<_>=out.lines().skip(1).filter(|s|!s.is_empty()&&!s.starts_with('*')).map(str::to_owned).collect();
    if services.is_empty(){return Err("repair.settingsUnknown".into())} Ok(services)
}
fn read_state(os:Os,setting:Setting)->Result<State> {
    let entries=match (os,setting) {
        (Os::Linux,Setting::Language)=>{
            let output=run(recipe("localectl", &["status","--no-pager"]))?;
            let mut values=vec![];let mut observed=false;
            for line in output.lines(){
                let line=line.trim();
                let value=if let Some(v)=line.strip_prefix("System Locale:"){observed=true;v.trim()}else if observed && (line.starts_with("LC_")||line.starts_with("LANG=")){line}else{continue};
                if value!="n/a" && value!="(unset)" && !value.is_empty(){values.extend(value.split_whitespace().map(str::to_owned));}
            }
            if !observed{return Err("repair.settingsUnknown".into())}
            let mut entries=vec![entry("system",values)];
            for path in ["/etc/locale.conf","/etc/default/locale"]{
                let values=match std::fs::read_to_string(path){Ok(s)=>vec![s],Err(e) if e.kind()==std::io::ErrorKind::NotFound=>vec![],Err(_)=>return Err("repair.settingsUnknown".into())};entries.push(entry(path,values));
            }entries
        },
        (Os::Mac,Setting::Language)=>{
            // Read through CFPreferences rather than a potentially stale on-disk plist.
            let xml=run(recipe("defaults", &["export","NSGlobalDomain","-"]))?;
            let mut random=[0;16];getrandom::fill(&mut random).map_err(|_|"repair.settingsUnknown")?;
            let path=std::env::temp_dir().join(format!("aienv-preferences-{:x}.plist",u128::from_ne_bytes(random)));
            atomic_write(&path,xml.as_bytes())?;
            let converted=run(recipe("plutil", &["-convert","json","-o","-",path.to_str().ok_or("repair.settingsUnknown")?]));
            let _=std::fs::remove_file(path);
            let v:Value=serde_json::from_str(&converted?).map_err(|_|"repair.settingsUnknown")?;
            vec![entry("AppleLanguages",v.get("AppleLanguages").map(|v|strings(v).map(|_|vec![v.to_string()])).transpose()?.unwrap_or_default()),entry("AppleLocale",v.get("AppleLocale").map(|v|v.as_str().map(|s|vec![s.to_owned()]).ok_or("repair.settingsUnknown")).transpose()?.unwrap_or_default())]
        },
        (Os::Windows,Setting::Language)=>{
            let text=run(ps("@{languages=@(Get-WinUserLanguageList | ForEach-Object { @{tag=$_.LanguageTag; tips=@($_.InputMethodTips); spell=$_.Spellchecking; handwriting=$_.Handwriting} }); culture=(Get-Culture).Name; geo=(Get-WinHomeLocation).GeoId} | ConvertTo-Json -Depth 6 -Compress"))?;
            let _:Value=serde_json::from_str(&text).map_err(|_|"repair.settingsUnknown")?;
            vec![entry("windows",vec![text.trim().into()])]
        },
        (Os::Linux,Setting::Proxy)=>vec![entry("ignore-hosts",vec![run(recipe("gsettings", &["get","org.gnome.system.proxy","ignore-hosts"]))?.trim().into()])],
        (Os::Mac,Setting::Proxy)=>{
            let mut entries=vec![];
            for service in mac_services()? {
                let out=run(recipe("networksetup", &["-getproxybypassdomains",&service]))?;
                let values=if out.trim().starts_with("There aren't any bypass domains set") {vec![]}else{out.lines().map(str::to_owned).collect()};
                entries.push(entry(&service,values));
            } entries
        },
        (Os::Windows,Setting::Proxy)=>{
            let text=run(ps("$p=Get-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings'; if ($null -eq $p.ProxyOverride) { '[]' } else { if ((Get-Item 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings').GetValueKind('ProxyOverride') -ne 'String') {throw 'Unsupported registry type'}; ConvertTo-Json -InputObject @([string]$p.ProxyOverride) -Compress }"))?;
            vec![entry("ProxyOverride",strings(&serde_json::from_str(&text).map_err(|_|"repair.settingsUnknown")?)?)]
        },
        (Os::Windows,Setting::Location|Setting::LocationMachine)=>{
            let text=run(ps("$h=@(HIVE); $r=@(foreach($x in $h) {$p=\"${x}:\\Software\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\location\"; $v=if(Test-Path $p){(Get-ItemProperty $p).Value}else{$null}; if($null -ne $v -and (Get-Item $p).GetValueKind('Value') -ne 'String'){throw 'Unsupported registry type'}; @{id=$x;values=@(if($null -ne $v){[string]$v})}}); ConvertTo-Json -InputObject @{entries=$r} -Depth 5 -Compress".replace("HIVE",if setting==Setting::LocationMachine{"'HKLM'"}else{"'HKCU'"}).as_str()))?;
            return decode(text.trim())
        },
        (Os::Linux,Setting::Ipv6)=>{
            let mut entries=vec![];
            for item in std::fs::read_dir("/sys/class/net").map_err(|_|"repair.settingsUnknown")? {
                let item=item.map_err(|_|"repair.settingsUnknown")?;
                if !item.path().join("device").exists(){continue}
                let id=item.file_name().to_string_lossy().into_owned();
                if !safe_iface(&id){return Err("repair.settingsUnknown".into())}
                let value=std::fs::read_to_string(format!("/proc/sys/net/ipv6/conf/{id}/disable_ipv6")).map_err(|_|"repair.settingsUnknown")?;
                entries.push(entry(&id,vec![value.trim().into()]));
            }
            if entries.is_empty(){return Err("repair.settingsUnknown".into())}
            let file=match std::fs::read_to_string(IPV6_FILE){Ok(s)=>vec![s],Err(e) if e.kind()==std::io::ErrorKind::NotFound=>vec![],Err(_)=>return Err("repair.settingsUnknown".into())};
            entries.push(entry("drop-in",file));entries
        },
        (Os::Mac,Setting::Ipv6)=>{
            let ports=run(recipe("networksetup", &["-listallhardwareports"]))?;
            let devices=ports.lines().filter_map(|s|s.strip_prefix("Device: ")).filter(|s|s.starts_with("en")).collect::<Vec<_>>();
            let order=run(recipe("networksetup", &["-listnetworkserviceorder"]))?;
            let mut services=vec![];let mut service=None;
            for line in order.lines(){
                if line.starts_with('(') && line.as_bytes().get(1).is_some_and(u8::is_ascii_digit) {service=line.split_once(") ").map(|(_,s)|s.to_owned());}
                if let Some((_,tail))=line.split_once("Device: "){let dev=tail.trim_end_matches(')');if devices.contains(&dev){if let Some(s)=service.take(){services.push(s)}}}
            }
            let mut entries=vec![];
            for service in services {
                let info=run(recipe("networksetup", &["-getinfo",&service]))?;
                let field=|key:&str|info.lines().find_map(|s|s.strip_prefix(key)).unwrap_or("").to_owned();
                let mode=field("IPv6: ");
                if !matches!(mode.as_str(),"Automatic"|"Off"|"Link-local only"|"Manual"){return Err("repair.settingsUnknown".into())}
                entries.push(entry(&service,vec![mode,field("IPv6 IP address: "),field("IPv6 Prefix Length: "),field("IPv6 Router: ")]));
            } entries
        },
        (Os::Windows,Setting::Ipv6)=>{
            let text=run(ps("$r=@(Get-NetAdapter -Physical | ForEach-Object {$b=Get-NetAdapterBinding -Name $_.Name -ComponentID ms_tcpip6; @{id=$_.InterfaceGuid.ToString(); values=@([string]$b.Enabled)}}); ConvertTo-Json -InputObject @{entries=$r} -Depth 4 -Compress"))?;
            return decode(text.trim())
        },
        (Os::Linux,Setting::Dns)=>{
            let ids=run(recipe("nmcli", &["-t","-f","UUID","connection","show","--active"]))?;
            let mut entries=vec![];
            for id in ids.lines().filter(|s|!s.is_empty()) {
                let mut values=vec![];
                for property in ["ipv4.dns","ipv4.ignore-auto-dns","ipv6.dns","ipv6.ignore-auto-dns","GENERAL.DEVICES"] {values.push(run(recipe("nmcli", &["-g",property,"connection","show",id]))?.trim().into());}
                entries.push(entry(id,values));
            } entries
        },
        (Os::Mac,Setting::Dns)=>{
            let mut entries=vec![];
            for service in mac_services()? {
                let info=run(recipe("networksetup", &["-getinfo",&service]))?;
                if !info.lines().any(|s|s.starts_with("IP address: ") && !s.ends_with("none")){continue}
                let out=run(recipe("networksetup", &["-getdnsservers",&service]))?;
                let values=if out.trim().starts_with("There aren't any DNS Servers set") {vec![]}else{out.lines().map(str::to_owned).collect()};
                if values.iter().any(|s|s.parse::<std::net::IpAddr>().is_err()){return Err("repair.settingsUnknown".into())}
                entries.push(entry(&service,values));
            } entries
        },
        (Os::Windows,Setting::Dns)=>{
            let text=run(ps("$r=@(Get-NetAdapter -ErrorAction Stop | Where-Object Status -eq 'Up' | ForEach-Object {$g=([guid]$_.InterfaceGuid).ToString('B');$a=Get-ItemProperty \"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\$g\"; $b=Get-ItemProperty \"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters\\Interfaces\\$g\" -ErrorAction SilentlyContinue; @{id=([guid]$_.InterfaceGuid).ToString();values=@([string]$a.NameServer,[string]$b.NameServer)}}); ConvertTo-Json -InputObject @{entries=$r} -Depth 4 -Compress"))?;
            return decode(text.trim())
        },
        _=>return Err("repair.settingsUnknown".into()),
    };
    if entries.is_empty(){return Err("repair.settingsUnknown".into())} Ok(State{entries})
}
trait SettingsWriter {
    fn command(&self,command:Recipe)->Result<()>;
    fn current(&self,setting:Setting)->Result<State>;
    fn file(&self,path:&std::path::Path,value:Option<&str>)->Result<()>;
}
struct NativeWriter;
impl SettingsWriter for NativeWriter {
    fn command(&self,command:Recipe)->Result<()>{run(command).map(|_|())}
    fn current(&self,setting:Setting)->Result<State>{read_state(Os::current(),setting)}
    fn file(&self,path:&std::path::Path,value:Option<&str>)->Result<()>{
        let metadata=match std::fs::symlink_metadata(path){Ok(m)=>Some(m),Err(e) if e.kind()==std::io::ErrorKind::NotFound=>None,Err(_)=>return Err("repair.settingsUnknown".into())};
        if metadata.as_ref().is_some_and(|m|m.file_type().is_symlink()||!m.is_file()){return Err("repair.settingsUnknown".into())}
        if let Some(text)=value {
            atomic_write(path,text.as_bytes())?;
            #[cfg(unix)] {use std::os::unix::fs::PermissionsExt;let mode=metadata.as_ref().map(|m|m.permissions().mode()).unwrap_or(0o644);std::fs::set_permissions(path,std::fs::Permissions::from_mode(mode)).map_err(|_|"repair.settingsUnknown")?;}
            Ok(())
        }else{match std::fs::remove_file(path){Ok(())=>Ok(()),Err(e) if e.kind()==std::io::ErrorKind::NotFound=>Ok(()),Err(_)=>Err("repair.settingsUnknown".into())}}
    }
}
pub fn write(setting:Setting,value:&PreviousValue)->Result<()> {write_with(Os::current(),setting,value,&NativeWriter)}
fn write_with(os:Os,setting:Setting,value:&PreviousValue,io:&impl SettingsWriter)->Result<()> {
    let PreviousValue::Text(text)=value else{return Err("repair.settingsUnknown".into())};
    validate_value(setting,text)?;let state=decode(text)?;
    if matches!(setting,Setting::Ipv6|Setting::Dns) {
        let current=io.current(setting)?;
        if state.entries.iter().any(|e|!current.entries.iter().any(|c|c.id==e.id)){return Err("repair.settingsUnknown".into())}
    }
    let commands=write_recipes(os,setting,&state)?;
    let current=if matches!((os,setting),(Os::Mac,Setting::Language)){Some(io.current(setting)?)}else{None};
    for command in commands {
        if command.program=="defaults" && command.args.first().is_some_and(|s|s=="delete") {
            let key=command.args.get(2).ok_or("repair.settingsUnknown")?;
            if !current.as_ref().ok_or("repair.settingsUnknown")?.entries.iter().any(|e|&e.id==key&&!e.values.is_empty()){continue}
        }
        io.command(command)?;
    }
    if matches!((os,setting),(Os::Linux,Setting::Language)) {
        for e in state.entries.iter().filter(|e|e.id!="system") {io.file(std::path::Path::new(&e.id),e.values.first().map(String::as_str))?;}
    }
    if matches!((os,setting),(Os::Linux,Setting::Ipv6)) {
        let e=state.entries.iter().find(|e|e.id=="drop-in").ok_or("repair.settingsUnknown")?;
        if e.values.len()>1{return Err("repair.settingsUnknown".into())}
        io.file(std::path::Path::new(IPV6_FILE),e.values.first().map(String::as_str))?;
    }
    Ok(())
}
fn write_recipes(os:Os,setting:Setting,state:&State)->Result<Vec<Recipe>> {
    let mut commands=vec![];
    for e in &state.entries {
        let refs=e.values.iter().map(String::as_str).collect::<Vec<_>>();
        match (os,setting) {
            (Os::Linux,Setting::Language)=>{
                if state.entries.len()!=3||!state.entries.iter().any(|e|e.id=="system")||!state.entries.iter().any(|e|e.id=="/etc/locale.conf")||!state.entries.iter().any(|e|e.id=="/etc/default/locale"){return Err("repair.settingsUnknown".into())}
                if e.id=="system" {
                    let mut pairs=std::collections::BTreeMap::new();
                    for v in &e.values{let (key,value)=v.split_once('=').ok_or("repair.settingsUnknown")?;if !LOCALE_KEYS.contains(&key)||!safe_locale(value){return Err("repair.settingsUnknown".into())}pairs.insert(key,value);}
                    let args=LOCALE_KEYS.iter().map(|key|format!("{key}={}",pairs.get(key).copied().unwrap_or(""))).collect::<Vec<_>>();
                    let mut refs=vec!["set-locale"];refs.extend(args.iter().map(String::as_str));commands.push(recipe("localectl",&refs));
                }else if e.values.len()>1{return Err("repair.settingsUnknown".into())}
            },
            (Os::Mac,Setting::Language)=>{
                if !matches!(e.id.as_str(),"AppleLanguages"|"AppleLocale") || (e.id=="AppleLocale"&&e.values.len()>1){return Err("repair.settingsUnknown".into())}
                if e.values.is_empty(){
                    // Delete only an existing key: defaults returns nonzero for absent keys.
                    commands.push(recipe("defaults", &["delete","NSGlobalDomain",&e.id]));
                }else{
                    let languages=if e.id=="AppleLanguages"{if e.values.len()!=1{return Err("repair.settingsUnknown".into())}serde_json::from_str::<Vec<String>>(&e.values[0]).map_err(|_|"repair.settingsUnknown")?}else{vec![]};
                    let mut args=vec!["write","NSGlobalDomain",&e.id,if e.id=="AppleLanguages"{"-array"}else{"-string"}];
                    if e.id=="AppleLanguages"{args.extend(languages.iter().map(String::as_str))}else{args.extend(refs)}commands.push(recipe("defaults",&args));
                }
            },
            (Os::Windows,Setting::Language)=>{
                if e.id!="windows" || e.values.len()!=1{return Err("repair.settingsUnknown".into())}
                let v:Value=serde_json::from_str(&e.values[0]).map_err(|_|"repair.settingsUnknown")?;
                let langs=v["languages"].as_array().filter(|a|!a.is_empty()).ok_or("repair.settingsUnknown")?;
                let mut script=String::from("$l=$null; ");
                for (i,l) in langs.iter().enumerate(){
                    let tag=l["tag"].as_str().ok_or("repair.settingsUnknown")?;
                    script+=&format!("$n=New-WinUserLanguageList {}; if($null -eq $l){{$l=$n}}else{{$l.Add($n[0])}}; ",quote(tag));
                    if l.get("defaultTips").and_then(Value::as_bool)!=Some(true){script+=&format!("$l[{i}].InputMethodTips.Clear(); ");}
                    for tip in strings(&l["tips"])?{script+=&format!("$l[{i}].InputMethodTips.Add({}); ",quote(&tip));}
                    for (key,prop) in [("spell","Spellchecking"),("handwriting","Handwriting")]{let b=l[key].as_bool().ok_or("repair.settingsUnknown")?;script+=&format!("$l[{i}].{prop}=${}; ",b);}
                }
                script+=&format!("Set-WinUserLanguageList $l -Force; Set-Culture {}; Set-WinHomeLocation -GeoId {}",quote(v["culture"].as_str().ok_or("repair.settingsUnknown")?),v["geo"].as_u64().ok_or("repair.settingsUnknown")?);
                commands.push(ps(&script));
            },
            (Os::Linux,Setting::Proxy) if e.id=="ignore-hosts"&&e.values.len()==1=>commands.push(recipe("gsettings", &["set","org.gnome.system.proxy","ignore-hosts",&e.values[0]])),
            (Os::Mac,Setting::Proxy)=>{let mut args=vec!["-setproxybypassdomains",&e.id];if refs.is_empty(){args.push("Empty")}else{args.extend(refs)}commands.push(recipe("networksetup",&args));},
            (Os::Windows,Setting::Proxy|Setting::Location|Setting::LocationMachine)=>{
                if e.values.len()>1{return Err("repair.settingsUnknown".into())}
                let (path,name)=if setting==Setting::Proxy {
                    if e.id!="ProxyOverride"{return Err("repair.settingsUnknown".into())}
                    ("HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings".to_owned(),"ProxyOverride")
                }else{
                    if (setting==Setting::Location&&e.id!="HKCU")||(setting==Setting::LocationMachine&&e.id!="HKLM"){return Err("repair.settingsUnknown".into())}
                    (format!("{}:\\Software\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\location",e.id),"Value")
                };
                commands.push(ps(&if let Some(v)=e.values.first(){format!("if(-not (Test-Path {})){{New-Item -Path {} -Force | Out-Null}}; New-ItemProperty -Path {} -Name {name} -PropertyType String -Value {} -Force | Out-Null",quote(&path),quote(&path),quote(&path),quote(v))}else{format!("if(Test-Path {}) {{ $p=Get-ItemProperty {}; if($null -ne $p.{name}) {{Remove-ItemProperty -Path {} -Name {name} }} }}",quote(&path),quote(&path),quote(&path))}));
            },
            (Os::Linux,Setting::Ipv6)=>{
                if e.id=="drop-in" {continue}
                if !safe_iface(&e.id)||e.values.len()!=1||!matches!(e.values[0].as_str(),"0"|"1"){return Err("repair.settingsUnknown".into())}
                commands.push(recipe("sysctl", &["-w",&format!("net/ipv6/conf/{}/disable_ipv6={}",e.id,e.values[0])]));
            },
            (Os::Mac,Setting::Ipv6) if e.values.len()==4=>{
                let args=match e.values[0].as_str(){
                    "Automatic"=>vec!["-setv6automatic",e.id.as_str()],"Off"=>vec!["-setv6off",e.id.as_str()],"Link-local only"=>vec!["-setv6linklocal",e.id.as_str()],
                    "Manual"=>{if e.values[1].parse::<std::net::Ipv6Addr>().is_err()||e.values[2].parse::<u8>().map_or(true,|n|n>128)||e.values[3].parse::<std::net::Ipv6Addr>().is_err(){return Err("repair.settingsUnknown".into())}vec!["-setv6manual",&e.id,&e.values[1],&e.values[2],&e.values[3]]},
                    _=>return Err("repair.settingsUnknown".into()),
                };commands.push(recipe("networksetup",&args));
            },
            (Os::Windows,Setting::Ipv6) if e.values.len()==1=>{
                if !matches!(e.values[0].as_str(),"True"|"False"){return Err("repair.settingsUnknown".into())}
                commands.push(ps(&format!("$a=Get-NetAdapter -Physical | Where-Object {{$_.InterfaceGuid -eq [guid]{}}}; if($null -eq $a){{throw 'Physical adapter unavailable'}}; {}-NetAdapterBinding -Name $a.Name -ComponentID ms_tcpip6",quote(&e.id),if e.values[0]=="True"{"Enable"}else{"Disable"})));
            },
            (Os::Linux,Setting::Dns) if e.values.len()==5=>{
                if !matches!(e.values[1].as_str(),"yes"|"no")||!matches!(e.values[3].as_str(),"yes"|"no"){return Err("repair.settingsUnknown".into())}
                for value in [&e.values[0],&e.values[2]] {if value.split([',',' ']).filter(|s|!s.is_empty()).any(|s|s.parse::<std::net::IpAddr>().is_err()){return Err("repair.settingsUnknown".into())}}
                for (prop,v) in ["ipv4.dns","ipv4.ignore-auto-dns","ipv6.dns","ipv6.ignore-auto-dns"].iter().zip(&e.values){commands.push(recipe("nmcli", &["connection","modify",&e.id,prop,v]));}
                if !safe_iface(&e.values[4]){return Err("repair.settingsUnknown".into())}
                commands.push(recipe("nmcli", &["device","reapply",&e.values[4]]));
            },
            (Os::Mac,Setting::Dns)=>{if e.values.iter().any(|v|v.parse::<std::net::IpAddr>().is_err()){return Err("repair.settingsUnknown".into())}let mut args=vec!["-setdnsservers",&e.id];if refs.is_empty(){args.push("Empty")}else{args.extend(refs)}commands.push(recipe("networksetup",&args));},
            (Os::Windows,Setting::Dns) if e.values.len()==2=>{
                if e.id.len()!=36||!e.id.bytes().all(|c|c.is_ascii_hexdigit()||c==b'-'){return Err("repair.settingsUnknown".into())}
                for (family,v) in [("IPv4",&e.values[0]),("IPv6",&e.values[1])] {
                    let servers=v.split([',',';',' ']).filter(|s|!s.is_empty()).map(|s|s.parse::<std::net::IpAddr>().map(|ip|quote(&ip.to_string())).map_err(|_|"repair.settingsUnknown".to_string())).collect::<Result<Vec<_>>>()?;
                    commands.push(ps(&format!("$a=Get-NetAdapter | Where-Object {{([guid]$_.InterfaceGuid) -eq [guid]{}}}; if($null -eq $a){{throw 'Adapter unavailable'}}; $i=Get-DnsClientServerAddress -InterfaceIndex $a.ifIndex -AddressFamily {family}; $i | Set-DnsClientServerAddress {}",quote(&e.id),if servers.is_empty(){"-ResetServerAddresses".into()}else{format!("-ServerAddresses @({})",servers.join(","))})));
                }
            },
            _=>return Err("repair.settingsUnknown".into()),
        }
    }
    Ok(commands)
}
pub fn setting_for_check(id:&str)->Option<Setting>{match id{"locale"=>Some(Setting::Language),"dns_configured"=>Some(Setting::Dns),"exit_ipv6"=>Some(Setting::Ipv6),"system_proxy"=>Some(Setting::Proxy),"location" if cfg!(windows)=>Some(Setting::Location),_=>None}}
pub fn plan(adapter:&impl SystemAdapter,os:Os,setting:Setting,region:&crate::region::RegionPreset,check_id:&str,dns_proof:Option<&DnsProof>)->Result<Option<FixPlan>> {
    if setting==Setting::Dns{let proof=dns_proof.ok_or("repair.dnsGate")?;let age=chrono::Utc::now().signed_duration_since(proof.observed_at);if proof.region!=region.id||age<chrono::Duration::zero()||age>chrono::Duration::seconds(120){return Err("repair.dnsGate".into())}}
    let resource=ResourceId::Setting(setting);let before=adapter.read(&resource)?;
    let PreviousValue::Text(text)=&before else{return Err("repair.settingsUnknown".into())};
    validate_value(setting,text)?;
    let mut state=decode(text)?;
    if state.entries.is_empty(){return Err("repair.settingsUnknown".into())}
    // Validate that the captured state can be restored before offering a mutation.
    write_recipes(os,setting,&state)?;
    match setting {
        Setting::Language=>{
            let tag=region.languages.first().ok_or("repair.settingsUnknown")?;
            state=match os {
                Os::Linux=>{
                    let locale=format!("LANG={}.UTF-8",tag.replace('-',"_"));
                    let any_file=state.entries.iter().any(|e|e.id!="system"&&!e.values.is_empty());
                    for e in &mut state.entries {
                        if e.id=="system"{e.values=vec![locale.clone()];continue}
                        if e.values.is_empty()&&(any_file||e.id!="/etc/locale.conf"){continue}
                        let mut content=e.values.first().map(String::as_str).unwrap_or("").lines().filter(|line|{let key=line.trim().split('=').next().unwrap_or("");!LOCALE_KEYS.contains(&key)}).map(|s|format!("{s}\n")).collect::<String>();
                        content+=&format!("{locale}\n");e.values=vec![content];
                    }state
                },
                Os::Mac=>State{entries:vec![entry("AppleLanguages",vec![json!([tag]).to_string()]),entry("AppleLocale",vec![tag.replace('-',"_")])]},
                Os::Windows=>{
                    let mut v:Value=serde_json::from_str(state.entries.first().and_then(|e|e.values.first()).ok_or("repair.settingsUnknown")?).map_err(|_|"repair.settingsUnknown")?;
                    let geo=match region.country.as_str(){"US"=>244,"CA"=>39,"GB"=>242,"JP"=>122,"KR"=>134,"SG"=>215,"TW"=>237,"DE"=>94,"FR"=>84,"AU"=>12,"IE"=>68,"NL"=>176,_=>return Err("repair.settingsUnknown".into())};
                    v["languages"]=json!([{"tag":tag,"tips":[],"defaultTips":true,"spell":true,"handwriting":false}]);v["culture"]=json!(tag);v["geo"]=json!(geo);
                    State{entries:vec![entry("windows",vec![v.to_string()])]}
                },
            };
        },
        Setting::Dns=>{
            if region.recommended_dns.iter().any(|s|s.parse::<std::net::IpAddr>().is_err()){return Err("repair.settingsUnknown".into())}
            for e in &mut state.entries{e.values=match os {Os::Linux=>vec![region.recommended_dns.join(","),"yes".into(),String::new(),"yes".into(),e.values.get(4).ok_or("repair.settingsUnknown")?.clone()],Os::Mac=>region.recommended_dns.clone(),Os::Windows=>vec![region.recommended_dns.join(","),String::new()]};}
        },
        Setting::Proxy=>for e in &mut state.entries {
            match os {
                Os::Mac=>e.values.retain(|s|!target_domain(s)),
                Os::Windows=>if let Some(v)=e.values.first_mut(){*v=v.split(';').filter(|s|!target_domain(s)).collect::<Vec<_>>().join(";")},
                Os::Linux=>{
                    let old=e.values.first().ok_or("repair.settingsUnknown")?;
                    // GVariant string arrays: parse only the unambiguous common quoted form.
                    let values=parse_gvariant(old)?;
                    e.values=vec![format!("[{}]",values.into_iter().filter(|s|!target_domain(s)).map(|s|format!("'{}'",s.replace('\\',"\\\\").replace('\'',"\\'"))).collect::<Vec<_>>().join(", "))];
                },
            }
        },
        Setting::Location|Setting::LocationMachine=>{if !matches!(os,Os::Windows){return Err("repair.settingsUnknown".into())}for e in &mut state.entries{e.values=vec!["Deny".into()]}}
        Setting::Ipv6=>{
            let mut lines=String::new();
            for e in &mut state.entries {
                match os {
                    Os::Linux if e.id!="drop-in"=>{if !safe_iface(&e.id){return Err("repair.settingsUnknown".into())}e.values=vec!["1".into()];lines+=&format!("net/ipv6/conf/{}/disable_ipv6 = 1\n",e.id)},
                    Os::Linux=>{},
                    Os::Mac=>{if e.values.len()!=4{return Err("repair.settingsUnknown".into())}e.values[0]="Off".into();},
                    Os::Windows=>e.values=vec!["False".into()],
                }
            }
            if matches!(os,Os::Linux){let drop=state.entries.iter_mut().find(|e|e.id=="drop-in").ok_or("repair.settingsUnknown")?;drop.values=vec![lines];}
        },
    }
    let admin=matches!(setting,Setting::Dns|Setting::Ipv6)||matches!((os,setting),(Os::Linux,Setting::Language)|(Os::Mac,Setting::Proxy))||setting==Setting::LocationMachine;
    let after=encode(state)?;validate_value(setting,&after)?;
    if text==&after{return Ok(None)}
    let mut random=[0;16];getrandom::fill(&mut random).map_err(|_|"repair.settingsUnknown")?;
    Ok(Some(FixPlan{id:format!("{}-{}",if setting==Setting::Dns{format!("dns-{}",region.id)}else{"settings".into()},random.iter().map(|b|format!("{b:02x}")).collect::<String>()),check_id:check_id.into(),steps:vec![FixStep::SetSetting{setting,value:after.clone()}],requires_admin:admin,resources:vec![resource.clone()],preview:vec![ChangePreview{resource,before:display_value(&before),after}]}))
}
fn target_domain(s:&str)->bool {
    let s=s.trim().to_ascii_lowercase();
    let s=s.split_once("://").map_or(s.as_str(),|(_,host)|host).split('/').next().unwrap_or("").split(':').next().unwrap_or("").trim_start_matches('*').trim_start_matches('.').trim_end_matches('.');
    ["claude.ai","anthropic.com"].iter().any(|d|s==*d||s.ends_with(&format!(".{d}")))
}
fn parse_gvariant(text:&str)->Result<Vec<String>> {
    let text=text.trim().strip_prefix("@as ").unwrap_or(text.trim());
    let body=text.strip_prefix('[').and_then(|s|s.strip_suffix(']')).ok_or("repair.settingsUnknown")?;
    let mut out=vec![];let mut chars=body.chars().peekable();
    while let Some(c)=chars.next(){
        if c.is_whitespace()||c==','{continue}
        if c!='\''&&c!='"'{return Err("repair.settingsUnknown".into())}
        let mut value=String::new();let mut closed=false;
        while let Some(ch)=chars.next(){if ch==c{closed=true;break}if ch=='\\'{value.push(chars.next().ok_or("repair.settingsUnknown")?)}else{value.push(ch)}}
        if !closed{return Err("repair.settingsUnknown".into())}out.push(value);
    } Ok(out)
}
pub struct DnsProof{region:String,observed_at:chrono::DateTime<chrono::Utc>}
pub fn dns_gate(report:&crate::model::ScanReport,region:&crate::region::RegionPreset,now:chrono::DateTime<chrono::Utc>)->Result<DnsProof> {
    let time=chrono::DateTime::parse_from_rfc3339(&report.generated_at).map_err(|_|"repair.dnsGate")?;
    let age=now.signed_duration_since(time);
    if age<chrono::Duration::zero()||age>chrono::Duration::seconds(120)||report.region_id!=region.id||matches!(region.country.as_str(),"CN"|"HK"|"MO")||!report.checks.iter().any(|c|c.id=="exit_ipv4"&&c.status==crate::model::Status::Pass&&c.observed.get("country")==Some(&region.country)) {return Err("repair.dnsGate".into())}Ok(DnsProof{region:region.id.clone(),observed_at:time.with_timezone(&chrono::Utc)})
}

const IPV6_FILE:&str="/etc/sysctl.d/90-aienv-ipv6.conf";
fn safe_iface(id:&str)->bool{!id.is_empty()&&id.len()<=64&&id.bytes().all(|c|c.is_ascii_alphanumeric()||b"_-".contains(&c))}

#[cfg(test)] mod tests {
    use super::*;
    use std::{sync::Mutex,collections::BTreeMap};
    struct Fake(Mutex<BTreeMap<ResourceId,PreviousValue>>,Os,std::path::PathBuf,Mutex<Vec<Recipe>>);
    impl SettingsWriter for Fake {
        fn command(&self,c:Recipe)->Result<()>{self.3.lock().unwrap().push(c);Ok(())}
        fn current(&self,s:Setting)->Result<State>{let PreviousValue::Text(text)=self.read(&ResourceId::Setting(s))? else{return Err("missing".into())};decode(&text)}
        fn file(&self,path:&std::path::Path,value:Option<&str>)->Result<()>{let local=self.2.join(path.file_name().unwrap());NativeWriter.file(&local,value)}
    }
    impl SystemAdapter for Fake {
        fn read(&self,r:&ResourceId)->Result<PreviousValue>{self.0.lock().unwrap().get(r).cloned().ok_or("unobserved".into())}
        fn write(&self,r:&ResourceId,v:&PreviousValue)->Result<()>{let ResourceId::Setting(setting)=r else{return Err("unexpected resource".into())};write_with(self.1,*setting,v,self)?;self.0.lock().unwrap().insert(r.clone(),v.clone());Ok(())}
    }
    fn initial(os:Os,setting:Setting)->State {
        let entries=match (os,setting) {
            (Os::Linux,Setting::Language)=>vec![entry("system",vec!["LANG=fr_FR.UTF-8".into()]),entry("/etc/locale.conf",vec!["# original\nLANG=fr_FR.UTF-8\n".into()]),entry("/etc/default/locale",vec![])],
            (Os::Mac,Setting::Language)=>vec![entry("AppleLanguages",vec![json!(["fr-FR","de-DE"]).to_string()]),entry("AppleLocale",vec!["fr_FR".into()])],
            (Os::Windows,Setting::Language)=>vec![entry("windows",vec![json!({"languages":[{"tag":"fr-FR","tips":["040c:0000040c"],"spell":false,"handwriting":true}],"culture":"fr-FR","geo":84}).to_string()])],
            (Os::Linux,Setting::Dns)=>vec![entry("11111111-1111-1111-1111-111111111111",vec!["".into(),"no".into(),"2001:4860:4860::8888".into(),"no".into(),"eth0".into()]),entry("22222222-2222-2222-2222-222222222222",vec!["9.9.9.9".into(),"yes".into(),"".into(),"no".into(),"wlan0".into()])],
            (Os::Mac,Setting::Dns)=>vec![entry("Wi-Fi",vec![]),entry("USB Ethernet",vec!["9.9.9.9".into()])],
            (Os::Windows,Setting::Dns)=>vec![entry("12345678-1234-1234-1234-123456789abc",vec!["".into(),"".into()]),entry("87654321-1234-1234-1234-123456789abc",vec!["9.9.9.9".into(),"2001:4860:4860::8888".into()])],
            (Os::Linux,Setting::Ipv6)=>vec![entry("eth0",vec!["0".into()]),entry("wlan0",vec!["1".into()]),entry("drop-in",vec![])],
            (Os::Mac,Setting::Ipv6)=>vec![entry("Wi-Fi",vec!["Automatic".into(),"none".into(),"64".into(),"none".into()]),entry("Ethernet",vec!["Manual".into(),"2001:db8::2".into(),"64".into(),"2001:db8::1".into()])],
            (Os::Windows,Setting::Ipv6)=>vec![entry("12345678-1234-1234-1234-123456789abc",vec!["True".into()]),entry("87654321-1234-1234-1234-123456789abc",vec!["False".into()])],
            (Os::Linux,Setting::Proxy)=>vec![entry("ignore-hosts",vec!["['localhost', '*.claude.ai', 'api.anthropic.com', 'corp.example']".into()])],
            (Os::Mac,Setting::Proxy)=>vec![entry("Wi-Fi",vec!["localhost".into(),"*.claude.ai".into(),"api.anthropic.com".into()]),entry("Ethernet",vec![])],
            (Os::Windows,Setting::Proxy)=>vec![entry("ProxyOverride",vec!["<local>;*.claude.ai;api.anthropic.com;corp.example".into()])],
            (Os::Windows,Setting::Location)=>vec![entry("HKCU",vec![])],
            (Os::Windows,Setting::LocationMachine)=>vec![entry("HKLM",vec!["Allow".into()])],
            _=>unreachable!(),
        };State{entries}
    }
    fn roundtrip(os:Os,setting:Setting) {
        let resource=ResourceId::Setting(setting);let original=PreviousValue::Text(encode(initial(os,setting)).unwrap());
        let mut random=[0;16];getrandom::fill(&mut random).unwrap();let dir=std::env::temp_dir().join(format!("aienv-settings-{:x}",u128::from_ne_bytes(random)));
        let adapter=Fake(Mutex::new(BTreeMap::from([(resource.clone(),original.clone())])),os,dir.join("files"),Mutex::new(vec![]));
        let engine=Engine{dir:dir.clone(),adapter,locks:Default::default(),allowed:[resource.clone()].into_iter().collect()};
        let proof=DnsProof{region:"us".into(),observed_at:chrono::Utc::now()};
        let p=plan(&engine.adapter,os,setting,crate::region::find("us").unwrap(),"test",Some(&proof)).unwrap().unwrap();
        assert_eq!(p.preview[0].before,display_value(&original));
        assert_eq!(p.requires_admin,matches!(setting,Setting::Dns|Setting::Ipv6|Setting::LocationMachine)||matches!((os,setting),(Os::Linux,Setting::Language)|(Os::Mac,Setting::Proxy)));
        let FixStep::SetSetting{value,..}=&p.steps[0] else{panic!()};
        let state=decode(value).unwrap();
        {
            let commands=write_recipes(os,setting,&state).unwrap();assert!(!commands.is_empty());
            let restore=write_recipes(os,setting,&initial(os,setting)).unwrap();assert!(!restore.is_empty());
            match (os,setting){
                (Os::Linux,Setting::Dns)=>{assert_eq!(commands[0].args[0],"connection");assert_eq!(commands[4],recipe("nmcli", &["device","reapply","eth0"]));assert_eq!(restore[0].args.last().unwrap(),"");assert_eq!(restore[1].args.last().unwrap(),"no")},
                (Os::Mac,Setting::Dns)=>{assert_eq!(restore[0],recipe("networksetup", &["-setdnsservers","Wi-Fi","Empty"]));},
                (Os::Windows,Setting::Dns)=>{assert!(restore[0].args.last().unwrap().contains("-ResetServerAddresses"));assert!(restore[2].args.last().unwrap().contains("9.9.9.9"));},
                (Os::Linux,Setting::Ipv6)=>{assert_eq!(commands.len(),2);assert_eq!(commands[0],recipe("sysctl", &["-w","net/ipv6/conf/eth0/disable_ipv6=1"]));assert!(state.entries.last().unwrap().values[0].contains("wlan0"));},
                (Os::Mac,Setting::Ipv6)=>{assert_eq!(commands[0].args[0],"-setv6off");assert_eq!(restore[1].args[0],"-setv6manual");},
                (Os::Windows,Setting::Ipv6)=>{assert!(commands[0].args.last().unwrap().contains("Disable-NetAdapterBinding"));assert!(restore[0].args.last().unwrap().contains("Enable-NetAdapterBinding"));assert!(commands[0].args.last().unwrap().contains("-Physical"));},
                (Os::Linux,Setting::Language)=>{assert_eq!(commands[0].program,"localectl");assert!(commands[0].args.contains(&"LANG=en_US.UTF-8".to_string()));assert!(restore[0].args.contains(&"LANG=fr_FR.UTF-8".to_string()));},
                (Os::Mac,Setting::Language)=>{assert_eq!(commands[0],recipe("defaults", &["write","NSGlobalDomain","AppleLanguages","-array","en-US"]));},
                (Os::Windows,Setting::Language)=>{let script=restore[0].args.last().unwrap();assert!(script.contains("Set-WinUserLanguageList"));assert!(script.contains("Set-Culture 'fr-FR'"));assert!(script.contains("Set-WinHomeLocation -GeoId 84"));assert!(script.contains("040c:0000040c"));},
                (Os::Windows,Setting::Location)=>{assert!(commands[0].args.last().unwrap().contains("Deny"));assert!(restore[0].args.last().unwrap().contains("Remove-ItemProperty"));},
                (Os::Windows,Setting::LocationMachine)=>{assert!(commands[0].args.last().unwrap().contains("HKLM:"));assert!(restore[0].args.last().unwrap().contains("Allow"));},
                (_,Setting::Proxy)=>{assert!(!value.contains("claude.ai"));assert!(!value.contains("anthropic.com"));assert!(value.contains("localhost")||value.contains("<local>"));},
                _=>{},
            }
        }
        let report=engine.apply(&p).unwrap();assert!(report.success);
        if matches!((os,setting),(Os::Linux,Setting::Language)){assert!(std::fs::read_to_string(engine.adapter.2.join("locale.conf")).unwrap().contains("LANG=en_US.UTF-8"));}
        if matches!((os,setting),(Os::Linux,Setting::Ipv6)){assert!(std::fs::read_to_string(engine.adapter.2.join("90-aienv-ipv6.conf")).unwrap().contains("eth0/disable_ipv6 = 1"));}
        let b=engine.load(&report.backup_id).unwrap();assert_eq!(b.entries[0].previous_value,original);
        assert!(engine.restore(&report.backup_id).unwrap().success);assert_eq!(engine.adapter.read(&resource).unwrap(),original);
        if matches!((os,setting),(Os::Linux,Setting::Language)){assert_eq!(std::fs::read_to_string(engine.adapter.2.join("locale.conf")).unwrap(),"# original\nLANG=fr_FR.UTF-8\n");}
        if matches!((os,setting),(Os::Linux,Setting::Ipv6)){assert!(!engine.adapter.2.join("90-aienv-ipv6.conf").exists());}
        // Restore-all must support the same typed settings and disk backup format.
        assert!(engine.restore_all().unwrap().iter().all(|r|r.success));
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]fn language_linux(){roundtrip(Os::Linux,Setting::Language)}
    #[test]fn language_mac(){roundtrip(Os::Mac,Setting::Language)}
    #[test]fn language_windows(){roundtrip(Os::Windows,Setting::Language)}
    #[test]fn dns_linux(){roundtrip(Os::Linux,Setting::Dns)}
    #[test]fn dns_mac(){roundtrip(Os::Mac,Setting::Dns)}
    #[test]fn dns_windows(){roundtrip(Os::Windows,Setting::Dns)}
    #[test]fn ipv6_linux(){roundtrip(Os::Linux,Setting::Ipv6)}
    #[test]fn ipv6_mac(){roundtrip(Os::Mac,Setting::Ipv6)}
    #[test]fn ipv6_windows(){roundtrip(Os::Windows,Setting::Ipv6)}
    #[test]fn proxy_linux(){roundtrip(Os::Linux,Setting::Proxy)}
    #[test]fn proxy_mac(){roundtrip(Os::Mac,Setting::Proxy)}
    #[test]fn proxy_windows(){roundtrip(Os::Windows,Setting::Proxy)}
    #[test]fn location_windows(){roundtrip(Os::Windows,Setting::Location)}
    #[test]fn location_windows_machine(){roundtrip(Os::Windows,Setting::LocationMachine)}
    #[test]fn unknown_and_malformed_refused(){
        let fake=Fake(Mutex::new(BTreeMap::new()),Os::Linux,std::env::temp_dir(),Mutex::new(vec![]));for os in [Os::Linux,Os::Mac,Os::Windows]{for setting in Setting::ALL{assert!(plan(&fake,os,setting,crate::region::find("us").unwrap(),"test",None).is_err())}}
        assert!(validate_value(Setting::Ipv6,&encode(State{entries:vec![entry("drop-in",vec!["kernel.panic = 1".into()])]}).unwrap()).is_err());
        assert!(!target_domain("notclaude.ai"));assert!(!target_domain("claude.ai.evil.example"));assert!(target_domain("*.Claude.ai"));
        assert_eq!(parse_gvariant("@as []").unwrap(),Vec::<String>::new());assert!(parse_gvariant("['unterminated]").is_err());
    }
    #[test]fn absent_and_empty_mac_language_keys_are_distinct(){
        let absent=State{entries:vec![entry("AppleLanguages",vec![]),entry("AppleLocale",vec![])]};
        let empty=State{entries:vec![entry("AppleLanguages",vec!["[]".into()]),entry("AppleLocale",vec![])]};
        assert_eq!(write_recipes(Os::Mac,Setting::Language,&absent).unwrap()[0],recipe("defaults", &["delete","NSGlobalDomain","AppleLanguages"]));
        assert_eq!(write_recipes(Os::Mac,Setting::Language,&empty).unwrap()[0],recipe("defaults", &["write","NSGlobalDomain","AppleLanguages","-array"]));
    }
    #[test]fn restore_refuses_a_disappeared_physical_interface(){
        let state=State{entries:vec![entry("eth0",vec!["0".into()]),entry("drop-in",vec![])]};
        let fake=Fake(Mutex::new(BTreeMap::from([(ResourceId::Setting(Setting::Ipv6),PreviousValue::Text(encode(state).unwrap()))])),Os::Linux,std::env::temp_dir(),Mutex::new(vec![]));
        let malicious=State{entries:vec![entry("tun0",vec!["1".into()]),entry("drop-in",vec![])]};
        assert!(write_with(Os::Linux,Setting::Ipv6,&PreviousValue::Text(encode(malicious).unwrap()),&fake).is_err());assert!(fake.3.lock().unwrap().is_empty());
    }
    #[test]fn dns_freshness_country_and_inconclusive_gates(){
        use crate::model::*;
        let region=crate::region::find("us").unwrap();let now=chrono::Utc::now();
        let mut report=ScanReport{generated_at:now.to_rfc3339(),os:"linux".into(),region_id:"us".into(),region_name:Default::default(),verdict:Verdict::Consistent,browser_url:String::new(),browser_opened:false,phase:2,checks:vec![CheckResult{id:"exit_ipv4".into(),category:"exit".into(),status:Status::Pass,observed:BTreeMap::from([("country".into(),"US".into())]),expected:Default::default(),summary_key:String::new(),summary_params:Default::default(),advice_key:String::new(),advice_params:Default::default(),summary_en:String::new(),advice_en:String::new()}]};
        assert!(dns_gate(&report,region,now).is_ok());
        report.generated_at=(now-chrono::Duration::seconds(121)).to_rfc3339();assert!(dns_gate(&report,region,now).is_err());
        report.generated_at=(now+chrono::Duration::seconds(1)).to_rfc3339();assert!(dns_gate(&report,region,now).is_err());report.generated_at=now.to_rfc3339();
        report.checks[0].status=Status::Inconclusive;assert!(dns_gate(&report,region,now).is_err());report.checks[0].status=Status::Pass;
        report.checks[0].observed.insert("country".into(),"CN".into());assert!(dns_gate(&report,region,now).is_err());report.checks[0].observed.insert("country".into(),"US".into());
        report.region_id="jp".into();assert!(dns_gate(&report,region,now).is_err());
    }
}

const LOCALE_KEYS:&[&str]=&["LANG","LANGUAGE","LC_CTYPE","LC_NUMERIC","LC_TIME","LC_COLLATE","LC_MONETARY","LC_MESSAGES","LC_PAPER","LC_NAME","LC_ADDRESS","LC_TELEPHONE","LC_MEASUREMENT","LC_IDENTIFICATION"];

pub fn elevated()->Result<bool>{Ok(run(ps("([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)"))?.trim()=="True")}

fn safe_locale(value:&str)->bool{value.bytes().all(|c|c.is_ascii_alphanumeric()||b"_-.@ :".contains(&c))}
