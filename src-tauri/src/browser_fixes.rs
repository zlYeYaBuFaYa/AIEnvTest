//! Enterprise policy resources. All mutation is behind the transaction adapter.
use crate::{system_fixes::{Os,recipe,run}, transaction::*};
use serde::{Deserialize,Serialize};
use serde_json::{Value,json};
use std::path::PathBuf;
type Result<T> = std::result::Result<T,String>;
#[derive(Debug,Clone,Copy,Serialize,Deserialize,PartialEq,Eq,PartialOrd,Ord)]
pub enum Target { Chrome, Edge, Chromium, Brave, Firefox, FirefoxUsr, FirefoxOpt, FirefoxEsr, FirefoxLib64, FirefoxX86 }
impl Target {
    pub const ALL:[Self;10]=[Self::Chrome,Self::Edge,Self::Chromium,Self::Brave,Self::Firefox,Self::FirefoxUsr,Self::FirefoxOpt,Self::FirefoxEsr,Self::FirefoxLib64,Self::FirefoxX86];
    pub fn name(self)-> &'static str {match self {Self::Chrome=>"Chrome",Self::Edge=>"Edge",Self::Chromium=>"Chromium",Self::Brave=>"Brave",_=>"Firefox"}}
    fn firefox(self)->bool {matches!(self,Self::Firefox|Self::FirefoxUsr|Self::FirefoxOpt|Self::FirefoxEsr|Self::FirefoxLib64|Self::FirefoxX86)}
}
pub fn path(os:Os,t:Target)->Option<PathBuf> {
    use Target::*;
    Some(match os {
        Os::Linux=>match t {Chrome=>"/etc/opt/chrome/policies/managed/aienv.json",Edge=>"/etc/opt/edge/policies/managed/aienv.json",Chromium=>"/etc/chromium/policies/managed/aienv.json",Brave=>"/etc/brave/policies/managed/aienv.json",Firefox=>"/etc/firefox/policies/policies.json",FirefoxUsr=>"/usr/lib/firefox/distribution/policies.json",FirefoxOpt=>"/opt/firefox/distribution/policies.json",FirefoxEsr=>"/usr/lib/firefox-esr/distribution/policies.json",FirefoxLib64=>"/usr/lib64/firefox/distribution/policies.json",FirefoxX86=>return None}.into(),
        Os::Mac=>match t {Chrome=>"/Library/Managed Preferences/com.google.Chrome.plist",Edge=>"/Library/Managed Preferences/com.microsoft.Edge.plist",Chromium=>"/Library/Managed Preferences/org.chromium.Chromium.plist",Brave=>"/Library/Managed Preferences/com.brave.Browser.plist",Firefox=>"/Applications/Firefox.app/Contents/Resources/distribution/policies.json",_=>return None}.into(),
        Os::Windows=>{let (env,fallback)=match t {Firefox=>("ProgramFiles",r"C:\Program Files"),FirefoxX86=>("ProgramFiles(x86)",r"C:\Program Files (x86)"),_=>return None};PathBuf::from(std::env::var_os(env).unwrap_or_else(||fallback.into())).join("Mozilla Firefox/distribution/policies.json")},
    })
}
pub fn registry(t:Target)->Option<&'static str> {Some(match t {Target::Chrome=>r"SOFTWARE\Policies\Google\Chrome",Target::Edge=>r"SOFTWARE\Policies\Microsoft\Edge",Target::Chromium=>r"SOFTWARE\Policies\Chromium",Target::Brave=>r"SOFTWARE\Policies\BraveSoftware\Brave",_=>return None})}
/// Detection is read-only and injectable for tests. Unknown install layouts are not guessed.
pub fn installed(os:Os,t:Target,exists:impl Fn(&str)->bool)->bool {
    use Target::*;
    let candidates:Vec<String>=match os {
        Os::Linux=>match t {Chrome=>vec!["/usr/bin/google-chrome","/opt/google/chrome/chrome"],Edge=>vec!["/usr/bin/microsoft-edge","/opt/microsoft/msedge/msedge"],Chromium=>vec!["/usr/bin/chromium","/usr/bin/chromium-browser"],Brave=>vec!["/usr/bin/brave-browser","/opt/brave.com/brave/brave"],Firefox=>vec!["/usr/bin/firefox","/usr/bin/firefox-esr","/usr/lib/firefox/firefox","/opt/firefox/firefox","/usr/lib/firefox-esr/firefox-esr","/usr/lib64/firefox/firefox"],FirefoxUsr=>vec!["/usr/lib/firefox/firefox"],FirefoxOpt=>vec!["/opt/firefox/firefox"],FirefoxEsr=>vec!["/usr/lib/firefox-esr/firefox-esr","/usr/lib/firefox-esr/firefox"],FirefoxLib64=>vec!["/usr/lib64/firefox/firefox"],FirefoxX86=>vec![]}.into_iter().map(str::to_owned).collect(),
        Os::Mac=>vec![format!("/Applications/{}.app/Contents/MacOS/{}",match t{Chrome=>"Google Chrome",Edge=>"Microsoft Edge",Chromium=>"Chromium",Brave=>"Brave Browser",_=>"Firefox"},match t{Chrome=>"Google Chrome",Edge=>"Microsoft Edge",Chromium=>"Chromium",Brave=>"Brave Browser",_=>"firefox"})].into_iter().filter(|_|matches!(t,Chrome|Edge|Chromium|Brave|Firefox)).collect(),
        Os::Windows=>if t==Firefox || t==FirefoxX86 {std::env::var(if t==Firefox{"ProgramFiles"}else{"ProgramFiles(x86)"}).ok().map(|root|vec![format!("{root}/Mozilla Firefox/firefox.exe")]).unwrap_or_default()} else {["ProgramFiles","ProgramFiles(x86)","LOCALAPPDATA"].iter().filter_map(|env|std::env::var(env).ok()).filter(|_|matches!(t,Chrome|Edge|Chromium|Brave)).map(|root|format!("{root}/{}",match t{Chrome=>"Google/Chrome/Application/chrome.exe",Edge=>"Microsoft/Edge/Application/msedge.exe",Chromium=>"Chromium/Application/chrome.exe",Brave=>"BraveSoftware/Brave-Browser/Application/brave.exe",_=>unreachable!()})).collect()},
    };
    candidates.iter().any(|p|exists(p))
}
pub fn detected(os:Os)->Vec<Target> {Target::ALL.into_iter().filter(|t|installed(os,*t,|p|std::path::Path::new(p).is_file())).collect()}
pub fn merge(dst:&mut Value,patch:&Value)->Result<()> {
    let map=dst.as_object_mut().ok_or("Browser policy must be an object")?;
    for (k,v) in patch.as_object().ok_or("Invalid policy patch")? {if v.is_object(){let entry=map.entry(k).or_insert(json!({}));if !entry.is_object(){*entry=json!({})}merge(entry,v)?}else{map.insert(k.clone(),v.clone());}}
    Ok(())
}
pub fn patch(os:Os,t:Target,languages:&[String])->Value {
    if t.firefox() {let mut prefs=json!({});for (key,value) in [("media.peerconnection.ice.default_address_only",json!(true)),("media.peerconnection.ice.no_host",json!(true)),("media.peerconnection.ice.proxy_only_if_behind_proxy",json!(true)),("network.http.http3.enable",json!(false)),("intl.accept_languages",json!(languages.join(","))),("geo.enabled",json!(false))]{prefs[key]=json!({"Value":value,"Status":"locked"});}json!({"policies":{"Preferences":prefs,"RequestedLocales":languages,"Permissions":{"Location":{"BlockNewRequests":true}}}})}
    else {let mut p=json!({"WebRtcIPHandlingPolicy":"disable_non_proxied_udp","QuicAllowed":false,"ForcedLanguages":languages,"DefaultGeolocationSetting":2});
        // Keep the requested key and also set the actual vendor enterprise policy.
        p[if t==Target::Edge{"WebRtcLocalhostIpHandling"}else{"WebRtcIPHandling"}]=json!("disable_non_proxied_udp");
        if matches!(os,Os::Windows){p["ApplicationLocaleValue"]=json!(languages.first().cloned().unwrap_or_else(||"en-US".into()));}p}
}
// Raw file bytes are serialized, so even binary plists restore byte-for-byte.
pub fn read(t:Target)->Result<PreviousValue> {
    let os=Os::current();
    if matches!(os,Os::Windows)&&registry(t).is_some(){return read_registry(t)}
    let p=path(os,t).ok_or("Unsupported browser policy location")?;
    match std::fs::read(p){Ok(bytes)=>Ok(PreviousValue::Text(serde_json::to_string(&bytes).map_err(|e|e.to_string())?)),Err(e) if e.kind()==std::io::ErrorKind::NotFound=>Ok(PreviousValue::Absent),Err(e)=>Err(e.to_string())}
}
fn bytes(v:&PreviousValue)->Result<Vec<u8>> {match v{PreviousValue::Absent=>Ok(vec![]),PreviousValue::Text(s)=>serde_json::from_str(s).map_err(|_|"Invalid browser file snapshot".into())}}
pub fn write(t:Target,v:&PreviousValue)->Result<()> {
    let os=Os::current();if matches!(os,Os::Windows)&&registry(t).is_some(){return write_registry(t,v)}
    let p=path(os,t).ok_or("Unsupported browser policy location")?;
    write_policy_file(&p,v)
}
fn write_policy_file(p:&std::path::Path,v:&PreviousValue)->Result<()> {
    // Refuse links in any existing component before elevated file access.
    for component in p.ancestors(){if std::fs::symlink_metadata(component).is_ok_and(|m|m.file_type().is_symlink()){return Err("Linked browser policy paths are refused".into())}}
    match v {PreviousValue::Absent=>match std::fs::remove_file(p){Ok(())=>Ok(()),Err(e) if e.kind()==std::io::ErrorKind::NotFound=>Ok(()),Err(e)=>Err(e.to_string())},_=>{
        let b=bytes(v)?;
        #[cfg(unix)] let mode={use std::os::unix::fs::PermissionsExt;std::fs::metadata(p).map(|m|m.permissions().mode()).unwrap_or(0o644)};
        atomic_write(p,&b)?;
        #[cfg(unix)] {use std::os::unix::fs::PermissionsExt;std::fs::set_permissions(p,std::fs::Permissions::from_mode(mode)).map_err(|e|e.to_string())?;}
        Ok(())
    }}
}

fn ps(script:&str)->Result<String>{run(recipe("powershell", &["-NoProfile","-NonInteractive","-Command",&format!("$ErrorActionPreference='Stop'; [Console]::OutputEncoding=[Text.UTF8Encoding]::new(); {script}")]))}
fn quote(s:&str)->String{format!("'{}'",s.replace('\'',"''"))}
fn read_registry(t:Target)->Result<PreviousValue>{
    let key=registry(t).ok_or("Invalid registry target")?;
    let output=ps(&format!(r#"$root='HKLM:\{key}'; if(!(Test-Path -LiteralPath $root)){{'null';exit}}; $keys=@((Get-Item -LiteralPath $root)) + @(Get-ChildItem -LiteralPath $root -Recurse); $entries=@(foreach($k in $keys){{@{{path='{key}'+$k.Name.Substring({root_len});values=@(foreach($n in $k.GetValueNames()){{@{{name=$n;kind=[string]$k.GetValueKind($n);data=$k.GetValue($n,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)}}}})}}}}); ConvertTo-Json -InputObject $entries -Depth 20 -Compress"#,root_len=19+key.len()))?;
    if output.trim()=="null"{Ok(PreviousValue::Absent)}else{Ok(PreviousValue::Text(canonical_registry(output.trim())?))}
}
// PowerShell hashtable/property enumeration order is not stable across processes.
fn canonical_registry(text:&str)->Result<String> {
    let mut entries:Vec<Value>=serde_json::from_str(text).map_err(|_|"Invalid registry snapshot")?;
    for e in &mut entries {e["values"].as_array_mut().ok_or("Invalid registry values")?.sort_by_key(|v|v["name"].as_str().unwrap_or_default().to_ascii_lowercase());}
    entries.sort_by_key(|e|e["path"].as_str().unwrap_or_default().to_ascii_lowercase());
    serde_json::to_string(&entries).map_err(|e|e.to_string())
}
fn registry_entries(v:&PreviousValue)->Result<Vec<Value>> {match v{PreviousValue::Absent=>Ok(vec![]),PreviousValue::Text(s)=>serde_json::from_str(s).map_err(|_|"Invalid registry snapshot".into())}}
fn registry_script(t:Target,v:&PreviousValue,current:&PreviousValue)->Result<String> {
    let key=registry(t).ok_or("Invalid registry target")?;
    let entries=registry_entries(v)?;let old=registry_entries(current)?;
    for e in entries.iter().chain(&old) {let p=e["path"].as_str().ok_or("Invalid registry path")?;if !p.eq_ignore_ascii_case(key) && !p.to_ascii_lowercase().starts_with(&format!("{}\\",key.to_ascii_lowercase())){return Err("Registry scope rejected".into())}}
    let mut script=String::new();
    // Only remove resources absent from the desired snapshot; retain unrelated keys and ACLs.
    let mut removed=old.iter().filter_map(|e|e["path"].as_str()).filter(|p|!entries.iter().any(|e|e["path"].as_str().is_some_and(|x|x.eq_ignore_ascii_case(p)))).collect::<Vec<_>>();
    removed.sort_by_key(|p|std::cmp::Reverse(p.len()));
    for p in removed {script.push_str(&format!("[Microsoft.Win32.Registry]::LocalMachine.DeleteSubKeyTree({},$false);",quote(p)));}
    for e in &entries {
        let p=e["path"].as_str().ok_or("Invalid registry path")?;
        let prior=old.iter().find(|e|e["path"].as_str().is_some_and(|x|x.eq_ignore_ascii_case(p.as_ref())));
        let values=e["values"].as_array().ok_or("Invalid registry values")?;
        script.push_str(&format!("$k=[Microsoft.Win32.Registry]::LocalMachine.CreateSubKey({});try{{",quote(p)));
        if let Some(prev)=prior {for value in prev["values"].as_array().ok_or("Invalid registry values")? {if !values.iter().any(|v|v["name"].as_str().zip(value["name"].as_str()).is_some_and(|(a,b)|a.eq_ignore_ascii_case(b))){script.push_str(&format!("$k.DeleteValue({},$false);",quote(value["name"].as_str().ok_or("Invalid registry name")?)));}}}
        for value in values {
            if prior.is_some_and(|e|e["values"].as_array().is_some_and(|vs|vs.contains(value))){continue}
            script.push_str(&format!(r#"$v=ConvertFrom-Json -InputObject {}; $kind=[Enum]::Parse([Microsoft.Win32.RegistryValueKind],[string]$v.kind); $d=$v.data; switch($v.kind){{'Binary'{{$d=[byte[]]$d}} 'None'{{$d=[byte[]]$d}} 'MultiString'{{$d=[string[]]$d}} 'DWord'{{$d=[int]$d}} 'QWord'{{$d=[long]$d}}}}; $k.SetValue([string]$v.name,$d,$kind);"#,quote(&value.to_string())));
        }
        script.push_str("}finally{$k.Close()};");
    }
    Ok(script)
}
fn write_registry(t:Target,v:&PreviousValue)->Result<()> {ps(&registry_script(t,v,&read_registry(t)?)?)?;Ok(())}
fn registry_after(t:Target,before:&PreviousValue,patch:&Value)->Result<PreviousValue>{
    let key=registry(t).ok_or("Invalid registry target")?;
    let mut entries=match before{PreviousValue::Absent=>vec![],PreviousValue::Text(s)=>serde_json::from_str::<Vec<Value>>(s).map_err(|_|"Invalid registry snapshot")?};
    for (name,val) in patch.as_object().ok_or("Invalid policy")? {
        let (p,values)=if let Some(items)=val.as_array(){(format!("{key}\\{name}"),items.iter().enumerate().map(|(i,v)|json!({"name":(i+1).to_string(),"kind":"String","data":v})).collect::<Vec<_>>())}else{(key.to_owned(),vec![json!({"name":name,"kind":if val.is_string(){"String"}else{"DWord"},"data":if val.is_boolean(){json!(if val==true{1}else{0})}else{val.clone()}})])};
        if !entries.iter().any(|e|e["path"].as_str().is_some_and(|x|x.eq_ignore_ascii_case(p.as_ref()))){entries.push(json!({"path":p,"values":[]}));}
        let e=entries.iter_mut().find(|e|e["path"].as_str().is_some_and(|x|x.eq_ignore_ascii_case(p.as_ref()))).unwrap();
        let vs=e["values"].as_array_mut().ok_or("Invalid registry values")?;
        if val.is_array(){vs.clear()}
        for v in values{vs.retain(|old|!old["name"].as_str().zip(v["name"].as_str()).is_some_and(|(a,b)|a.eq_ignore_ascii_case(b)));vs.push(v);}
    }
    Ok(PreviousValue::Text(serde_json::to_string(&entries).map_err(|e|e.to_string())?))
}
pub fn after(os:Os,t:Target,before:&PreviousValue,languages:&[String])->Result<PreviousValue>{
    let patch=patch(os,t,languages);
    if matches!(os,Os::Windows)&&registry(t).is_some(){return registry_after(t,before,&patch)}
    let raw=bytes(before)?;
    if !raw.is_empty() && matches!(os,Os::Mac) && !t.firefox() {
        // Modify a private copy with plutil, retaining unrelated data/date/real values.
        let mut random=[0;16];getrandom::fill(&mut random).map_err(|e|e.to_string())?;
        let tmp=std::env::temp_dir().join(format!("aienv-plist-{:x}",u128::from_ne_bytes(random)));
        atomic_write(&tmp,&raw)?;
        let result=(|| {
            let file=tmp.to_str().ok_or("Invalid temporary path")?;
            for (key,value) in patch.as_object().ok_or("Invalid policy patch")? {
                let json=value.to_string();
                if run(recipe("plutil", &["-replace",key,"-json",&json,file])).is_err(){
                    run(recipe("plutil", &["-insert",key,"-json",&json,file]))?;
                }
            }
            let output=std::fs::read(&tmp).map_err(|e|e.to_string())?;
            Ok(PreviousValue::Text(serde_json::to_string(&output).map_err(|e|e.to_string())?))
        })();
        let _=std::fs::remove_file(tmp);return result;
    }
    let mut doc=if raw.is_empty(){json!({})}else{serde_json::from_slice(&raw).map_err(|_|"Invalid browser policy JSON")?};
    merge(&mut doc,&patch)?;
    let output=if matches!(os,Os::Mac)&&!t.firefox(){plist(&doc)?}else{serde_json::to_vec_pretty(&doc).map_err(|e|e.to_string())?};
    Ok(PreviousValue::Text(serde_json::to_string(&output).map_err(|e|e.to_string())?))
}
fn plist(v:&Value)->Result<Vec<u8>> {
    fn xml(v:&Value)->Result<String>{Ok(match v{Value::Object(m)=>format!("<dict>{}</dict>",m.iter().map(|(k,v)|Ok(format!("<key>{}</key>{}",escape(k),xml(v)?))).collect::<Result<Vec<_>>>()?.join("")),Value::Array(a)=>format!("<array>{}</array>",a.iter().map(xml).collect::<Result<Vec<_>>>()?.join("")),Value::String(s)=>format!("<string>{}</string>",escape(s)),Value::Bool(b)=>format!("<{} />",b),Value::Number(n) if n.is_i64()||n.is_u64()=>format!("<integer>{n}</integer>"),_=>return Err("Unsupported plist value; policy unchanged".into())})}
    fn escape(s:&str)->String{s.replace('&',"&amp;").replace('<',"&lt;").replace('>',"&gt;").replace('"',"&quot;").replace('\'',"&apos;")}
    Ok(format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\"><plist version=\"1.0\">{}</plist>",xml(v)?).into_bytes())
}
pub fn plan(adapter:&impl SystemAdapter,os:Os,targets:&[Target],languages:&[String])->Result<Option<FixPlan>> {
    let mut random=[0;16];getrandom::fill(&mut random).map_err(|e|e.to_string())?;
    let mut p=FixPlan{id:format!("browser-{:x}",u128::from_ne_bytes(random)),check_id:"browser".into(),steps:vec![],requires_admin:true,resources:vec![],preview:vec![]};
    for t in targets {let r=ResourceId::Browser(*t);let before=adapter.read(&r)?;let next=after(os,*t,&before,languages)?;
        if next==before{continue}p.resources.push(r.clone());p.preview.push(ChangePreview{resource:r,before:display_value(&before),after:serde_json::to_string_pretty(&patch(os,*t,languages)).map_err(|e|e.to_string())?});p.steps.push(FixStep::SetBrowser{target:*t,value:next});
    }
    if p.steps.is_empty(){Ok(None)}else{Ok(Some(p))}
}

#[cfg(test)] mod tests {
    use super::*;
    use std::{collections::BTreeMap,sync::Mutex};
    #[derive(Default)]struct Fake(Mutex<BTreeMap<ResourceId,PreviousValue>>);
    impl SystemAdapter for Fake {
        fn read(&self,r:&ResourceId)->Result<PreviousValue>{Ok(self.0.lock().unwrap().get(r).cloned().unwrap_or(PreviousValue::Absent))}
        fn write(&self,r:&ResourceId,v:&PreviousValue)->Result<()>{self.0.lock().unwrap().insert(r.clone(),v.clone());Ok(())}
    }
    fn snapshot(v:Value)->PreviousValue {PreviousValue::Text(serde_json::to_string(&serde_json::to_vec(&v).unwrap()).unwrap())}
    #[test]fn json_merge_preserves_unrelated_and_exceptions(){
        let before=snapshot(json!({"OtherPolicy":{"nested":true},"WebRtcLocalIpsAllowedUrls":["https://allowed.example"],"QuicAllowed":true}));
        let next=after(Os::Linux,Target::Chrome,&before,&["ja-JP".into()]).unwrap();
        let doc:Value=serde_json::from_slice(&bytes(&next).unwrap()).unwrap();
        assert_eq!(doc["OtherPolicy"]["nested"],true);assert_eq!(doc["WebRtcLocalIpsAllowedUrls"][0],"https://allowed.example");assert_eq!(doc["WebRtcIPHandling"],"disable_non_proxied_udp");assert_eq!(doc["QuicAllowed"],false);assert_eq!(doc["DefaultGeolocationSetting"],2);assert_eq!(doc["WebRtcIPHandlingPolicy"],"disable_non_proxied_udp");assert!(doc.get("ApplicationLocaleValue").is_none());
    }
    #[test]fn firefox_merge_locked_preferences(){
        let before=snapshot(json!({"policies":{"DisableTelemetry":true,"Preferences":{"other.pref":true},"Permissions":{"Location":{"Allow":["https://existing.example"]}}}}));
        let next=after(Os::Linux,Target::Firefox,&before,&["ko-KR".into(),"en-US".into()]).unwrap();
        let d:Value=serde_json::from_slice(&bytes(&next).unwrap()).unwrap();let p=&d["policies"];
        assert_eq!(p["DisableTelemetry"],true);assert_eq!(p["Preferences"]["other.pref"],true);
        assert_eq!(p["RequestedLocales"],json!(["ko-KR","en-US"]));assert_eq!(p["Preferences"]["intl.accept_languages"]["Value"],"ko-KR,en-US");
        assert_eq!(p["Permissions"]["Location"]["Allow"][0],"https://existing.example");assert_eq!(p["Permissions"]["Location"]["BlockNewRequests"],true);
        for k in ["media.peerconnection.ice.default_address_only","media.peerconnection.ice.no_host","media.peerconnection.ice.proxy_only_if_behind_proxy","network.http.http3.enable","intl.accept_languages","geo.enabled"]{assert_eq!(p["Preferences"][k]["Status"],"locked");}
    }
    #[test]fn plist_and_registry_generation(){
        let langs=vec!["en-US".into(),"en".into()];
        let mac=after(Os::Mac,Target::Edge,&PreviousValue::Absent,&langs).unwrap();let xml=String::from_utf8(bytes(&mac).unwrap()).unwrap();assert!(xml.contains("<key>ForcedLanguages</key><array><string>en-US</string>"));assert!(xml.contains("<key>WebRtcLocalhostIpHandling</key><string>disable_non_proxied_udp</string>"));assert!(xml.contains("<false />"));assert!(!xml.contains("ApplicationLocaleValue"));
        let key=registry(Target::Chrome).unwrap();
        let before=PreviousValue::Text(json!([{"path":key,"values":[{"name":"Unrelated","kind":"Binary","data":[0,255]},{"name":"WebRtcLocalIpsAllowedUrls","kind":"String","data":"keep"}]}]).to_string());
        let next=after(Os::Windows,Target::Chrome,&before,&langs).unwrap();let PreviousValue::Text(text)=next else{panic!()};let entries:Vec<Value>=serde_json::from_str(&text).unwrap();
        let values=entries[0]["values"].as_array().unwrap();assert!(values.iter().any(|v|v["name"]=="Unrelated"&&v["data"]==json!([0,255])));assert!(values.iter().any(|v|v["name"]=="ApplicationLocaleValue"&&v["data"]=="en-US"));assert!(entries.iter().any(|e|e["path"]==format!("{key}\\ForcedLanguages")&&e["values"][1]["data"]=="en"));
    }
    #[test]fn backup_absent_restore_and_exact_bytes(){
        let mut random=[0;16];getrandom::fill(&mut random).unwrap();let dir=std::env::temp_dir().join(format!("aienv-browser-{:x}",u128::from_ne_bytes(random)));
        let r=ResourceId::Browser(Target::Chrome);let e=Engine{dir:dir.clone(),adapter:Fake::default(),locks:Default::default(),allowed:[r.clone()].into_iter().collect()};
        for before in [PreviousValue::Absent,PreviousValue::Text(serde_json::to_string(&b"{\n \"Other\": true }\n".to_vec()).unwrap())]{e.adapter.write(&r,&before).unwrap();let p=plan(&e.adapter,Os::Linux,&[Target::Chrome],&["en-US".into()]).unwrap().unwrap();let report=e.apply(&p).unwrap();assert!(report.success);assert_eq!(e.load(&report.backup_id).unwrap().entries[0].previous_value,before);assert!(e.restore(&report.backup_id).unwrap().success);assert_eq!(e.adapter.read(&r).unwrap(),before);}
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]fn absent_browser_is_skipped(){
        let targets=Target::ALL.into_iter().filter(|t|installed(Os::Linux,*t,|_|false)).collect::<Vec<_>>();assert!(targets.is_empty());assert!(plan(&Fake::default(),Os::Linux,&targets,&["en-US".into()]).unwrap().is_none());
        assert!(installed(Os::Linux,Target::FirefoxUsr,|p|p=="/usr/lib/firefox/firefox"));
        assert_eq!(path(Os::Linux,Target::Edge).unwrap(),PathBuf::from("/etc/opt/edge/policies/managed/aienv.json"));
    }
    #[test]fn invalid_json_refused(){assert!(after(Os::Linux,Target::Chrome,&PreviousValue::Text("[255]".into()),&[]).is_err());}
}

#[cfg(test)] mod regression_tests {
    use super::*;
    #[test]fn registry_delta_preserves_unrelated_values_and_absence(){
        let key=registry(Target::Edge).unwrap();let before=PreviousValue::Text(json!([{"path":key,"values":[{"name":"Unrelated","kind":"Binary","data":[0,255]}]}]).to_string());
        let after=registry_after(Target::Edge,&before,&patch(Os::Windows,Target::Edge,&["ja-JP".into()])).unwrap();
        let apply=registry_script(Target::Edge,&after,&before).unwrap();
        assert!(!apply.contains("Unrelated"));assert!(!apply.contains("DeleteSubKeyTree"));assert!(apply.contains("ForcedLanguages"));assert!(apply.contains("ApplicationLocaleValue"));
        let restore=registry_script(Target::Edge,&before,&after).unwrap();assert!(restore.contains("DeleteSubKeyTree"));assert!(restore.contains("DeleteValue('QuicAllowed'"));assert!(!restore.contains("Unrelated"));
        let remove=registry_script(Target::Edge,&PreviousValue::Absent,&after).unwrap();assert!(remove.contains(&format!("DeleteSubKeyTree('{}'",key)));
        let outside=PreviousValue::Text(json!([{"path":"SOFTWARE\\Other","values":[]}]).to_string());assert!(registry_script(Target::Edge,&outside,&before).is_err());
    }
    #[test]fn temporary_file_absence_restore_deletes_and_contents_restore_exactly(){
        struct TempAdapter(std::path::PathBuf);
        impl SystemAdapter for TempAdapter {
            fn read(&self,_:&ResourceId)->Result<PreviousValue>{match std::fs::read(&self.0){Ok(b)=>Ok(PreviousValue::Text(serde_json::to_string(&b).unwrap())),Err(e) if e.kind()==std::io::ErrorKind::NotFound=>Ok(PreviousValue::Absent),Err(e)=>Err(e.to_string())}}
            fn write(&self,_:&ResourceId,v:&PreviousValue)->Result<()>{write_policy_file(&self.0,v)}
        }
        let mut random=[0;16];getrandom::fill(&mut random).unwrap();let dir=std::env::temp_dir().join(format!("aienv-browser-file-{:x}",u128::from_ne_bytes(random)));let path=dir.join("policies/aienv.json");let r=ResourceId::Browser(Target::Chrome);
        let e=Engine{dir:dir.join("journal"),adapter:TempAdapter(path.clone()),locks:Default::default(),allowed:[r.clone()].into_iter().collect()};
        let p=plan(&e.adapter,Os::Linux,&[Target::Chrome],&["en-US".into()]).unwrap().unwrap();let applied=e.apply(&p).unwrap();assert!(applied.success);assert!(path.is_file());
        #[cfg(unix)] {use std::os::unix::fs::PermissionsExt;assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode()&0o777,0o644);}
        assert!(e.restore(&applied.backup_id).unwrap().success);assert!(!path.exists());
        let original=b"{ \"Custom\": true }\n";std::fs::write(&path,original).unwrap();let p=plan(&e.adapter,Os::Linux,&[Target::Chrome],&["ko-KR".into()]).unwrap().unwrap();let applied=e.apply(&p).unwrap();assert!(e.restore(&applied.backup_id).unwrap().success);assert_eq!(std::fs::read(&path).unwrap(),original);
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]fn unsupported_variants_not_detected_and_standard_paths(){
        assert!(!installed(Os::Linux,Target::FirefoxX86,|_|true));assert!(!installed(Os::Mac,Target::FirefoxUsr,|_|true));
        assert_eq!(path(Os::Linux,Target::FirefoxEsr).unwrap(),PathBuf::from("/usr/lib/firefox-esr/distribution/policies.json"));
        assert_eq!(path(Os::Mac,Target::Firefox).unwrap(),PathBuf::from("/Applications/Firefox.app/Contents/Resources/distribution/policies.json"));
        assert!(path(Os::Windows,Target::FirefoxX86).unwrap().to_string_lossy().contains("Mozilla Firefox"));
    }
}

#[cfg(test)] mod generation_tests {
    use super::*;
    struct Absent;
    impl SystemAdapter for Absent {
        fn read(&self,_:&ResourceId)->Result<PreviousValue>{Ok(PreviousValue::Absent)}
        fn write(&self,_:&ResourceId,_:&PreviousValue)->Result<()>{panic!("Generation never writes")}
    }
    #[test]fn typed_plist_registry_and_firefox_steps_all_os(){
        for os in [Os::Linux,Os::Mac,Os::Windows] {for target in [Target::Chrome,Target::Edge,Target::Chromium,Target::Brave,Target::Firefox] {
            let p=plan(&Absent,os,&[target],&["en-US".into()]).unwrap().unwrap();
            assert!(p.requires_admin);assert_eq!(p.resources,vec![ResourceId::Browser(target)]);assert!(matches!(p.steps[0],FixStep::SetBrowser{target:t,..} if t==target));
            assert!(crate::transaction::validate(&p,&crate::helper::allowlist()).is_ok());
            let mut wrong=p;wrong.resources=vec![ResourceId::Timezone];assert!(crate::transaction::validate(&wrong,&crate::helper::allowlist()).is_err());
        }}
    }
    #[test]fn firefox_existing_scalar_preference_is_locked_without_losing_siblings(){
        let mut doc=json!({"policies":{"Preferences":{"geo.enabled":true,"other":false}}});merge(&mut doc,&patch(Os::Linux,Target::Firefox,&["ja-JP".into()])).unwrap();
        assert_eq!(doc["policies"]["Preferences"]["geo.enabled"],json!({"Value":false,"Status":"locked"}));assert_eq!(doc["policies"]["Preferences"]["other"],false);
    }
}

#[cfg(test)]mod snapshot_tests {
    use super::*;
    #[test]fn registry_snapshot_order_is_stable_across_helper_processes(){
        let a=r#"[{"path":"root\\z","values":[]},{"values":[{"name":"z","data":"secret","kind":"String"},{"name":"a","data":0,"kind":"DWord"}],"path":"root"}]"#;
        let b=r#"[{"path":"root","values":[{"kind":"DWord","data":0,"name":"a"},{"kind":"String","data":"secret","name":"z"}]},{"values":[],"path":"root\\z"}]"#;
        assert_eq!(canonical_registry(a).unwrap(),canonical_registry(b).unwrap());
    }
}
