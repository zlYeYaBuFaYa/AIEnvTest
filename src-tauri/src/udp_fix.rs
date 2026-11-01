//! An owned firewall policy; it never flushes a shared table, ruleset or group.
use crate::{system_fixes::{Os,Recipe,recipe,run},transaction::*};
use serde::{Serialize,Deserialize};
use std::{net::IpAddr,path::PathBuf};
type Result<T>=std::result::Result<T,String>;
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TunnelException {pub endpoint:IpAddr,pub port:u16,pub resolver:IpAddr}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Policy {pub owner:String,pub interfaces:Vec<String>,pub tunnel:TunnelException,pub pf_token:Option<String>}
pub fn validate(text:&str)->Result<Option<Policy>>{
    let policy:Option<Policy>=serde_json::from_str(text).map_err(|_|"repair.udpPrerequisite")?;
    if let Some(p)=&policy {
        if p.owner.len()!=32||!p.owner.bytes().all(|c|c.is_ascii_hexdigit())||p.interfaces.is_empty()||p.interfaces.len()>128||p.interfaces.iter().any(|s|s.is_empty()||s.len()>256||s.contains(['\n','\r','\0']))||p.tunnel.port==0||p.tunnel.endpoint.is_unspecified()||p.tunnel.endpoint.is_multicast()||p.tunnel.resolver.is_unspecified()||p.tunnel.resolver.is_multicast()||p.pf_token.as_ref().is_some_and(|s|s.is_empty()||!s.bytes().all(|c|c.is_ascii_digit())) {return Err("repair.udpPrerequisite".into())}
    }Ok(policy)
}
fn manifest()->PathBuf{match Os::current(){Os::Linux=>"/etc/aienv-udp.json".into(),Os::Mac=>"/Library/Preferences/com.aienv.udp.json".into(),Os::Windows=>r"C:\ProgramData\AIEnv\udp.json".into()}}
fn load()->Result<Option<Policy>> {
    let path=manifest();
    match std::fs::symlink_metadata(&path){Ok(m) if !m.is_file()||m.file_type().is_symlink()=>return Err("repair.udpOwned".into()),Ok(_)=>{},Err(e) if e.kind()==std::io::ErrorKind::NotFound=>return Ok(None),Err(_)=>return Err("repair.udpOwned".into())}
    validate(&std::fs::read_to_string(path).map_err(|_|"repair.udpOwned")?)
}
fn ps(script:&str)->Recipe{recipe("powershell", &["-NoProfile","-NonInteractive","-Command",&format!("$ErrorActionPreference='Stop'; [Console]::OutputEncoding=[Text.UTF8Encoding]::new(); {script}")])}
fn q(s:&str)->String{format!("'{}'",s.replace('\'',"''"))}
fn tag(p:&Policy)->String{format!("AIEnv-{}",p.owner)}
fn native_present(os:Os)->Result<bool>{Ok(match os {
    Os::Linux=>{let v:serde_json::Value=serde_json::from_str(&run(recipe("nft", &["-j","list","tables"]))?).map_err(|_|"repair.udpOwned")?;v["nftables"].as_array().ok_or("repair.udpOwned")?.iter().any(|v|v["table"]["family"]=="inet"&&v["table"]["name"]=="aienv")},
    Os::Mac=>!run(recipe("pfctl", &["-a","com.apple/com.aienv","-sr"]))?.trim().is_empty(),
    Os::Windows=>false,
})}
fn verify_owned(os:Os,p:&Policy)->Result<()> {
    match os {
        Os::Linux=>{
            let v:serde_json::Value=serde_json::from_str(&run(recipe("nft", &["-j","list","table","inet","aienv"]))?).map_err(|_|"repair.udpOwned")?;
            let items=v["nftables"].as_array().ok_or("repair.udpOwned")?;
            for item in items {
                if item.get("metainfo").is_some(){continue}
                if let Some(t)=item.get("table"){if t["name"]!="aienv"||t["comment"]!=tag(p){return Err("repair.udpOwned".into())}}
                else if let Some(c)=item.get("chain"){if c["name"]!="output"{return Err("repair.udpOwned".into())}}
                else if let Some(r)=item.get("rule"){if r["comment"]!=tag(p){return Err("repair.udpOwned".into())}}
                else{return Err("repair.udpOwned".into())}
            }
        },
        Os::Mac=>{
            let rules=run(recipe("pfctl", &["-a","com.apple/com.aienv","-sr"]))?;
            if rules.lines().any(|line|!line.trim().is_empty()&&!line.contains(&format!("label \"{}\"",tag(p)))){return Err("repair.udpOwned".into())}
        },
        Os::Windows=>{run(ps(&format!("Get-NetFirewallRule -Group AIEnv -ErrorAction SilentlyContinue | Where-Object {{$_.Name -like '{}-*'}} | ForEach-Object {{if($_.Description -ne {}){{throw 'Foreign rule'}}}}",tag(p),q(&tag(p)))))?;},
    } Ok(())
}
pub fn read()->Result<PreviousValue>{
    let mut policy=load()?;
    if let Some(p)=&policy{verify_owned(Os::current(),p)?}else if native_present(Os::current())?{return Err("repair.udpOwned".into())}
    if let Some(p)=&mut policy{p.pf_token=None;} // Refcounts belong to the live manifest, not portable backups.
    Ok(PreviousValue::Text(serde_json::to_string(&policy).map_err(|_|"repair.udpOwned")?))
}
fn save(p:&Policy)->Result<()> {
    let path=manifest();atomic_write(&path,&serde_json::to_vec(p).map_err(|_|"repair.udpOwned")?)?;
    #[cfg(unix)] {use std::os::unix::fs::PermissionsExt;std::fs::set_permissions(path,std::fs::Permissions::from_mode(0o644)).map_err(|_|"repair.udpOwned")?;}
    Ok(())
}
fn safe_iface(s:&str)->bool{!s.is_empty()&&s.bytes().all(|c|c.is_ascii_alphanumeric()||b"_-".contains(&c))}
pub fn physical(os:Os)->Result<Vec<String>> {
    let names=match os {
        Os::Linux=>{let mut v=vec![];for e in std::fs::read_dir("/sys/class/net").map_err(|_|"repair.udpPrerequisite")?{let e=e.map_err(|_|"repair.udpPrerequisite")?;if e.path().join("device").exists(){v.push(e.file_name().to_string_lossy().into_owned())}}v},
        Os::Mac=>run(recipe("networksetup", &["-listallhardwareports"]))?.lines().filter_map(|s|s.strip_prefix("Device: ")).filter(|s|s.starts_with("en")).map(str::to_owned).collect(),
        Os::Windows=>{let text=run(ps("ConvertTo-Json -InputObject @(Get-NetAdapter -Physical | ForEach-Object {$_.Name}) -Compress"))?;serde_json::from_str(&text).map_err(|_|"repair.udpPrerequisite")?},
    };
    if names.is_empty()||(!matches!(os,Os::Windows)&&names.iter().any(|s|!safe_iface(s))){return Err("repair.udpPrerequisite".into())}Ok(names)
}
pub fn policy_text(os:Os,p:&Policy)->Result<String> {
    validate(&serde_json::to_string(&Some(p)).map_err(|_|"repair.udpOwned")?)?;
    if !matches!(os,Os::Windows)&&p.interfaces.iter().any(|s|!safe_iface(s)){return Err("repair.udpPrerequisite".into())}
    let t=&p.tunnel;let tag=tag(p);
    Ok(match os {
        Os::Linux=>{
            let ifaces=p.interfaces.iter().map(|s|format!("\"{s}\"")).collect::<Vec<_>>().join(", ");
            let base=format!("create table inet aienv {{ comment \"{tag}\"; }}\nadd chain inet aienv output {{ type filter hook output priority 0; policy accept; }}\n");
            let mut text=base;
            for exception in ["meta nfproto ipv4 udp sport 68 udp dport 67".to_owned(),"meta nfproto ipv6 udp sport 546 udp dport 547".to_owned(),format!("{} daddr {} udp dport {}",if t.endpoint.is_ipv4(){"ip"}else{"ip6"},t.endpoint,t.port),format!("{} daddr {} udp dport 53",if t.resolver.is_ipv4(){"ip"}else{"ip6"},t.resolver)] {text+=&format!("add rule inet aienv output oifname {{ {ifaces} }} {exception} accept comment \"{tag}\"\n");}
            text+=&format!("add rule inet aienv output oifname {{ {ifaces} }} meta l4proto udp drop comment \"{tag}\"\n");text
        },
        Os::Mac=>{
            let mut text=String::new();
            for iface in &p.interfaces {
                for (family,exception) in [("inet","from any port 68 to any port 67".to_owned()),("inet6","from any port 546 to any port 547".to_owned()),(if t.endpoint.is_ipv4(){"inet"}else{"inet6"},format!("from any to {} port {}",t.endpoint,t.port)),(if t.resolver.is_ipv4(){"inet"}else{"inet6"},format!("from any to {} port 53",t.resolver))] {text+=&format!("pass out quick on {iface} {family} proto udp {exception} label \"{tag}\"\n");}
                text+=&format!("block drop out quick on {iface} proto udp from any to any label \"{tag}\"\n");
            }text
        },
        Os::Windows=>windows_script(p),
    })
}
fn port_complement(excluded:&[u16])->String {
    let mut values=excluded.to_vec();values.sort_unstable();values.dedup();let mut start=0u32;let mut out=vec![];
    for port in values{let port=port as u32;if start<port{out.push(if start==port-1{start.to_string()}else{format!("{start}-{}",port-1)})}start=port+1;}
    if start<=65535{out.push(if start==65535{"65535".into()}else{format!("{start}-65535")})}out.join(",")
}
fn address_complement(ips:&[IpAddr])->Vec<String>{
    let mut out=vec![];
    for v4 in [true,false]{
        let mut excluded=ips.iter().filter(|a|a.is_ipv4()==v4).map(|ip|match ip{IpAddr::V4(a)=>u32::from(*a) as u128,IpAddr::V6(a)=>u128::from(*a)}).collect::<Vec<_>>();excluded.sort_unstable();excluded.dedup();
        let max=if v4{u32::MAX as u128}else{u128::MAX};let display=|n:u128|if v4{std::net::Ipv4Addr::from(n as u32).to_string()}else{std::net::Ipv6Addr::from(n).to_string()};
        let mut start=Some(0);for n in excluded{if let Some(s)=start{if s<n{out.push(format!("{}-{}",display(s),display(n-1)))}}start=n.checked_add(1);}
        if let Some(s)=start{if s<=max{out.push(format!("{}-{}",display(s),display(max)))}}
    }out
}
fn windows_script(p:&Policy)->String {
    let mut specials=std::collections::BTreeMap::<IpAddr,Vec<u16>>::new();specials.entry(p.tunnel.endpoint).or_default().push(p.tunnel.port);specials.entry(p.tunnel.resolver).or_default().push(53);
    let ips=specials.keys().copied().collect::<Vec<_>>();let ranges=address_complement(&ips);
    let mut groups=vec![];
    for v4 in [true,false]{groups.push((ranges.iter().filter(|s|s.split('-').next().unwrap_or("").parse::<IpAddr>().is_ok_and(|a|a.is_ipv4()==v4)).cloned().collect::<Vec<_>>(),vec![],v4));}
    groups.extend(specials.into_iter().map(|(ip,ports)|(vec![ip.to_string()],ports,ip.is_ipv4())));
    let mut text=String::new();let aliases=p.interfaces.iter().map(|s|q(s)).collect::<Vec<_>>().join(",");let mut i=0;
    text+=&format!("$aliases=@({aliases}); foreach($a in $aliases){{if(-not (Get-NetAdapter -Physical | Where-Object Name -eq $a)){{throw 'Physical adapter unavailable'}}}}; ");
    for (addresses,allowed,v4) in groups{
        if addresses.is_empty(){continue}
        for (local,extra) in [(port_complement(&[68,546]),None),("68".into(),if v4{Some(67)}else{None}),("546".into(),if v4{None}else{Some(547)})]{
            let mut ports=allowed.clone();ports.extend(extra);let remote=port_complement(&ports);
            let array=|s:&str|s.split(',').map(q).collect::<Vec<_>>().join(",");
            text+=&format!("New-NetFirewallRule -Name {} -DisplayName {} -Description {} -Group AIEnv -Direction Outbound -Action Block -Protocol UDP -InterfaceAlias $aliases -LocalPort @({}) -RemotePort @({}) -RemoteAddress @({}) -Enabled True -Profile Any | Out-Null; ",q(&format!("{}-{i}",tag(p))),q("AIEnv UDP / QUIC"),q(&tag(p)),array(&local),array(&remote),addresses.iter().map(|s|q(s)).collect::<Vec<_>>().join(","));i+=1;
        }
    }text
}
fn windows_names(p:&Policy)->Vec<String>{let n=if p.tunnel.endpoint==p.tunnel.resolver{9}else{12};(0..n).map(|i|format!("{}-{i}",tag(p))).collect()}
fn removal_recipes(os:Os,p:&Policy)->Vec<Recipe>{match os {
    Os::Linux=>vec![recipe("nft", &["delete","table","inet","aienv"])],
    Os::Mac=>{let mut v=vec![recipe("pfctl", &["-a","com.apple/com.aienv","-F","rules"])];if let Some(token)=&p.pf_token{v.push(recipe("pfctl", &["-X",token]));}v},
    Os::Windows=>windows_names(p).iter().map(|name|ps(&format!("$r=Get-NetFirewallRule -Name {} -ErrorAction SilentlyContinue; if($null -ne $r){{if($r.Group -ne 'AIEnv' -or $r.Description -ne {}){{throw 'Foreign rule'}}; $r | Remove-NetFirewallRule}}",q(name),q(&tag(p))))).collect(),
}}
fn script_file(text:&str)->Result<PathBuf>{let mut random=[0;16];getrandom::fill(&mut random).map_err(|_|"repair.udpOwned")?;let path=std::env::temp_dir().join(format!("aienv-firewall-{:x}",u128::from_ne_bytes(random)));atomic_write(&path,text.as_bytes())?;Ok(path)}
pub fn write(value:&PreviousValue)->Result<()> {
    let PreviousValue::Text(text)=value else{return Err("repair.udpOwned".into())};let desired=validate(text)?;let current=load()?;let os=Os::current();
    if let Some(old)=&current {
        if let Some(new)=&desired{let mut portable=old.clone();portable.pf_token=None;if new==&portable{return Ok(())}return Err("repair.udpRestoreFirst".into())}
        let present=if matches!(os,Os::Linux){native_present(os)?}else{true};
        if present {verify_owned(os,old)?;for command in removal_recipes(os,old){run(command)?;}}
        std::fs::remove_file(manifest()).map_err(|_|"repair.udpOwned")?;return Ok(())
    }
    let Some(mut p)=desired else{return Ok(())};
    p.pf_token=None;
    if native_present(os)?{return Err("repair.udpOwned".into())}
    let physical=physical(os)?;if p.interfaces.iter().any(|s|!physical.contains(s)){return Err("repair.udpPrerequisite".into())}
    if matches!(os,Os::Mac){let main=run(recipe("pfctl", &["-sr"]))?;validate_pf_hook(&main)?;let children=run(recipe("pfctl", &["-a","com.apple/*","-sr"]))?;if children.split_whitespace().any(|s|s=="quick"){return Err("repair.udpPfHook".into())}let states=run(recipe("pfctl", &["-ss"]))?;validate_pf_states(&states,&p.tunnel)?;}
    let script=policy_text(os,&p)?;
    save(&p)?; // Record ownership before a possibly partial firewall write, for rollback.
    match os {
        Os::Windows=>{run(ps(&script))?;},
        Os::Linux|Os::Mac=>{
            let path=script_file(&script)?;
            let command=if matches!(os,Os::Linux){recipe("nft", &["-f",path.to_str().ok_or("repair.udpOwned")?])}else{recipe("pfctl", &["-a","com.apple/com.aienv","-f",path.to_str().ok_or("repair.udpOwned")?])};
            let result=run(command);let _=std::fs::remove_file(path);result?;
            if matches!(os,Os::Mac){let output=run(recipe("pfctl", &["-E"]))?;let token=output.lines().find_map(|l|l.trim().strip_prefix("Token : ")).ok_or("repair.udpOwned")?;if !token.bytes().all(|c|c.is_ascii_digit()){return Err("repair.udpOwned".into())}p.pf_token=Some(token.into());save(&p)?;}
        },
    }Ok(())
}
pub fn plan(adapter:&impl SystemAdapter,os:Os,tunnel:TunnelException,interfaces:Vec<String>)->Result<Option<FixPlan>>{
    let before=adapter.read(&ResourceId::Udp)?;let PreviousValue::Text(text)=&before else{return Err("repair.udpOwned".into())};
    if let Some(current)=validate(text)?{if current.tunnel==tunnel&&current.interfaces==interfaces{return Ok(None)}return Err("repair.udpRestoreFirst".into())}
    let mut random=[0;16];getrandom::fill(&mut random).map_err(|_|"repair.udpOwned")?;
    let owner=random.iter().map(|b|format!("{b:02x}")).collect::<String>();let p=Policy{owner:owner.clone(),interfaces,tunnel,pf_token:None};
    let preview=format!("{}\n\n{}",serde_json::to_string_pretty(&p).map_err(|_|"repair.udpOwned")?,policy_text(os,&p)?);let after=serde_json::to_string(&Some(p)).map_err(|_|"repair.udpOwned")?;
    Ok(Some(FixPlan{id:owner,check_id:"udp_quic".into(),steps:vec![FixStep::SetUdp{value:after}],requires_admin:true,resources:vec![ResourceId::Udp],preview:vec![ChangePreview{resource:ResourceId::Udp,before:display_value(&before),after:preview}]}))
}

#[cfg(test)]mod tests{
    use super::*;use std::sync::Mutex;
    struct Fake(Mutex<PreviousValue>);
    impl SystemAdapter for Fake{fn read(&self,_:&ResourceId)->Result<PreviousValue>{Ok(self.0.lock().unwrap().clone())}fn write(&self,_:&ResourceId,v:&PreviousValue)->Result<()>{*self.0.lock().unwrap()=v.clone();Ok(())}}
    fn sample()->TunnelException{TunnelException{endpoint:"198.51.100.7".parse().unwrap(),port:51820,resolver:"10.0.0.1".parse().unwrap()}}
    fn roundtrip(os:Os){
        let mut random=[0;16];getrandom::fill(&mut random).unwrap();let dir=std::env::temp_dir().join(format!("aienv-udp-test-{:x}",u128::from_ne_bytes(random)));
        let engine=Engine{dir:dir.clone(),adapter:Fake(Mutex::new(PreviousValue::Text("null".into()))),locks:Default::default(),allowed:[ResourceId::Udp].into_iter().collect()};
        let p=plan(&engine.adapter,os,sample(),vec![if matches!(os,Os::Windows){"Wi-Fi".into()}else{"en0".into()}]).unwrap().unwrap();assert!(p.requires_admin);
        let FixStep::SetUdp{value}=&p.steps[0] else{panic!()};let mut policy=validate(value).unwrap().unwrap();policy.pf_token=Some("123".into());
        let cleanup=removal_recipes(os,&policy);
        match os {Os::Linux=>assert_eq!(cleanup,vec![recipe("nft", &["delete","table","inet","aienv"])]),Os::Mac=>assert_eq!(cleanup[1],recipe("pfctl", &["-X","123"])),Os::Windows=>{assert_eq!(cleanup.len(),12);for c in cleanup{assert!(c.args.last().unwrap().contains("-Name 'AIEnv-"));assert!(!c.args.last().unwrap().contains("-Group AIEnv | Remove"));}}}
        let after=&p.preview[0].after;assert!(after.contains("198.51.100.7"));assert!(after.contains("51820"));assert!(!after.contains("utun"));assert!(!after.contains("tun0"));
        match os{
            Os::Linux=>{assert!(after.contains("table inet aienv"));assert!(after.contains("udp sport 68 udp dport 67"));assert!(after.contains("10.0.0.1 udp dport 53"));assert!(after.contains("meta l4proto udp drop"));},
            Os::Mac=>{assert!(after.contains("pass out quick on en0"));assert!(after.contains("block drop out quick on en0 proto udp"));assert!(after.find("port 51820").unwrap()<after.find("block drop").unwrap());},
            Os::Windows=>{assert!(after.contains("-Group AIEnv"));assert!(after.contains("-InterfaceAlias $aliases"));assert!(after.contains("Get-NetAdapter -Physical"));assert!(!after.contains("-InterfaceType"));assert!(after.contains("AIEnv UDP / QUIC"));assert!(after.contains("198.51.100.8-255.255.255.255"));},
        }
        let report=engine.apply(&p).unwrap();assert!(report.success);assert_eq!(engine.load(&report.backup_id).unwrap().entries[0].previous_value,PreviousValue::Text("null".into()));
        assert!(engine.restore(&report.backup_id).unwrap().success);assert_eq!(engine.adapter.read(&ResourceId::Udp).unwrap(),PreviousValue::Text("null".into()));
        assert!(engine.restore_all().unwrap().iter().all(|r|r.success));std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]fn udp_linux(){roundtrip(Os::Linux)}
    #[test]fn udp_mac(){roundtrip(Os::Mac)}
    #[test]fn udp_windows(){roundtrip(Os::Windows)}
    #[test]fn windows_exact_exception_complements(){
        assert_eq!(port_complement(&[53,67,53]),"0-52,54-66,68-65535");assert_eq!(port_complement(&[0,65535]),"1-65534");
        let ranges=address_complement(&["0.0.0.0".parse().unwrap(),"255.255.255.255".parse().unwrap(),"::".parse().unwrap(),"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap()]);
        assert_eq!(ranges,vec!["0.0.0.1-255.255.255.254","::1-ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe"]);
        let p=Policy{owner:"0".repeat(32),interfaces:vec!["Wi-Fi ' office".into()],tunnel:sample(),pf_token:None};let script=policy_text(Os::Windows,&p).unwrap();assert!(script.contains("'Wi-Fi '' office'"));
    }
    #[test]fn pf_hook_is_observed_before_writes(){assert!(validate_pf_hook("anchor \"com.apple/*\" all").is_ok());assert!(validate_pf_hook("pass out quick all\nanchor \"com.apple/*\" all").is_err());assert!(validate_pf_hook("pass all").is_err());}
    #[test]fn pf_existing_direct_states_are_refused_without_killing_tunnel(){
        let tunnel=sample();
        assert!(validate_pf_states("all udp 192.0.2.1:12345 -> 198.51.100.7:51820 MULTIPLE:MULTIPLE",&tunnel).is_ok());
        assert!(validate_pf_states("all udp 10.0.0.2:12345 -> 10.0.0.1:53 SINGLE:SINGLE",&tunnel).is_ok());
        assert!(validate_pf_states("all udp 192.0.2.1:68 -> 255.255.255.255:67 SINGLE:SINGLE",&tunnel).is_ok());
        assert!(validate_pf_states("all udp 192.0.2.1:12345 -> 203.0.113.1:443 MULTIPLE:MULTIPLE",&tunnel).is_err());
        assert!(validate_pf_states("all udp unrecognized-format",&tunnel).is_err());
    }
    #[test]fn missing_or_invalid_udp_context_refused(){
        let fake=Fake(Mutex::new(PreviousValue::Text("null".into())));
        assert!(plan(&fake,Os::Linux,sample(),vec![]).is_err());
        assert!(plan(&fake,Os::Linux,sample(),vec!["en0; id".into()]).is_err());
        let mut t=sample();t.port=0;assert!(plan(&fake,Os::Windows,t,vec!["Ethernet".into()]).is_err());
        assert!(validate("{\"owner\":\"arbitrary\"}").is_err());
    }
}

fn validate_pf_hook(main:&str)->Result<()> {
    for line in main.lines(){
        if line.starts_with("anchor \"com.apple/*\""){return Ok(())}
        if line.split_whitespace().any(|s|s=="quick") || line.starts_with("anchor "){return Err("repair.udpPfHook".into())}
    }Err("repair.udpPfHook".into())
}

// PF state lookup precedes rule evaluation. Refuse rather than silently leaving
// an existing direct flow alive or flushing states needed by the tunnel.
fn validate_pf_states(text:&str,tunnel:&TunnelException)->Result<()> {
    fn address(token:&str)->Option<std::net::SocketAddr>{
        let token=token.trim_matches(['(',')']);
        token.parse().ok().or_else(||{let (ip,port)=token.rsplit_once('[')?;Some(std::net::SocketAddr::new(ip.parse().ok()?,port.strip_suffix(']')?.parse().ok()?))})
    }
    for line in text.lines(){
        let tokens=line.split_whitespace().collect::<Vec<_>>();
        if !tokens.contains(&"udp"){continue}
        let addresses=tokens.iter().filter_map(|s|address(s)).collect::<Vec<_>>();
        let remote=addresses.last().ok_or("repair.udpExisting")?;
        if (remote.ip()==tunnel.endpoint&&remote.port()==tunnel.port)||(remote.ip()==tunnel.resolver&&remote.port()==53){continue}
        if let Some(local)=addresses.first(){if local.is_ipv4()==remote.is_ipv4()&&((local.is_ipv4()&&local.port()==68&&remote.port()==67)||(local.is_ipv6()&&local.port()==546&&remote.port()==547)){continue}}
        return Err("repair.udpExisting".into())
    }Ok(())
}
