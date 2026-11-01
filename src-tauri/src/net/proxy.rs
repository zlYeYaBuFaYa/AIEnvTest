use tokio::{io::{AsyncReadExt,AsyncWriteExt},net::TcpStream};
use crate::platform::ProxySnapshot;
#[derive(Clone,Debug)]
pub enum Path { Direct, Connect(url::Url), Socks(url::Url) }
impl Path {
 pub fn label(&self)->String { match self {Self::Direct=>"effective == direct (no proxy)".into(),Self::Connect(u)=>format!("effective(PROXY {}:{})",u.host_str().unwrap_or(""),u.port_or_known_default().unwrap_or(80)),Self::Socks(u)=>format!("effective(SOCKS5 {}:{})",u.host_str().unwrap_or(""),u.port().unwrap_or(1080))} }
}
pub async fn resolve(p:&ProxySnapshot,target:&str)->Result<Vec<Path>,String>{
 let u=url::Url::parse(target).map_err(|_|"invalid target")?;let host=u.host_str().ok_or("missing host")?;
 if p.pac {
  let body=if p.pac_url.starts_with("file:"){crate::pac::read_file_url(&p.pac_url).await.ok_or("PAC unavailable")?}else{super::http::fetch(&p.pac_url,None,std::time::Duration::from_secs(6)).await?.body};
  let mut ips=crate::pac::resolve_targets().await;
  if let Ok(mut addrs)=tokio::net::lookup_host((host,443)).await {if let Some(a)=addrs.next(){ips.insert(host.into(),a.ip().to_string());}}
  let target=target.to_owned();let host=host.to_owned();
  let routes=tokio::task::spawn_blocking(move||crate::pac::evaluate(&body,&target,&host,ips).map_err(|_|"PAC evaluation failed".to_string())).await.map_err(|_|"PAC worker failed")??;
  return routes.into_iter().map(|r|match r{crate::pac::Route::Direct=>Ok(Path::Direct),crate::pac::Route::Proxy(s)=>{let(k,a)=s.split_once(' ').ok_or("invalid PAC route")?;parse(a,k)}}).collect();
 }
 if !p.enabled {if p.wpad{return Err("automatic proxy discovery unresolved".into())}return Ok(vec![Path::Direct]);}
 if p.bypass.iter().any(|v| bypass(v,host,u.port_or_known_default())){return Ok(vec![Path::Direct]);}
 // Preserve per-protocol environment overrides before the system's manual endpoints.
 let env_key=if u.scheme()=="https"{"env.https"}else{"env.http"};
 if let Some(raw)=p.sources.get(env_key).or_else(||p.sources.get("env.all")).filter(|s|!s.is_empty()) {
     return Ok(vec![parse(raw,"PROXY")?]);
 }
 let (raw,kind)=if u.scheme()=="https" && !p.https_proxy.is_empty(){(&p.https_proxy,"PROXY")}else if !p.http_proxy.is_empty(){(&p.http_proxy,"PROXY")}else{(&p.socks_proxy,"SOCKS5")};
 if raw.is_empty(){return Err("enabled proxy configuration has no usable endpoint".into());}
 Ok(vec![parse(raw,kind)?])
}
fn bypass(rule:&str,host:&str,port:Option<u16>)->bool{
 let rule=rule.trim();if rule=="*"{return true}if rule=="<local>"{return !host.contains('.')}
 let (r,p)=rule.rsplit_once(':').filter(|(_,p)|p.parse::<u16>().is_ok()).map_or((rule,None),|(h,p)|(h,p.parse().ok()));
 if p.is_some()&&p!=port{return false}let r=r.trim_start_matches('*').trim_start_matches('.');host.eq_ignore_ascii_case(r)||host.to_lowercase().ends_with(&format!(".{}",r.to_lowercase()))
}
fn parse(raw:&str,kind:&str)->Result<Path,String>{
 let scheme=if kind=="SOCKS5"||kind=="SOCKS"{"socks5h"}else{"http"};
 if kind=="SOCKS4"||kind=="HTTPS"{return Err("unsupported proxy transport".into())}
 let u=url::Url::parse(&if raw.contains("://"){raw.into()}else{format!("{scheme}://{raw}")}).map_err(|_|"invalid proxy address")?;
 if u.host_str().is_none(){return Err("invalid proxy host".into())}
 match u.scheme(){"http"=>Ok(Path::Connect(u)),"socks5"|"socks5h"|"socks"=>Ok(Path::Socks(u)),_=>Err("unsupported proxy transport".into())}
}
fn base64(bytes:&[u8])->String{const T:&[u8]=b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";let mut s=String::new();for c in bytes.chunks(3){let n=((c[0] as u32)<<16)|((c.get(1).copied().unwrap_or(0) as u32)<<8)|c.get(2).copied().unwrap_or(0) as u32;for i in 0..4{ s.push(if i>c.len(){'='}else{T[((n>>(18-6*i))&63) as usize] as char});}}s}
fn decode(s:&str)->Result<String,String>{let mut out=Vec::new();let b=s.as_bytes();let mut i=0;while i<b.len(){if b[i]==b'%' {if i+2>=b.len(){return Err("invalid proxy credential encoding".into())}out.push(u8::from_str_radix(&s[i+1..i+3],16).map_err(|_|"invalid proxy credential encoding")?);i+=3}else{out.push(b[i]);i+=1}}String::from_utf8(out).map_err(|_|"invalid proxy credential encoding".into())}
pub async fn connect(path:&Path,host:&str,port:u16,family:Option<super::http::Family>)->Result<TcpStream,String>{
 if matches!(path,Path::Direct){return super::http::connect(host,port,family).await}
 let u=match path{Path::Connect(u)|Path::Socks(u)=>u,_=>unreachable!()};
 let mut s=super::http::connect(u.host_str().ok_or("proxy host missing")?.trim_start_matches('[').trim_end_matches(']'),u.port().unwrap_or(if matches!(path,Path::Socks(_)){1080}else{80}),None).await?;
 match path {
 Path::Connect(_)=>{
 let authority=if host.contains(':'){format!("[{host}]:{port}")}else{format!("{host}:{port}")};
 let auth=if !u.username().is_empty(){format!("Proxy-Authorization: Basic {}\r\n",base64(format!("{}:{}",decode(u.username())?,decode(u.password().unwrap_or(""))?).as_bytes()))}else{String::new()};
 s.write_all(format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n{auth}\r\n").as_bytes()).await.map_err(|_|"CONNECT write failed")?;
 let mut header=Vec::new();while !header.ends_with(b"\r\n\r\n"){if header.len()>=16384{return Err("CONNECT header too large".into())}header.push(s.read_u8().await.map_err(|_|"CONNECT response incomplete")?);}
 if String::from_utf8_lossy(&header).lines().next().and_then(|s|s.split_whitespace().nth(1))!=Some("200"){return Err("CONNECT refused".into())}
 },
 Path::Socks(_)=>{
 let auth=!u.username().is_empty();s.write_all(if auth{&[5,2,0,2]}else{&[5,1,0]}).await.map_err(|_|"SOCKS greeting failed")?;
 let mut reply=[0;2];s.read_exact(&mut reply).await.map_err(|_|"SOCKS greeting incomplete")?;
 if reply==[5,2]&&auth{let user=decode(u.username())?;let pass=decode(u.password().unwrap_or(""))?;if user.len()>255||pass.len()>255{return Err("SOCKS credential too long".into())}let mut b=vec![1,user.len() as u8];b.extend(user.bytes());b.push(pass.len() as u8);b.extend(pass.bytes());s.write_all(&b).await.map_err(|_|"SOCKS auth write failed")?;s.read_exact(&mut reply).await.map_err(|_|"SOCKS auth incomplete")?;if reply!=[1,0]{return Err("SOCKS authentication refused".into())}}
 else if reply!=[5,0]{return Err("SOCKS authentication unavailable".into())}
 let mut b=vec![5,1,0];
 match host.parse::<std::net::IpAddr>() {
     Ok(std::net::IpAddr::V4(ip))=>{b.push(1);b.extend(ip.octets());},
     Ok(std::net::IpAddr::V6(ip))=>{b.push(4);b.extend(ip.octets());},
     Err(_)=>{if host.len()>255{return Err("SOCKS target too long".into())}b.extend([3,host.len() as u8]);b.extend(host.bytes());},
 }
 b.extend(port.to_be_bytes());s.write_all(&b).await.map_err(|_|"SOCKS request failed")?;
 let mut h=[0;4];s.read_exact(&mut h).await.map_err(|_|"SOCKS reply incomplete")?;if h[..3]!=[5,0,0]{return Err("SOCKS connect refused".into())}let n=match h[3]{1=>4,4=>16,3=>s.read_u8().await.map_err(|_|"SOCKS address missing")? as usize,_=>return Err("invalid SOCKS address".into())};let mut tail=vec![0;n+2];s.read_exact(&mut tail).await.map_err(|_|"SOCKS address incomplete")?;
 },_=>{}
 }Ok(s)
}
#[cfg(test)] mod tests{
 use super::*;
 async fn listener()->Option<tokio::net::TcpListener> {
     match tokio::net::TcpListener::bind("127.0.0.1:0").await {
         Ok(l)=>Some(l),
         Err(e) if e.kind()==std::io::ErrorKind::PermissionDenied=>{eprintln!("SKIP localhost handshake: socket bind denied: {e}");None},
         Err(e)=>panic!("localhost bind failed: {e}"),
     }
 }
 // Localhost socket tests skip only when the sandbox denies bind.
 #[tokio::test] async fn connect_fake_server(){
 let Some(l)=listener().await else{return};let a=l.local_addr().unwrap();let task=tokio::spawn(async move{let(mut s,_)=l.accept().await.unwrap();let mut b=Vec::new();while !b.ends_with(b"\r\n\r\n"){b.push(s.read_u8().await.unwrap())}let h=String::from_utf8(b).unwrap();assert!(h.starts_with("CONNECT target.invalid:443 HTTP/1.1"));assert!(h.contains("Proxy-Authorization: Basic dTpw"));s.write_all(b"HTTP/1.1 200 OK\r\n\r\nX").await.unwrap();});
 let p=parse(&format!("http://u:p@{a}"),"PROXY").unwrap();assert!(!p.label().contains("u:p"));let mut s=connect(&p,"target.invalid",443,None).await.unwrap();assert_eq!(s.read_u8().await.unwrap(),b'X');task.await.unwrap();
 }
 #[tokio::test] async fn socks_fake_server_remote_dns(){
 let Some(l)=listener().await else{return};let a=l.local_addr().unwrap();let task=tokio::spawn(async move{let(mut s,_)=l.accept().await.unwrap();let mut g=[0;3];s.read_exact(&mut g).await.unwrap();assert_eq!(g,[5,1,0]);s.write_all(&[5,0]).await.unwrap();let mut h=[0;5];s.read_exact(&mut h).await.unwrap();assert_eq!(h,[5,1,0,3,14]);let mut target=[0;16];s.read_exact(&mut target).await.unwrap();assert_eq!(&target[..14],b"target.invalid");assert_eq!(&target[14..],&443u16.to_be_bytes());s.write_all(&[5,0,0,1,127,0,0,1,0,1]).await.unwrap();});connect(&parse(&a.to_string(),"SOCKS5").unwrap(),"target.invalid",443,None).await.unwrap();task.await.unwrap();
 }
}

pub async fn fetch(p:&ProxySnapshot,url:&str,family:Option<super::http::Family>)->Result<(super::http::Response,String),String>{
 super::http::fetch_effective(url,family,p).await
}

#[cfg(test)] mod selection_tests {
use super::*;
fn snapshot()->ProxySnapshot { ProxySnapshot{sources:Default::default(),wpad:false,enabled:false,pac:false,pac_url:String::new(),bypass:vec![],http_proxy:String::new(),https_proxy:String::new(),socks_proxy:String::new()} }
#[tokio::test] async fn no_proxy_protocol_bypass_and_redaction(){
 let mut p=snapshot();assert!(matches!(resolve(&p,"https://example.com/").await.unwrap()[0],Path::Direct));
 p.enabled=true;p.http_proxy="http://user:p%40ss@proxy.invalid:8123".into();p.https_proxy="secure.invalid:8443".into();
 let route=resolve(&p,"https://example.com/").await.unwrap();assert_eq!(route[0].label(),"effective(PROXY secure.invalid:8443)");
 let route=resolve(&p,"http://example.com/").await.unwrap();assert_eq!(route[0].label(),"effective(PROXY proxy.invalid:8123)");
 assert!(!route[0].label().contains("user"));p.bypass=vec![".example.com:443".into()];
 assert!(matches!(resolve(&p,"https://sub.example.com/").await.unwrap()[0],Path::Direct));
 assert!(!matches!(resolve(&p,"http://sub.example.com/").await.unwrap()[0],Path::Direct));
 p.bypass.clear();p.sources.insert("env.all".into(),"socks5h://all.invalid:1080".into());
 assert_eq!(resolve(&p,"https://example.com/").await.unwrap()[0].label(),"effective(SOCKS5 all.invalid:1080)");p.sources.clear();
 p.http_proxy.clear();p.https_proxy.clear();p.bypass.clear();p.socks_proxy="socks5h://s.invalid:1080".into();assert!(matches!(resolve(&p,"https://example.com/").await.unwrap()[0],Path::Socks(_)));
 p.socks_proxy.clear();assert!(resolve(&p,"https://example.com/").await.is_err());
 p.enabled=false;p.wpad=true;assert!(resolve(&p,"https://example.com/").await.is_err());
 assert_eq!(decode("p%40ss").unwrap(),"p@ss");assert_eq!(base64(b"u:p"),"dTpw");assert_eq!(base64(b"u:"),"dTo=");assert_eq!(base64(b"u"),"dQ==");
}
#[test] fn mac_system_proxy_addresses_respect_enable_flags(){
 let s="HTTPEnable : 1\nHTTPProxy : p.example\nHTTPPort : 8080\nHTTPSEnable : 0\nHTTPSProxy : stale.example\nHTTPSPort : 443\nSOCKSEnable : 1\nSOCKSProxy : ::1\nSOCKSPort : 1080";
 assert_eq!(crate::platform::parse::scutil_proxy_endpoint(s,"HTTP"),"p.example:8080");assert_eq!(crate::platform::parse::scutil_proxy_endpoint(s,"HTTPS"),"");assert_eq!(crate::platform::parse::scutil_proxy_endpoint(s,"SOCKS"),"[::1]:1080");
}
}
