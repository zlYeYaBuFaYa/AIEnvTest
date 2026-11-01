use std::net::{IpAddr,Ipv4Addr,Ipv6Addr};
use tokio::{net::UdpSocket,time::{timeout,Duration}};
const COOKIE:[u8;4]=[0x21,0x12,0xa4,0x42];
#[derive(Debug)] pub enum StunResult { Mapped(IpAddr), Blocked, Unknown(String) }
/// Validate binding success, transaction association, padded attributes and XOR address.
pub fn parse_stun(b:&[u8],tx:&[u8;12])->Result<IpAddr,String>{
 if b.len()<20||b[..2]!=[1,1]||b[4..8]!=COOKIE||&b[8..20]!=tx{return Err("invalid STUN header".into())}
 let len=u16::from_be_bytes([b[2],b[3]]) as usize;if len%4!=0||b.len()!=20+len{return Err("invalid STUN length".into())}
 let mut i=20;let mut mapped=None;
 while i<b.len(){if i+4>b.len(){return Err("truncated STUN attribute".into())}let kind=u16::from_be_bytes([b[i],b[i+1]]);let n=u16::from_be_bytes([b[i+2],b[i+3]]) as usize;i+=4;if i+n>b.len(){return Err("truncated STUN value".into())}
 if kind==0x20{let a=&b[i..i+n];if n<4||a[0]!=0{return Err("invalid XOR address".into())}mapped=Some(match (a[1],n){(1,8)=>IpAddr::V4(Ipv4Addr::new(a[4]^COOKIE[0],a[5]^COOKIE[1],a[6]^COOKIE[2],a[7]^COOKIE[3])),(2,20)=>{let mut ip=[0;16];for j in 0..16{ip[j]=a[j+4]^if j<4{COOKIE[j]}else{tx[j-4]};}IpAddr::V6(Ipv6Addr::from(ip))},_=>return Err("invalid XOR address family/length".into())});}
 i+=(n+3)&!3;if i>b.len(){return Err("invalid STUN padding".into())}
 }mapped.ok_or("no XOR-MAPPED-ADDRESS".into())
}
pub async fn stun(server:&str)->StunResult{
 let run=async{
 let addr=tokio::net::lookup_host(server).await.map_err(|e|e.to_string())?.find(|a|a.is_ipv4()).ok_or("no IPv4 STUN server")?;
 let s=UdpSocket::bind("0.0.0.0:0").await.map_err(|e|e.to_string())?;s.connect(addr).await.map_err(|e|e.to_string())?;
 let mut tx=[0;12];getrandom::fill(&mut tx).map_err(|_|"random source unavailable")?;
 let mut req=vec![0,1,0,0];req.extend(COOKIE);req.extend(tx);s.send(&req).await.map_err(|e|e.to_string())?;
 let mut b=[0;2048];match s.recv(&mut b).await {Ok(n)=>parse_stun(&b[..n],&tx).map(StunResult::Mapped),Err(e) if e.kind()==std::io::ErrorKind::PermissionDenied=>Ok(StunResult::Blocked),Err(e)=>Err(e.to_string())}
 };
 match timeout(Duration::from_secs(4),run).await{Ok(Ok(r))=>r,Ok(Err(e))=>StunResult::Unknown(e),Err(_)=>StunResult::Unknown("STUN timeout; blocking not proven".into())}
}
/// Version negotiation echoes our source/destination connection IDs in reverse.
pub fn parse_vn(b:&[u8],dcid:&[u8],scid:&[u8])->bool{
 if b.len()<7||b[0]&0x80==0||b[1..5]!=[0,0,0,0]{return false}
 let d=b[5] as usize;if d>20||b.len()<7+d||b.get(6..6+d)!=Some(scid){return false}
 let n=b[6+d] as usize;let start=7+d;if n>20||b.get(start..start+n)!=Some(dcid){return false}let versions=&b[start+n..];
 !versions.is_empty()&&versions.len()%4==0&&versions.chunks_exact(4).all(|v|v!=[0,0,0,0]&&v!=[10,10,10,10])
}
pub async fn quic()->Result<bool,String>{
 let run=async{
 let addr=tokio::net::lookup_host(("www.google.com",443)).await.map_err(|e|e.to_string())?.find(|a|a.is_ipv4()).ok_or("no QUIC endpoint address")?;
 let s=UdpSocket::bind("0.0.0.0:0").await.map_err(|e|e.to_string())?;s.connect(addr).await.map_err(|e|e.to_string())?;
 let mut ids=[0;16];getrandom::fill(&mut ids).map_err(|_|"random source unavailable")?;let(dcid,scid)=ids.split_at(8);
 // A v1 Initial layout with a reserved unsupported version solicits VN without encryption.
 let mut req=vec![0xc0,10,10,10,10,8];req.extend(dcid);req.push(8);req.extend(scid);req.extend([0,0x44,0x96]);req.resize(1200,0);
 s.send(&req).await.map_err(|e|e.to_string())?;let mut b=[0;2048];let n=s.recv(&mut b).await.map_err(|e|e.to_string())?;
 if parse_vn(&b[..n],dcid,scid){Ok(true)}else{Err("unassociated or invalid QUIC response".into())}
 };
 timeout(Duration::from_secs(4),run).await.map_err(|_|"QUIC timeout; no response observed".to_string())?
}
#[cfg(test)] mod tests{
use super::*;
#[test] fn xor_mapped_v4_v6_and_invalid_packets(){let tx=[3;12];for ip in ["203.0.113.7".parse::<IpAddr>().unwrap(),"2001:db8::123".parse().unwrap()]{let octets=match ip{IpAddr::V4(a)=>a.octets().to_vec(),IpAddr::V6(a)=>a.octets().to_vec()};let n=octets.len()+4;let mut b=vec![1,1,0,(n+4) as u8];b.extend(COOKIE);b.extend(tx);b.extend([0,0x20,0,n as u8,0,if n==8{1}else{2},0,0]);for(j,v)in octets.iter().enumerate(){b.push(v^if j<4{COOKIE[j]}else{tx[j-4]})}assert_eq!(parse_stun(&b,&tx).unwrap(),ip);assert!(parse_stun(&b,&[4;12]).is_err());assert!(parse_stun(&b[..b.len()-1],&tx).is_err());b[0]=0;assert!(parse_stun(&b,&tx).is_err());}}
#[test] fn version_negotiation_requires_connection_ids_and_versions(){let b=[0x80,0,0,0,0,2,3,4,2,1,2,0,0,0,1];assert!(parse_vn(&b,&[1,2],&[3,4]));assert!(!parse_vn(&b,&[3,4],&[1,2]));for n in 0..b.len(){assert!(!parse_vn(&b[..n],&[1,2],&[3,4]));}let mut bad=b;bad[4]=1;assert!(!parse_vn(&bad,&[1,2],&[3,4]));}
}
