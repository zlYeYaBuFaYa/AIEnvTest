use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

const QTYPE_A: u16 = 1;
const QTYPE_AAAA: u16 = 28;
const QTYPE_TXT: u16 = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    A(String),
    Aaaa(String),
    Txt(String),
}

pub fn query(server: &str, name: &str, qtype: u16) -> Result<Vec<Answer>, String> {
    let addr = server_addr(server)?;
    let socket = UdpSocket::bind(if addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" })
        .or_else(|_| UdpSocket::bind("0.0.0.0:0"))
        .map_err(|err| err.to_string())?;
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .map_err(|err| err.to_string())?;
    let packet = build_query(name, qtype);
    socket.send_to(&packet, addr).map_err(|err| err.to_string())?;
    let mut buf = [0u8; 2048];
    let (len, _) = socket.recv_from(&mut buf).map_err(|err| err.to_string())?;
    parse_response(&buf[..len])
}

pub fn query_txt(server: &str, name: &str) -> Result<Vec<String>, String> {
    Ok(query(server, name, QTYPE_TXT)?
        .into_iter()
        .filter_map(|answer| match answer {
            Answer::Txt(text) => Some(text),
            _ => None,
        })
        .collect())
}

pub fn query_a(server: &str, name: &str) -> Result<Vec<String>, String> {
    Ok(query(server, name, QTYPE_A)?
        .into_iter()
        .filter_map(|answer| match answer {
            Answer::A(ip) => Some(ip),
            _ => None,
        })
        .collect())
}

pub fn blast(servers: &[String], names: &[String]) {
    for server in servers {
        let Ok(addr) = server_addr(server) else { continue };
        let Ok(socket) = UdpSocket::bind(if addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" })
            .or_else(|_| UdpSocket::bind("0.0.0.0:0"))
        else {
            continue;
        };
        let _ = socket.set_write_timeout(Some(Duration::from_secs(2)));
        for name in names {
            for qtype in [QTYPE_A, QTYPE_AAAA] {
                let packet = build_query(name, qtype);
                let _ = socket.send_to(&packet, addr);
            }
        }
    }
}

fn server_addr(server: &str) -> Result<SocketAddr, String> {
    let server = server.trim().trim_matches(|c| c == '[' || c == ']');
    if server.parse::<std::net::Ipv4Addr>().is_ok() {
        return format!("{server}:53").parse().map_err(|err: std::net::AddrParseError| err.to_string());
    }
    if server.parse::<std::net::Ipv6Addr>().is_ok() {
        return format!("[{server}]:53").parse().map_err(|err: std::net::AddrParseError| err.to_string());
    }
    Err(format!("not an IP address: {server}"))
}

fn build_query(name: &str, qtype: u16) -> Vec<u8> {
    let mut packet = Vec::new();
    let id = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(1)
        & 0xffff) as u16;
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&0x0100u16.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    write_name(&mut packet, name);
    packet.extend_from_slice(&qtype.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    packet
}

fn write_name(packet: &mut Vec<u8>, name: &str) {
    for label in name.split('.').filter(|label| !label.is_empty()) {
        let bytes = label.as_bytes();
        packet.push(bytes.len().min(63) as u8);
        packet.extend_from_slice(&bytes[..bytes.len().min(63)]);
    }
    packet.push(0);
}

pub fn parse_response(buf: &[u8]) -> Result<Vec<Answer>, String> {
    if buf.len() < 12 {
        return Err("short dns message".into());
    }
    let qd = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let an = u16::from_be_bytes([buf[6], buf[7]]) as usize;
    let mut pos = 12;
    for _ in 0..qd {
        let (_, next) = read_name(buf, pos, 0)?;
        pos = next + 4;
        if pos > buf.len() {
            return Err("question overrun".into());
        }
    }
    let mut answers = Vec::new();
    for _ in 0..an {
        let (_, next) = read_name(buf, pos, 0)?;
        pos = next;
        if pos + 10 > buf.len() {
            break;
        }
        let qtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let rdlength = u16::from_be_bytes([buf[pos + 8], buf[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlength > buf.len() {
            break;
        }
        let rdata = &buf[pos..pos + rdlength];
        match qtype {
            QTYPE_A if rdata.len() == 4 => {
                answers.push(Answer::A(format!("{}.{}.{}.{}", rdata[0], rdata[1], rdata[2], rdata[3])));
            }
            QTYPE_AAAA if rdata.len() == 16 => {
                let mut segments = [0u8; 16];
                segments.copy_from_slice(rdata);
                let ip = std::net::Ipv6Addr::from(segments);
                answers.push(Answer::Aaaa(ip.to_string()));
            }
            QTYPE_TXT => {
                let mut text = String::new();
                let mut cursor = 0;
                while cursor < rdata.len() {
                    let len = rdata[cursor] as usize;
                    cursor += 1;
                    if cursor + len > rdata.len() {
                        break;
                    }
                    text.push_str(&String::from_utf8_lossy(&rdata[cursor..cursor + len]));
                    cursor += len;
                }
                let text = text.trim_matches('"').trim().to_string();
                if !text.is_empty() {
                    answers.push(Answer::Txt(text));
                }
            }
            _ => {}
        }
        pos += rdlength;
    }
    Ok(answers)
}

fn read_name(buf: &[u8], mut pos: usize, depth: usize) -> Result<(String, usize), String> {
    if depth > 8 {
        return Err("dns name loop".into());
    }
    let mut labels = Vec::new();
    let mut end = None;
    while pos < buf.len() {
        let len = buf[pos];
        if len == 0 {
            pos += 1;
            break;
        }
        if len & 0xc0 == 0xc0 {
            if pos + 1 >= buf.len() {
                return Err("bad pointer".into());
            }
            let ptr = (((len as usize) & 0x3f) << 8) | buf[pos + 1] as usize;
            let (name, _) = read_name(buf, ptr, depth + 1)?;
            if !name.is_empty() {
                labels.push(name);
            }
            pos += 2;
            end = Some(pos);
            break;
        }
        pos += 1;
        if pos + len as usize > buf.len() {
            return Err("label overrun".into());
        }
        labels.push(String::from_utf8_lossy(&buf[pos..pos + len as usize]).to_string());
        pos += len as usize;
    }
    Ok((labels.join("."), end.unwrap_or(pos)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_compressed_a_record() {
        let mut packet = Vec::new();
        packet.extend_from_slice(&0x1234u16.to_be_bytes());
        packet.extend_from_slice(&0x8180u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        write_name(&mut packet, "example.com");
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&0xc00cu16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&60u32.to_be_bytes());
        packet.extend_from_slice(&4u16.to_be_bytes());
        packet.extend_from_slice(&[1, 2, 3, 4]);
        let answers = parse_response(&packet).unwrap();
        assert_eq!(answers, vec![Answer::A("1.2.3.4".into())]);
    }

    #[test]
    fn parses_txt_character_strings() {
        let mut packet = Vec::new();
        packet.extend_from_slice(&[0, 1, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);
        write_name(&mut packet, "o-o.myaddr.l.google.com");
        packet.extend_from_slice(&16u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&0xc00cu16.to_be_bytes());
        packet.extend_from_slice(&16u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&1u32.to_be_bytes());
        let text = b"edns0-client-subnet 203.0.113.0/24";
        packet.extend_from_slice(&(text.len() as u16 + 1).to_be_bytes());
        packet.push(text.len() as u8);
        packet.extend_from_slice(text);
        let answers = parse_response(&packet).unwrap();
        assert_eq!(answers, vec![Answer::Txt("edns0-client-subnet 203.0.113.0/24".into())]);
    }
}
