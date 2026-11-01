use std::net::UdpSocket;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const NTP_UNIX_DELTA: i64 = 2_208_988_800;

pub fn offset_millis() -> Option<i64> {
    for server in ["time.cloudflare.com:123", "time.google.com:123", "pool.ntp.org:123"] {
        if let Some(offset) = query(server) {
            return Some(offset);
        }
    }
    None
}

fn query(server: &str) -> Option<i64> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.set_read_timeout(Some(Duration::from_secs(3))).ok()?;
    let mut packet = [0u8; 48];
    packet[0] = 0x1b;
    let sent = SystemTime::now();
    socket.send_to(&packet, server).ok()?;
    let mut buf = [0u8; 48];
    socket.recv_from(&mut buf).ok()?;
    let got = SystemTime::now();
    if buf.len() < 48 {
        return None;
    }
    let secs = u32::from_be_bytes([buf[40], buf[41], buf[42], buf[43]]) as i64;
    let frac = u32::from_be_bytes([buf[44], buf[45], buf[46], buf[47]]) as i64;
    if secs <= NTP_UNIX_DELTA {
        return None;
    }
    let ntp_ms = (secs - NTP_UNIX_DELTA) * 1000 + (frac * 1000) / 0x1_0000_0000;
    let local_ms = got.duration_since(UNIX_EPOCH).ok()?.as_millis() as i64;
    let rtt = got.duration_since(sent).ok()?.as_millis() as i64;
    Some(ntp_ms - (local_ms - rtt / 2))
}
