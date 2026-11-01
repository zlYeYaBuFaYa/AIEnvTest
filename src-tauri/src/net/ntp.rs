use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const NTP_UNIX_DELTA: f64 = 2_208_988_800.0;

fn now() -> Option<f64> {
    Some(SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs_f64() + NTP_UNIX_DELTA)
}

fn timestamp(bytes: &[u8]) -> f64 {
    u32::from_be_bytes(bytes[..4].try_into().unwrap()) as f64
        + u32::from_be_bytes(bytes[4..8].try_into().unwrap()) as f64 / 4_294_967_296.0
}

fn validate(
    packet: &[u8], source: SocketAddr, server: SocketAddr,
    nonce: &[u8; 8], t1: f64, t4: f64,
) -> Option<i64> {
    if packet.len() < 48 || source != server {
        return None;
    }
    let leap = packet[0] >> 6;
    let version = (packet[0] >> 3) & 7;
    let mode = packet[0] & 7;
    if leap == 3 || !matches!(version, 3 | 4) || mode != 4
        || !(1..=15).contains(&packet[1]) || &packet[24..32] != nonce
    {
        return None;
    }
    let t2 = timestamp(&packet[32..40]);
    let t3 = timestamp(&packet[40..48]);
    if t2 == 0.0 || t3 == 0.0 || t3 < t2 {
        return None;
    }
    Some((((t2 - t1) + (t3 - t4)) / 2.0 * 1000.0).round() as i64)
}

pub fn offset_millis() -> Option<i64> {
    // Query all sources, even when the first source returns a valid reply.
    let offsets: Vec<_> = [
        "time.cloudflare.com:123", "time.google.com:123", "pool.ntp.org:123",
    ].iter().filter_map(|server| query(server)).collect();
    if offsets.is_empty() {
        None
    } else {
        Some(offsets.iter().sum::<i64>() / offsets.len() as i64)
    }
}

fn query(server: &str) -> Option<i64> {
    let server = server.to_socket_addrs().ok()?.find(|address| address.is_ipv4())?;
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.set_read_timeout(Some(Duration::from_secs(3))).ok()?;
    socket.connect(server).ok()?;
    let mut nonce = [0; 8];
    getrandom::fill(&mut nonce).ok()?;
    let mut request = [0; 48];
    request[0] = 0x23; // LI=0, version=4, client mode.
    request[40..48].copy_from_slice(&nonce);
    // The randomized wire timestamp associates the response with this request;
    // the actual local send/receive times supply t1/t4 in the offset formula.
    let t1 = now()?;
    socket.send(&request).ok()?;
    let mut buffer = [0; 512];
    let (received, source) = socket.recv_from(&mut buffer).ok()?;
    let t4 = now()?;
    validate(&buffer[..received], source, server, &nonce, t1, t4)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reply() -> [u8; 48] {
        let mut packet = [0; 48];
        packet[0] = 0x24;
        packet[1] = 1;
        packet[24..32].copy_from_slice(&[7; 8]);
        packet[32..36].copy_from_slice(&102u32.to_be_bytes());
        packet[40..44].copy_from_slice(&104u32.to_be_bytes());
        packet
    }

    fn check(packet: &[u8]) -> Option<i64> {
        let server = "127.0.0.1:123".parse().unwrap();
        validate(packet, server, server, &[7; 8], 100.0, 108.0)
    }

    #[test]
    fn four_timestamp_formula_and_supported_versions() {
        let mut packet = reply();
        assert_eq!(check(&packet), Some(-1000));
        packet[0] = 0x1c;
        assert_eq!(check(&packet), Some(-1000));
    }

    #[test]
    fn rejects_short_packet_and_wrong_source() {
        let packet = reply();
        for length in 0..48 { assert!(check(&packet[..length]).is_none()); }
        let server = "127.0.0.1:123".parse().unwrap();
        for source in ["127.0.0.2:123", "127.0.0.1:124"] {
            assert!(validate(&packet, source.parse().unwrap(), server, &[7; 8], 100.0, 108.0).is_none());
        }
    }

    #[test]
    fn rejects_unsynchronized_server() {
        let mut packet = reply(); packet[0] = 0xe4;
        assert!(check(&packet).is_none());
    }

    #[test]
    fn rejects_non_server_modes() {
        for mode in [0, 1, 2, 3, 5, 6, 7] {
            let mut packet = reply(); packet[0] = 0x20 | mode;
            assert!(check(&packet).is_none());
        }
    }

    #[test]
    fn rejects_invalid_strata() {
        for stratum in [0, 16, 255] {
            let mut packet = reply(); packet[1] = stratum;
            assert!(check(&packet).is_none());
        }
    }

    #[test]
    fn rejects_unsupported_versions() {
        for version in [0, 1, 2, 5, 6, 7] {
            let mut packet = reply(); packet[0] = (version << 3) | 4;
            assert!(check(&packet).is_none());
        }
    }

    #[test]
    fn rejects_wrong_originate_timestamp() {
        let mut packet = reply(); packet[24] ^= 1;
        assert!(check(&packet).is_none());
    }
}
