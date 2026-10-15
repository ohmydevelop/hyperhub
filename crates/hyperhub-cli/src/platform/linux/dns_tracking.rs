use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

const QUERY_TTL: Duration = Duration::from_secs(60);
const MAX_QUERIES: usize = 4096;

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
struct Question {
    transaction: u16,
    hostname: String,
    kind: u16,
    class: u16,
}

fn question(packet: &[u8], response: bool) -> Option<Question> {
    if packet.len() < 12
        || (packet[2] & 0x80 != 0) != response
        || u16::from_be_bytes([packet[4], packet[5]]) != 1
    {
        return None;
    }
    let (hostname, end) = parse_dns_name(packet, 12)?;
    let tail = packet.get(end..end.checked_add(4)?)?;
    if hostname.is_empty() {
        return None;
    }
    Some(Question {
        transaction: u16::from_be_bytes([packet[0], packet[1]]),
        hostname,
        kind: u16::from_be_bytes([tail[0], tail[1]]),
        class: u16::from_be_bytes([tail[2], tail[3]]),
    })
}

#[derive(Default)]
pub(super) struct DnsTransactions {
    queries: HashMap<(u64, SocketAddr, Question), Instant>,
}

impl DnsTransactions {
    pub fn sent(&mut self, socket: u64, resolver: SocketAddr, packet: &[u8]) {
        let Some(question) = question(packet, false) else {
            return;
        };
        let now = Instant::now();
        self.queries
            .retain(|_, sent| now.duration_since(*sent) < QUERY_TTL);
        if self.queries.len() < MAX_QUERIES {
            self.queries.insert((socket, resolver, question), now);
        }
    }

    pub fn received(
        &mut self,
        socket: u64,
        resolver: Option<SocketAddr>,
        packet: &[u8],
    ) -> Option<String> {
        let question = question(packet, true)?;
        // Truncated or unsuccessful responses do not contain usable address evidence.
        if packet[2] & 2 != 0 || packet[3] & 15 != 0 {
            return None;
        }
        let now = Instant::now();
        let mut matching = self.queries.iter().filter(|((id, peer, q), sent)| {
            *id == socket
                && *q == question
                && resolver.is_none_or(|value| value == *peer)
                && now.duration_since(**sent) < QUERY_TTL
        });
        let key = matching.next()?.0.clone();
        if matching.next().is_some() {
            return None;
        }
        self.queries.remove(&key);
        Some(question.hostname)
    }

    pub fn has_queries(&self, socket: u64) -> bool {
        self.queries.keys().any(|(id, _, _)| *id == socket)
    }

    pub fn forget(&mut self, socket: u64) {
        self.queries.retain(|(id, _, _), _| *id != socket);
    }
}

#[cfg(test)]
pub(super) fn parse_dns_query(packet: &[u8]) -> Option<String> {
    if packet.len() < 12 || packet[2] & 0x80 != 0 || u16::from_be_bytes([packet[4], packet[5]]) == 0
    {
        return None;
    }
    let (hostname, _) = parse_dns_name(packet, 12)?;
    (!hostname.is_empty()).then_some(hostname)
}

pub(super) fn parse_dns_addresses(packet: &[u8]) -> Vec<IpAddr> {
    if packet.len() < 12 || packet[2] & 0x80 == 0 {
        return Vec::new();
    }
    let questions = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let answers = u16::from_be_bytes([packet[6], packet[7]]) as usize;
    let mut offset = 12usize;
    for _ in 0..questions {
        let Some((_, next)) = parse_dns_name(packet, offset) else {
            return Vec::new();
        };
        offset = next.saturating_add(4);
        if offset > packet.len() {
            return Vec::new();
        }
    }
    let mut addresses = Vec::new();
    for _ in 0..answers {
        let Some((_, next)) = parse_dns_name(packet, offset) else {
            break;
        };
        if next + 10 > packet.len() {
            break;
        }
        let record_type = u16::from_be_bytes([packet[next], packet[next + 1]]);
        let data_length = u16::from_be_bytes([packet[next + 8], packet[next + 9]]) as usize;
        let data = next + 10;
        if data + data_length > packet.len() {
            break;
        }
        match (record_type, data_length) {
            (1, 4) => addresses.push(IpAddr::V4(Ipv4Addr::new(
                packet[data],
                packet[data + 1],
                packet[data + 2],
                packet[data + 3],
            ))),
            (28, 16) => {
                if let Ok(bytes) = <[u8; 16]>::try_from(&packet[data..data + 16]) {
                    addresses.push(IpAddr::V6(Ipv6Addr::from(bytes)));
                }
            }
            _ => {}
        }
        offset = data + data_length;
    }
    addresses
}

fn parse_dns_name(packet: &[u8], start: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut offset = start;
    let mut next = None;
    let mut jumps = 0usize;
    loop {
        let length = *packet.get(offset)?;
        if length & 0xc0 == 0xc0 {
            let second = *packet.get(offset + 1)?;
            let pointer = (((length & 0x3f) as usize) << 8) | second as usize;
            next.get_or_insert(offset + 2);
            offset = pointer;
            jumps += 1;
            if jumps > 16 {
                return None;
            }
            continue;
        }
        offset += 1;
        if length == 0 {
            return Some((labels.join("."), next.unwrap_or(offset)));
        }
        if length > 63 {
            return None;
        }
        let end = offset.checked_add(length as usize)?;
        let label = std::str::from_utf8(packet.get(offset..end)?).ok()?;
        labels.push(label.to_ascii_lowercase());
        offset = end;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(name: &str, transaction: u16, kind: u16) -> Vec<u8> {
        let mut packet = vec![0; 12];
        packet[..2].copy_from_slice(&transaction.to_be_bytes());
        packet[2] = 1;
        packet[5] = 1;
        for label in name.split('.') {
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0);
        packet.extend_from_slice(&kind.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet
    }

    fn response(mut packet: Vec<u8>) -> Vec<u8> {
        packet[2] = 0x81;
        packet[3] = 0x80;
        packet
    }

    #[test]
    fn pipelined_responses_match_transactions_questions_and_resolvers() {
        let mut tracker = DnsTransactions::default();
        let resolver = "127.0.0.1:53".parse().unwrap();
        let first = query("first.test", 1, 1);
        let second = query("second.test", 2, 28);
        tracker.sent(7, resolver, &first);
        tracker.sent(7, resolver, &second);
        assert_eq!(
            tracker.received(7, Some(resolver), &response(query("first.test", 2, 1))),
            None
        );
        assert_eq!(
            tracker.received(
                7,
                Some("127.0.0.2:53".parse().unwrap()),
                &response(first.clone())
            ),
            None
        );
        assert_eq!(
            tracker.received(8, Some(resolver), &response(first.clone())),
            None
        );
        assert_eq!(
            tracker.received(7, Some(resolver), &response(second)),
            Some("second.test".into())
        );
        assert_eq!(
            tracker.received(7, Some(resolver), &response(first.clone())),
            Some("first.test".into())
        );
        assert_eq!(tracker.received(7, Some(resolver), &response(first)), None);
    }

    #[test]
    fn ambiguous_sources_expired_and_closed_queries_are_not_attributed() {
        let mut tracker = DnsTransactions::default();
        let packet = query("example.test", 3, 1);
        tracker.sent(1, "127.0.0.1:53".parse().unwrap(), &packet);
        tracker.sent(1, "127.0.0.2:53".parse().unwrap(), &packet);
        assert_eq!(tracker.received(1, None, &response(packet.clone())), None);
        for sent in tracker.queries.values_mut() {
            *sent = Instant::now() - QUERY_TTL;
        }
        assert_eq!(
            tracker.received(
                1,
                Some("127.0.0.1:53".parse().unwrap()),
                &response(packet.clone())
            ),
            None
        );
        tracker.sent(2, "127.0.0.1:53".parse().unwrap(), &packet);
        tracker.forget(2);
        assert!(!tracker.has_queries(2));
    }

    #[test]
    fn ipv6_answers_and_truncated_packets() {
        let mut packet = response(query("ipv6.test", 4, 28));
        packet[7] = 1;
        packet.extend_from_slice(&[0xc0, 0x0c, 0, 28, 0, 1, 0, 0, 0, 60, 0, 16]);
        packet.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        assert_eq!(
            parse_dns_addresses(&packet),
            vec![IpAddr::V6(Ipv6Addr::LOCALHOST)]
        );
        packet.pop();
        assert!(parse_dns_addresses(&packet).is_empty());
    }
}
