use std::fs;
use std::io;
use std::path::Path;

const SYSCTL_RESERVED_PORTS: &str = "/proc/sys/net/ipv4/ip_local_reserved_ports";

#[derive(Debug, thiserror::Error)]
pub enum PortReservationError {
    #[error("failed to access NAT reserved port state: {0}")]
    Io(#[from] io::Error),
    #[error("invalid ip_local_reserved_ports value {0:?}")]
    InvalidReservedPorts(String),
    #[error("NAT port range {start}-{end} is not reserved in ip_local_reserved_ports")]
    MissingReservation { start: u16, end: u16 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PortRange {
    start: u16,
    end: u16,
}

impl PortRange {
    fn new(start: u16, end: u16) -> Result<Self, PortReservationError> {
        if start == 0 || start > end {
            return Err(PortReservationError::InvalidReservedPorts(format!(
                "{start}-{end}"
            )));
        }
        Ok(Self { start, end })
    }
}

pub fn ensure_nat_ports_reserved(
    ports: std::ops::RangeInclusive<u16>,
) -> Result<(), PortReservationError> {
    ensure_nat_ports_reserved_at(ports, Path::new(SYSCTL_RESERVED_PORTS))
}

fn ensure_nat_ports_reserved_at(
    ports: std::ops::RangeInclusive<u16>,
    path: &Path,
) -> Result<(), PortReservationError> {
    let required = PortRange::new(*ports.start(), *ports.end())?;
    let current = read_reserved_ranges(path)?;
    if range_contains(&current, required) {
        Ok(())
    } else {
        Err(PortReservationError::MissingReservation {
            start: required.start,
            end: required.end,
        })
    }
}

fn read_reserved_ranges(path: &Path) -> Result<Vec<PortRange>, PortReservationError> {
    let text = fs::read_to_string(path)?;
    parse_reserved_ranges(&text)
}

fn parse_reserved_ranges(text: &str) -> Result<Vec<PortRange>, PortReservationError> {
    let mut ranges = Vec::new();
    for term in text.trim().split(',').map(str::trim) {
        if term.is_empty() {
            continue;
        }
        let (start, end) = if let Some((start, end)) = term.split_once('-') {
            (parse_port(start, term)?, parse_port(end, term)?)
        } else {
            let port = parse_port(term, term)?;
            (port, port)
        };
        ranges.push(PortRange::new(start, end)?);
    }
    Ok(normalize_ranges(ranges))
}

fn parse_port(value: &str, term: &str) -> Result<u16, PortReservationError> {
    value
        .parse()
        .map_err(|_| PortReservationError::InvalidReservedPorts(term.to_string()))
}

#[cfg(test)]
fn format_reserved_ranges(ranges: &[PortRange]) -> String {
    normalize_ranges(ranges.to_vec())
        .iter()
        .map(|range| {
            if range.start == range.end {
                range.start.to_string()
            } else {
                format!("{}-{}", range.start, range.end)
            }
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn normalize_ranges(mut ranges: Vec<PortRange>) -> Vec<PortRange> {
    ranges.sort_by_key(|range| range.start);
    let mut merged: Vec<PortRange> = Vec::new();
    for range in ranges {
        match merged.last_mut() {
            Some(last) if u32::from(range.start) <= u32::from(last.end) + 1 => {
                last.end = last.end.max(range.end);
            }
            _ => merged.push(range),
        }
    }
    merged
}

fn range_contains(ranges: &[PortRange], required: PortRange) -> bool {
    ranges
        .iter()
        .any(|range| range.start <= required.start && range.end >= required.end)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn range(start: u16, end: u16) -> PortRange {
        PortRange { start, end }
    }

    fn temp_sysctl(contents: &str) -> (PathBuf, PathBuf) {
        let root = std::env::temp_dir().join(format!(
            "new-proxy-port-reservation-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        fs::create_dir_all(&root).unwrap();
        let path = root.join("ip_local_reserved_ports");
        fs::write(&path, contents).unwrap();
        (root, path)
    }

    #[test]
    fn v1_unit_port_reservation_parses_merges_and_formats_ranges() {
        let ranges = parse_reserved_ranges("40010,40000-40005,40006-40009,50000\n").unwrap();
        assert_eq!(ranges, vec![range(40000, 40010), range(50000, 50000)]);
        assert_eq!(format_reserved_ranges(&ranges), "40000-40010,50000");
        assert!(parse_reserved_ranges("41000-40000").is_err());
    }

    #[test]
    fn v1_unit_port_reservation_no_mode_requires_complete_reserved_range() {
        let (root, path) = temp_sysctl("40000-40010\n");
        ensure_nat_ports_reserved_at(40000..=40010, &path).unwrap();
        assert!(matches!(
            ensure_nat_ports_reserved_at(40000..=40020, &path),
            Err(PortReservationError::MissingReservation { .. })
        ));
        fs::remove_dir_all(root).unwrap();
    }
}
