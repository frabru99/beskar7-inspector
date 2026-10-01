//! Phase-1 network bring-up (decision D-013).
//!
//! The inspector must reach the callback (`beskar7.api`) to POST its report and
//! GET bootstrap data, but it boots with the provisioning NIC down and
//! unaddressed: the kernel's `ip=dhcp` autoconfig cannot help because the NIC
//! driver is a module loaded by the inspector *after* boot (D-012). So the
//! inspector configures networking itself, natively — no `dhclient`/`udhcpc`, no
//! shell, consistent with the single-binary-userspace principle.
//!
//! [`bring_up_provisioning_network`] is the one entry point `run()` calls,
//! immediately after [`crate::modules::load_drivers`] and before the callback
//! client. It:
//!   1. selects the provisioning NIC — by the `BOOTIF=<mac>` cmdline param (the
//!      pxelinux/iPXE convention: the NIC that just PXE-booted), the single
//!      physical NIC when only one is present, or — when several are present and
//!      none is pinned — by DHCP-racing all of them and taking the winner;
//!   2. brings the link up (RTNETLINK `RTM_NEWLINK`);
//!   3. runs a one-shot DHCP exchange (DISCOVER/OFFER/REQUEST/ACK), hand-rolled —
//!      the inspector runs once then reboots, so there is no lease renewal;
//!   4. assigns the leased address + default route (RTNETLINK `RTM_NEWADDR` /
//!      `RTM_NEWROUTE`).
//!
//! ## Multi-NIC (D-013 breadth)
//! When several NICs are present and `BOOTIF` does not pin one, the inspector
//! brings every candidate link up, runs DHCP on each concurrently (each socket is
//! `SO_BINDTODEVICE`-scoped, so the exchanges do not cross links), and applies the
//! winner — preferring a lease that carries a default gateway (that network has a
//! route toward `beskar7.api`), then the lowest-sorted interface name. Only the
//! winner is left addressed; the losing links are brought back down. `BOOTIF`
//! remains the deterministic pin and the recommended path; the race is the
//! fallback for hosts whose first-stage iPXE does not supply `?mac=`.
//!
//! ## DNS (D-013 breadth)
//! The DHCP option-6 servers are written to `/etc/resolv.conf`
//! ([`write_resolv_conf`]) so a hostname `beskar7.api` resolves. An IP-literal
//! `beskar7.api` remains the recommended form (contract §8.2) and needs no
//! resolver, so the write is best-effort — a failure does not abort bring-up.
//!
//! ## Static config (D-013 breadth)
//! When `beskar7.ip` is set, the inspector skips DHCP and configures the pinned
//! NIC (`BOOTIF` or the single interface) statically from the kernel-`ip=` subset
//! `<ip>::<gw>:<mask>[:<dns>]` — for DHCP-less / VLAN-pinned provisioning
//! networks. A multi-NIC host with `beskar7.ip` and no `BOOTIF` is rejected
//! (nothing disambiguates which NIC gets the address).
//!
//! ## Remaining scope
//! VLAN tagging remains a deliberate D-013 follow-up; the single entry point is
//! shaped so it lands additively.
//!
//! ## Secret hygiene (§9)
//! No secret passes through here — DHCP is unauthenticated by design and the
//! provisioning L2 is semi-trusted (the join secret is protected by the
//! verified-TLS `/bootstrap` GET, not the network). [`NetError`] carries only
//! interface names, IPs, and errnos, all non-secret.

mod dhcp;
mod netlink;

use std::net::Ipv4Addr;
use std::path::Path;

use nix::errno::Errno;

use crate::cmdline::BootParams;
use crate::probe::read_trimmed;
use dhcp::Lease;

/// `/sys/class/net` — one entry per network interface.
const SYSFS_NET: &str = "/sys/class/net";

/// The resolved network configuration applied to the provisioning interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetConfig {
    /// The provisioning interface kernel name (e.g. `eth0`, `ens3`).
    pub iface: String,
    /// The leased IPv4 address.
    pub ip: Ipv4Addr,
    /// The subnet prefix length (e.g. 24 for a `/24`).
    pub prefix_len: u8,
    /// The default gateway (DHCP option 3), if the lease supplied one.
    pub gateway: Option<Ipv4Addr>,
    /// DNS servers (DHCP option 6), written to `/etc/resolv.conf` by
    /// [`write_resolv_conf`] so a hostname `beskar7.api` resolves. The recommended
    /// IP-literal `beskar7.api` (§8.2) does not need them.
    pub dns: Vec<Ipv4Addr>,
}

/// A static network configuration from `beskar7.ip` (D-013), for DHCP-less /
/// VLAN-pinned provisioning networks. Parsed from the kernel `ip=` subset
/// `<ip>::<gw>:<mask>[:<dns>]`: client IP, an (ignored) server-IP field, an
/// optional gateway, a netmask, and an optional DNS server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticIp {
    /// The client address to assign.
    pub ip: Ipv4Addr,
    /// The default gateway, if the field was non-empty.
    pub gateway: Option<Ipv4Addr>,
    /// The subnet prefix length, parsed from the `<mask>` field.
    pub prefix_len: u8,
    /// DNS servers (zero or one in the kernel-`ip=` subset), written to
    /// `/etc/resolv.conf` like a DHCP lease's.
    pub dns: Vec<Ipv4Addr>,
}

impl StaticIp {
    /// Parse the `beskar7.ip` value (kernel `ip=` subset `<ip>::<gw>:<mask>[:<dns>]`).
    /// Returns `None` on any malformed field, an out-of-range prefix, or the wrong
    /// number of colon-separated fields — the caller surfaces that as a loud
    /// cmdline error rather than silently falling back to DHCP.
    pub fn parse(value: &str) -> Option<Self> {
        let f: Vec<&str> = value.split(':').collect();
        // <ip> : <server> : <gw> : <mask> [: <dns>]  — 4 or 5 fields.
        if f.len() < 4 || f.len() > 5 {
            return None;
        }
        let ip: Ipv4Addr = f[0].parse().ok()?;
        // f[1] is the kernel `ip=` server-IP field — unused here.
        let gateway = if f[2].is_empty() {
            None
        } else {
            Some(f[2].parse().ok()?)
        };
        let prefix_len = parse_mask(f[3])?;
        let dns = match f.get(4) {
            Some(d) if !d.is_empty() => vec![d.parse().ok()?],
            _ => Vec::new(),
        };
        Some(StaticIp {
            ip,
            gateway,
            prefix_len,
            dns,
        })
    }
}

/// Parse the `<mask>` field of `beskar7.ip`: either a dotted netmask
/// (`255.255.255.0`) or a bare CIDR prefix length (`24`).
fn parse_mask(s: &str) -> Option<u8> {
    if let Ok(mask) = s.parse::<Ipv4Addr>() {
        Some(mask_to_prefix_len(mask))
    } else {
        s.parse::<u8>().ok().filter(|&p| p <= 32)
    }
}

/// Errors from network bring-up. All variants carry only non-secret material
/// (interface names, IPs, errnos), so logging a `NetError` is safe (§9).
#[derive(Debug, thiserror::Error)]
pub enum NetError {
    /// No usable (non-loopback) network interface was found.
    #[error("no network interface found")]
    NoInterface,
    /// `BOOTIF` was given but no interface's MAC matched it.
    #[error("BOOTIF MAC {0} matched no interface")]
    BootifNoMatch(String),
    /// `beskar7.ip` (static config) was set on a multi-NIC host with no `BOOTIF`,
    /// so there is no way to know which interface the static address belongs to.
    #[error("static beskar7.ip with multiple NICs and no BOOTIF to pin one")]
    StaticAmbiguous,
    /// A required `/sys/class/net/<iface>/...` attribute could not be read.
    #[error("reading {0}")]
    SysRead(String),
    /// A socket operation (open/bind/setsockopt/send/recv) failed.
    #[error("DHCP socket: {0}")]
    Socket(#[source] Errno),
    /// No DHCP OFFER/ACK arrived within the retry budget.
    #[error("DHCP timed out (no lease offered)")]
    DhcpTimeout,
    /// A DHCP reply was malformed (bad cookie, truncated, no message-type).
    #[error("malformed DHCP reply")]
    DhcpMalformed,
    /// A netlink configuration message (link/addr/route) failed.
    #[error("netlink {op}: {source}")]
    Netlink {
        /// Which configuration step failed.
        op: &'static str,
        /// The netlink/errno failure.
        #[source]
        source: Errno,
    },
}

/// Outcome of NIC pre-selection over `/sys/class/net`.
enum NicSelection {
    /// Exactly one interface to use: a `BOOTIF` match, or the only NIC present.
    Pinned(String),
    /// No `BOOTIF` and several NICs — bring them all up and DHCP-race them.
    Race(Vec<String>),
}

/// Bring up the provisioning network and return the applied configuration
/// (D-013). Live entry point; the policy pieces it calls (`select_nics`,
/// `choose_lease`) are pure and unit-tested.
pub fn bring_up_provisioning_network(params: &BootParams) -> Result<NetConfig, NetError> {
    let selection = select_nics(Path::new(SYSFS_NET), params.bootif.as_deref())?;
    match &params.ip {
        // Static config (`beskar7.ip`, D-013): no DHCP. It needs a single pinned
        // interface — `BOOTIF` or a lone NIC — because, without a lease, there is
        // nothing to disambiguate which of several NICs the address belongs to.
        Some(static_ip) => match selection {
            NicSelection::Pinned(iface) => bring_up_static(&iface, static_ip),
            NicSelection::Race(_) => Err(NetError::StaticAmbiguous),
        },
        None => match selection {
            NicSelection::Pinned(iface) => bring_up_one(&iface),
            NicSelection::Race(ifaces) => bring_up_race(&ifaces),
        },
    }
}

/// Configure a single, already-chosen interface: bring the link up, DHCP, apply
/// the lease. The BOOTIF / single-NIC path.
fn bring_up_one(iface: &str) -> Result<NetConfig, NetError> {
    let ifindex = read_ifindex(iface)?;
    let mac = read_mac(iface)?;
    let lease = dhcp_link(iface, ifindex, mac)?;
    apply_lease(ifindex, &lease)?;
    Ok(net_config(iface, lease))
}

/// Configure a pinned interface from a static `beskar7.ip` spec — no DHCP
/// (D-013). Any DNS servers ride `NetConfig.dns` to the `/etc/resolv.conf` writer,
/// the same path the DHCP lease uses.
fn bring_up_static(iface: &str, s: &StaticIp) -> Result<NetConfig, NetError> {
    let ifindex = read_ifindex(iface)?;
    netlink::link_up(ifindex).map_err(|source| NetError::Netlink {
        op: "link up",
        source,
    })?;
    wait_for_link(iface);
    netlink::add_address(ifindex, s.ip, s.prefix_len).map_err(|source| NetError::Netlink {
        op: "add address",
        source,
    })?;
    if let Some(gw) = s.gateway {
        netlink::add_default_route(ifindex, gw).map_err(|source| NetError::Netlink {
            op: "add default route",
            source,
        })?;
    }
    Ok(NetConfig {
        iface: iface.to_string(),
        ip: s.ip,
        prefix_len: s.prefix_len,
        gateway: s.gateway,
        dns: s.dns.clone(),
    })
}

/// Bring every candidate link up, DHCP each concurrently, and apply the winning
/// lease — leaving exactly one interface configured (the losers are brought back
/// down). The winner is chosen deterministically by [`choose_lease`].
fn bring_up_race(ifaces: &[String]) -> Result<NetConfig, NetError> {
    // Resolve ifindex + MAC up front; skip any candidate whose sysfs we can't
    // read rather than failing the whole race for one bad NIC.
    let cands: Vec<(String, u32, [u8; 6])> = ifaces
        .iter()
        .filter_map(|iface| {
            let ifindex = read_ifindex(iface).ok()?;
            let mac = read_mac(iface).ok()?;
            Some((iface.clone(), ifindex, mac))
        })
        .collect();
    if cands.is_empty() {
        return Err(NetError::NoInterface);
    }

    // DHCP every link concurrently. Each acquire() binds its socket to its own
    // interface (SO_BINDTODEVICE), so the exchanges do not cross links. The wall
    // time is the slowest single link's DHCP budget, not the sum.
    let results: Vec<(String, u32, Option<Lease>)> = std::thread::scope(|scope| {
        let handles: Vec<_> = cands
            .iter()
            .map(|(iface, ifindex, mac)| {
                let (iface, ifindex, mac) = (iface.clone(), *ifindex, *mac);
                scope.spawn(move || dhcp_link(&iface, ifindex, mac).ok())
            })
            .collect();
        cands
            .iter()
            .zip(handles)
            .map(|((iface, ifindex, _), handle)| {
                (iface.clone(), *ifindex, handle.join().unwrap_or(None))
            })
            .collect()
    });

    let leases: Vec<Option<Lease>> = results.iter().map(|(_, _, lease)| lease.clone()).collect();
    let winner = choose_lease(&leases).ok_or(NetError::DhcpTimeout)?;

    // Apply the winner; bring every other link back down so exactly one interface
    // is left up and addressed. Only the winner is ever given an address, so the
    // "one configured link" invariant holds even if a teardown fails — a loser is
    // then at worst left administratively up but unaddressed (no IP, no route).
    let win_iface = results[winner].0.clone();
    let win_ifindex = results[winner].1;
    let win_lease = leases[winner]
        .clone()
        .expect("winner index carries a lease");
    apply_lease(win_ifindex, &win_lease)?;
    for (idx, (_, ifindex, _)) in results.iter().enumerate() {
        if idx != winner {
            let _ = netlink::link_down(*ifindex);
        }
    }
    Ok(net_config(&win_iface, win_lease))
}

/// Bring `iface` up, wait for carrier, and run one DHCP exchange.
fn dhcp_link(iface: &str, ifindex: u32, mac: [u8; 6]) -> Result<Lease, NetError> {
    netlink::link_up(ifindex).map_err(|source| NetError::Netlink {
        op: "link up",
        source,
    })?;
    wait_for_link(iface);
    dhcp::acquire(iface, mac)
}

/// Apply a lease to `ifindex`: assign the address and, if present, the default route.
fn apply_lease(ifindex: u32, lease: &Lease) -> Result<(), NetError> {
    netlink::add_address(ifindex, lease.ip, lease.prefix_len).map_err(|source| {
        NetError::Netlink {
            op: "add address",
            source,
        }
    })?;
    if let Some(gw) = lease.gateway {
        netlink::add_default_route(ifindex, gw).map_err(|source| NetError::Netlink {
            op: "add default route",
            source,
        })?;
    }
    Ok(())
}

/// Build the public [`NetConfig`] from a winning interface and its lease.
fn net_config(iface: &str, lease: Lease) -> NetConfig {
    NetConfig {
        iface: iface.to_string(),
        ip: lease.ip,
        prefix_len: lease.prefix_len,
        gateway: lease.gateway,
        dns: lease.dns,
    }
}

/// Choose the winning interface among raced DHCP results (pure; unit-tested).
/// `leases` is in candidate order, which `select_nics` sorts by interface name.
/// Prefers a lease that carries a default gateway — that network has a route
/// toward `beskar7.api` — and otherwise the lowest-sorted interface that leased
/// at all. Returns `None` when no interface obtained a lease.
fn choose_lease(leases: &[Option<Lease>]) -> Option<usize> {
    leases
        .iter()
        .position(|lease| lease.as_ref().is_some_and(|l| l.gateway.is_some()))
        .or_else(|| leases.iter().position(Option::is_some))
}

/// The libc resolver (musl/glibc) reads at most three `nameserver` lines; any
/// beyond that are silently ignored, so there is no point writing them.
const MAX_NAMESERVERS: usize = 3;

/// Render `/etc/resolv.conf` content from DHCP option-6 servers (pure;
/// unit-tested): one `nameserver <ip>` line each, in order, de-duplicated, capped
/// at [`MAX_NAMESERVERS`]. Empty input yields an empty string (no file written).
fn render_resolv_conf(dns: &[Ipv4Addr]) -> String {
    let mut chosen: Vec<Ipv4Addr> = Vec::new();
    for ip in dns {
        if !chosen.contains(ip) {
            chosen.push(*ip);
            if chosen.len() == MAX_NAMESERVERS {
                break;
            }
        }
    }
    chosen
        .iter()
        .map(|ip| format!("nameserver {ip}\n"))
        .collect()
}

/// Write the DHCP-provided DNS servers (option 6) to `/etc/resolv.conf` so a
/// hostname `beskar7.api` resolves (D-013). A no-op when no servers were offered.
/// Best-effort by contract: the recommended IP-literal `beskar7.api` (§8.2) needs
/// no resolver, so the caller treats a write failure as non-fatal.
pub fn write_resolv_conf(dns: &[Ipv4Addr]) -> std::io::Result<()> {
    let content = render_resolv_conf(dns);
    if content.is_empty() {
        return Ok(());
    }
    // The minimal initramfs ships no `/etc`, so create it before the write —
    // otherwise `std::fs::write` fails with ENOENT and the libc resolver, which
    // reads `/etc/resolv.conf`, never sees a nameserver.
    std::fs::create_dir_all("/etc")?;
    std::fs::write("/etc/resolv.conf", content)
}

/// Select the provisioning interface(s) from `net_dir` (a `/sys/class/net`-shaped
/// directory). With `bootif`, pins the interface whose MAC matches; with a single
/// non-loopback NIC, pins it; with several and no `BOOTIF`, returns them all to be
/// raced. Pure over the directory, so the selection policy is unit-tested.
fn select_nics(net_dir: &Path, bootif: Option<&str>) -> Result<NicSelection, NetError> {
    let candidates = candidate_interfaces(net_dir);
    if candidates.is_empty() {
        return Err(NetError::NoInterface);
    }

    if let Some(bootif) = bootif {
        let want = normalize_bootif(bootif);
        for iface in &candidates {
            if let Some(mac) = read_trimmed(&net_dir.join(iface).join("address")) {
                if mac.eq_ignore_ascii_case(&want) {
                    return Ok(NicSelection::Pinned(iface.clone()));
                }
            }
        }
        return Err(NetError::BootifNoMatch(want));
    }

    match candidates.as_slice() {
        [only] => Ok(NicSelection::Pinned(only.clone())),
        _ => Ok(NicSelection::Race(candidates)),
    }
}

/// Whether [`select_nics`] would succeed against `net_dir` now: the `BOOTIF`
/// interface exists when `bootif` pins one, otherwise any candidate does. The
/// post-module-load settle wait ([`crate::modules`]) waits for exactly this, so
/// it holds out for the NIC that PXE-booted rather than the first to register.
pub(crate) fn nic_selectable(net_dir: &Path, bootif: Option<&str>) -> bool {
    select_nics(net_dir, bootif).is_ok()
}

/// The interfaces NIC selection chooses from: every `net_dir` entry except
/// loopback, sorted so the race tie-break is deterministic. Empty when the
/// directory cannot be read.
pub(crate) fn candidate_interfaces(net_dir: &Path) -> Vec<String> {
    let Ok(rd) = std::fs::read_dir(net_dir) else {
        return Vec::new();
    };
    let mut names: Vec<String> = rd
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|name| name != "lo")
        .collect();
    names.sort();
    names
}

/// Normalize a `BOOTIF` value to a lowercase colon-separated MAC. pxelinux/iPXE
/// render it as `01-aa-bb-cc-dd-ee-ff` (a `01` hardware-type prefix + the MAC
/// with dashes); strip the prefix and convert to the `/sys/.../address` form.
fn normalize_bootif(bootif: &str) -> String {
    let hex = bootif.strip_prefix("01-").unwrap_or(bootif);
    hex.replace('-', ":").to_ascii_lowercase()
}

/// Read `/sys/class/net/<iface>/ifindex`.
fn read_ifindex(iface: &str) -> Result<u32, NetError> {
    let path = format!("{SYSFS_NET}/{iface}/ifindex");
    read_trimmed(Path::new(&path))
        .and_then(|s| s.parse().ok())
        .ok_or(NetError::SysRead(path))
}

/// Read and parse `/sys/class/net/<iface>/address` into 6 MAC bytes.
fn read_mac(iface: &str) -> Result<[u8; 6], NetError> {
    let path = format!("{SYSFS_NET}/{iface}/address");
    let raw = read_trimmed(Path::new(&path)).ok_or_else(|| NetError::SysRead(path.clone()))?;
    parse_mac(&raw).ok_or(NetError::SysRead(path))
}

/// Parse an `aa:bb:cc:dd:ee:ff` MAC into 6 bytes.
fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let mut out = [0u8; 6];
    let mut parts = s.split(':');
    for byte in out.iter_mut() {
        *byte = u8::from_str_radix(parts.next()?, 16).ok()?;
    }
    if parts.next().is_some() {
        return None;
    }
    Some(out)
}

/// Briefly wait for the link carrier after bringing the interface up, so DHCP
/// does not race a not-yet-up link. Best-effort and bounded; a link that never
/// reports a carrier still proceeds (DHCP will simply time out and surface that).
fn wait_for_link(iface: &str) {
    use std::time::{Duration, Instant};
    let carrier = format!("{SYSFS_NET}/{iface}/carrier");
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(3) {
        if read_trimmed(Path::new(&carrier)).as_deref() == Some("1") {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Count the leading one-bits of a subnet mask (DHCP option 1) into a prefix
/// length. A non-contiguous mask falls back to a `/24` rather than erroring —
/// the address is still usable for the brief inspection window.
fn mask_to_prefix_len(mask: Ipv4Addr) -> u8 {
    let bits = u32::from(mask);
    let ones = bits.count_ones();
    // Contiguous masks have all ones at the top; if not, default to /24.
    if bits.leading_ones() == ones {
        ones as u8
    } else {
        24
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probe::testutil::{write, Scratch};

    fn write_iface(root: &Path, name: &str, mac: &str) {
        write(root, &format!("{name}/address"), &format!("{mac}\n"));
        write(root, &format!("{name}/ifindex"), "2\n");
    }

    fn lease_with(gateway: Option<[u8; 4]>) -> Lease {
        Lease {
            ip: Ipv4Addr::new(192, 168, 1, 10),
            prefix_len: 24,
            gateway: gateway.map(Ipv4Addr::from),
            dns: vec![],
        }
    }

    #[test]
    fn select_nics_single_non_loopback_is_pinned() {
        let s = Scratch::new("net-single");
        write(s.path(), "lo/address", "00:00:00:00:00:00\n");
        write_iface(s.path(), "eth0", "52:54:00:12:34:56");
        match select_nics(s.path(), None) {
            Ok(NicSelection::Pinned(iface)) => assert_eq!(iface, "eth0"),
            _ => panic!("expected Pinned(eth0)"),
        }
    }

    #[test]
    fn select_nics_multiple_without_bootif_races_all_sorted() {
        let s = Scratch::new("net-ambig");
        // Insert out of order; the candidate list must come back sorted so the
        // race tie-break is deterministic.
        write_iface(s.path(), "eth1", "52:54:00:00:00:02");
        write_iface(s.path(), "eth0", "52:54:00:00:00:01");
        match select_nics(s.path(), None) {
            Ok(NicSelection::Race(ifaces)) => assert_eq!(ifaces, vec!["eth0", "eth1"]),
            _ => panic!("expected Race over both NICs"),
        }
    }

    #[test]
    fn select_nics_bootif_matches_mac() {
        let s = Scratch::new("net-bootif");
        write_iface(s.path(), "eth0", "52:54:00:00:00:01");
        write_iface(s.path(), "eth1", "52:54:00:aa:bb:cc");
        // pxelinux form: 01- prefix, dashes, any case.
        match select_nics(s.path(), Some("01-52-54-00-AA-BB-CC")) {
            Ok(NicSelection::Pinned(iface)) => assert_eq!(iface, "eth1"),
            _ => panic!("expected Pinned(eth1)"),
        }
    }

    #[test]
    fn select_nics_bootif_no_match_errors() {
        let s = Scratch::new("net-bootif-miss");
        // Two NICs so the no-match can't silently fall through to single-NIC.
        write_iface(s.path(), "eth0", "52:54:00:00:00:01");
        write_iface(s.path(), "eth1", "52:54:00:00:00:02");
        assert!(matches!(
            select_nics(s.path(), Some("01-de-ad-be-ef-00-00")),
            Err(NetError::BootifNoMatch(_))
        ));
    }

    #[test]
    fn select_nics_no_interface() {
        let s = Scratch::new("net-none");
        write(s.path(), "lo/address", "00:00:00:00:00:00\n");
        assert!(matches!(
            select_nics(s.path(), None),
            Err(NetError::NoInterface)
        ));
    }

    #[test]
    fn choose_lease_none_when_nothing_leased() {
        assert_eq!(choose_lease(&[]), None);
        assert_eq!(choose_lease(&[None, None]), None);
    }

    #[test]
    fn choose_lease_prefers_a_lease_with_a_gateway() {
        // eth0 leased but no gateway; eth1 has one -> eth1 (index 1) wins.
        let leases = [
            Some(lease_with(None)),
            Some(lease_with(Some([192, 168, 1, 1]))),
        ];
        assert_eq!(choose_lease(&leases), Some(1));
    }

    #[test]
    fn choose_lease_gateway_beats_an_earlier_gatewayless_lease() {
        // index 0 leased without a gateway, index 2 with one -> 2 wins over 0.
        let leases = [
            Some(lease_with(None)),
            None,
            Some(lease_with(Some([10, 0, 0, 1]))),
        ];
        assert_eq!(choose_lease(&leases), Some(2));
    }

    #[test]
    fn choose_lease_lowest_index_among_gatewayed() {
        let leases = [
            Some(lease_with(Some([10, 0, 0, 1]))),
            Some(lease_with(Some([10, 0, 1, 1]))),
        ];
        assert_eq!(choose_lease(&leases), Some(0));
    }

    #[test]
    fn choose_lease_falls_back_to_lowest_index_lease_without_gateway() {
        // No lease has a gateway; the lowest-index lease (skipping the gap) wins.
        let leases = [None, Some(lease_with(None)), Some(lease_with(None))];
        assert_eq!(choose_lease(&leases), Some(1));
    }

    #[test]
    fn normalize_bootif_strips_prefix_and_lowercases() {
        assert_eq!(
            normalize_bootif("01-52-54-00-AA-BB-CC"),
            "52:54:00:aa:bb:cc"
        );
        // Already-bare MAC with dashes is tolerated.
        assert_eq!(normalize_bootif("52-54-00-11-22-33"), "52:54:00:11:22:33");
    }

    #[test]
    fn parse_mac_roundtrips_and_rejects_bad() {
        assert_eq!(
            parse_mac("52:54:00:12:34:56"),
            Some([0x52, 0x54, 0x00, 0x12, 0x34, 0x56])
        );
        assert_eq!(parse_mac("52:54:00:12:34"), None); // too short
        assert_eq!(parse_mac("52:54:00:12:34:56:78"), None); // too long
        assert_eq!(parse_mac("zz:54:00:12:34:56"), None); // non-hex
    }

    #[test]
    fn mask_to_prefix_len_common_masks() {
        assert_eq!(mask_to_prefix_len(Ipv4Addr::new(255, 255, 255, 0)), 24);
        assert_eq!(mask_to_prefix_len(Ipv4Addr::new(255, 255, 0, 0)), 16);
        assert_eq!(mask_to_prefix_len(Ipv4Addr::new(255, 255, 255, 192)), 26);
        assert_eq!(mask_to_prefix_len(Ipv4Addr::new(0, 0, 0, 0)), 0);
        // Non-contiguous (pathological) falls back to /24.
        assert_eq!(mask_to_prefix_len(Ipv4Addr::new(255, 0, 255, 0)), 24);
    }

    #[test]
    fn render_resolv_conf_empty_input_is_empty() {
        // No option-6 servers -> empty string, so write_resolv_conf writes nothing.
        assert_eq!(render_resolv_conf(&[]), "");
    }

    #[test]
    fn render_resolv_conf_one_line_per_server_in_order() {
        let dns = [Ipv4Addr::new(192, 168, 1, 1), Ipv4Addr::new(8, 8, 8, 8)];
        assert_eq!(
            render_resolv_conf(&dns),
            "nameserver 192.168.1.1\nnameserver 8.8.8.8\n"
        );
    }

    #[test]
    fn render_resolv_conf_dedups_preserving_first_seen_order() {
        let dns = [
            Ipv4Addr::new(8, 8, 8, 8),
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(8, 8, 8, 8),
        ];
        assert_eq!(
            render_resolv_conf(&dns),
            "nameserver 8.8.8.8\nnameserver 1.1.1.1\n"
        );
    }

    #[test]
    fn render_resolv_conf_caps_at_the_resolver_limit() {
        let dns = [
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            Ipv4Addr::new(10, 0, 0, 3),
            Ipv4Addr::new(10, 0, 0, 4),
        ];
        // Only MAX_NAMESERVERS (3) lines; the resolver ignores any beyond that.
        assert_eq!(
            render_resolv_conf(&dns),
            "nameserver 10.0.0.1\nnameserver 10.0.0.2\nnameserver 10.0.0.3\n"
        );
    }

    #[test]
    fn static_ip_parse_full_form() {
        let s = StaticIp::parse("192.168.150.10::192.168.150.1:255.255.255.0:8.8.8.8").unwrap();
        assert_eq!(
            s,
            StaticIp {
                ip: Ipv4Addr::new(192, 168, 150, 10),
                gateway: Some(Ipv4Addr::new(192, 168, 150, 1)),
                prefix_len: 24,
                dns: vec![Ipv4Addr::new(8, 8, 8, 8)],
            }
        );
    }

    #[test]
    fn static_ip_parse_no_gateway_no_dns() {
        // Empty gateway field -> None; no dns field -> empty.
        let s = StaticIp::parse("10.0.0.5:::255.255.0.0").unwrap();
        assert_eq!(s.ip, Ipv4Addr::new(10, 0, 0, 5));
        assert_eq!(s.gateway, None);
        assert_eq!(s.prefix_len, 16);
        assert!(s.dns.is_empty());
    }

    #[test]
    fn static_ip_parse_accepts_cidr_prefix_mask() {
        // The <mask> field may be a bare prefix length instead of a dotted mask.
        let s = StaticIp::parse("172.16.0.9::172.16.0.1:24").unwrap();
        assert_eq!(s.prefix_len, 24);
        assert_eq!(s.gateway, Some(Ipv4Addr::new(172, 16, 0, 1)));
        assert!(s.dns.is_empty());
    }

    #[test]
    fn static_ip_parse_rejects_malformed() {
        // Too few fields.
        assert_eq!(StaticIp::parse("192.168.1.1:255.255.255.0"), None);
        // Bad client IP.
        assert_eq!(StaticIp::parse("not-an-ip::10.0.0.1:24"), None);
        // Bad gateway.
        assert_eq!(StaticIp::parse("10.0.0.5::nope:24"), None);
        // Out-of-range prefix.
        assert_eq!(StaticIp::parse("10.0.0.5::10.0.0.1:33"), None);
        // Bad netmask.
        assert_eq!(StaticIp::parse("10.0.0.5::10.0.0.1:not-a-mask"), None);
        // Too many fields.
        assert_eq!(StaticIp::parse("10.0.0.5::10.0.0.1:24:8.8.8.8:extra"), None);
    }
}
