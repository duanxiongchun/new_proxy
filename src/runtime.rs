use crate::config::{GatewayConfig, PeerConfig};

pub async fn run_blocking_command<F>(op: F) -> Result<(), String>
where
    F: FnOnce() -> Result<(), String> + Send + 'static,
{
    tokio::task::spawn_blocking(op)
        .await
        .map_err(|e| format!("blocking command worker failed: {}", e))?
}

pub fn run_script(script: &str) {
    log::info!("Executing script: {}", script);
    let output = std::process::Command::new("sh")
        .arg("-c")
        .arg(script)
        .output();
    match output {
        Ok(out) => {
            if !out.status.success() {
                log::warn!("Script exited with error: {:?}", out.status);
                log::warn!("Script stdout: {}", String::from_utf8_lossy(&out.stdout));
                log::warn!("Script stderr: {}", String::from_utf8_lossy(&out.stderr));
            } else {
                log::info!("Script completed successfully.");
            }
        }
        Err(e) => {
            log::error!("Failed to execute script '{}': {}", script, e);
        }
    }
}

pub fn cleanup_runtime(config: &GatewayConfig, interface_name: &str) {
    cleanup_routes_and_iptables(config, interface_name);
    if let Some(ref post_script) = config.interface.post_script {
        run_script(post_script);
    }
}

pub fn setup_routes_and_iptables(
    config: &GatewayConfig,
    interface_name: &str,
) -> Result<(), String> {
    // WireGuard device setup is independent from route/firewall ownership.
    // `Table = off` skips route/iptables changes, but the daemon still owns
    // the WireGuard device so peer sync and telemetry use the real backend.
    crate::wireguard::configure_device(
        interface_name,
        &config.interface.private_key,
        config.interface.listen_port,
    )?;

    if let Some(ref t) = config.interface.table {
        if t.to_lowercase() == "off" {
            log::info!("Table is off. Skipping automatic routing and iptables setup.");
            return Ok(());
        }
    }

    log::info!(
        "Setting up automatic routing and iptables for interface: {}",
        interface_name
    );

    for addr in &config.interface.addresses {
        run_command_checked(
            "ip",
            &[
                "addr".to_string(),
                "replace".to_string(),
                addr.to_string(),
                "dev".to_string(),
                interface_name.to_string(),
            ],
        )?;
    }

    run_command_checked(
        "ip",
        &[
            "link".to_string(),
            "set".to_string(),
            interface_name.to_string(),
            "up".to_string(),
            "mtu".to_string(),
            config.interface.mtu.to_string(),
        ],
    )?;

    if let Some(tproxy_port) = config.interface.tproxy_port {
        log::info!("Setting up TPROXY iptables rules on port {}", tproxy_port);
        let (fwmark, route_table) = instance_routing_ids(interface_name);
        ensure_tproxy_divert_rules(fwmark)?;

        for peer in &config.peers {
            setup_peer_routes_and_tproxy(peer, config.interface.tproxy_port, interface_name)?;
        }

        run_command_best_effort(
            "ip",
            &[
                "rule".to_string(),
                "del".to_string(),
                "fwmark".to_string(),
                format!("{:#x}", fwmark),
                "lookup".to_string(),
                route_table.to_string(),
            ],
        );
        run_command_checked(
            "ip",
            &[
                "rule".to_string(),
                "add".to_string(),
                "fwmark".to_string(),
                format!("{:#x}", fwmark),
                "lookup".to_string(),
                route_table.to_string(),
            ],
        )?;
        run_command_checked(
            "ip",
            &[
                "route".to_string(),
                "replace".to_string(),
                "local".to_string(),
                "0.0.0.0/0".to_string(),
                "dev".to_string(),
                "lo".to_string(),
                "table".to_string(),
                route_table.to_string(),
            ],
        )?;

        run_command_best_effort(
            "ip",
            &[
                "-6".to_string(),
                "rule".to_string(),
                "del".to_string(),
                "fwmark".to_string(),
                format!("{:#x}", fwmark),
                "lookup".to_string(),
                route_table.to_string(),
            ],
        );
        run_command_checked(
            "ip",
            &[
                "-6".to_string(),
                "rule".to_string(),
                "add".to_string(),
                "fwmark".to_string(),
                format!("{:#x}", fwmark),
                "lookup".to_string(),
                route_table.to_string(),
            ],
        )?;
        run_command_checked(
            "ip",
            &[
                "-6".to_string(),
                "route".to_string(),
                "replace".to_string(),
                "local".to_string(),
                "::/0".to_string(),
                "dev".to_string(),
                "lo".to_string(),
                "table".to_string(),
                route_table.to_string(),
            ],
        )?;
    } else {
        for peer in &config.peers {
            setup_peer_routes_and_tproxy(peer, config.interface.tproxy_port, interface_name)?;
        }
    }
    Ok(())
}

pub fn setup_peer_routes_and_tproxy(
    peer: &PeerConfig,
    tproxy_port: Option<u16>,
    interface_name: &str,
) -> Result<(), String> {
    let (fwmark, _) = instance_routing_ids(interface_name);
    let mark_spec = format!("{:#x}/0xffffffff", fwmark);

    for allowed_ip in &peer.allowed_ips {
        if matches!(allowed_ip, ipnet::IpNet::V4(_)) {
            run_command_checked(
                "ip",
                &[
                    "route".to_string(),
                    "replace".to_string(),
                    allowed_ip.to_string(),
                    "dev".to_string(),
                    interface_name.to_string(),
                ],
            )?;
        } else {
            run_command_checked(
                "ip",
                &[
                    "-6".to_string(),
                    "route".to_string(),
                    "replace".to_string(),
                    allowed_ip.to_string(),
                    "dev".to_string(),
                    interface_name.to_string(),
                ],
            )?;
        }
        if let Some(port) = tproxy_port.filter(|_| peer_has_l4_proxy(peer)) {
            ensure_tproxy_rule(*allowed_ip, port, &mark_spec)?;
            let _ = ensure_mss_clamp_rule(*allowed_ip);
        }
    }
    Ok(())
}

pub fn setup_proxy_tproxy_rules(
    config: &GatewayConfig,
    interface_name: &str,
) -> Result<(), String> {
    let Some(tproxy_port) = config.interface.tproxy_port else {
        return Ok(());
    };
    let (fwmark, _) = instance_routing_ids(interface_name);
    let mark_spec = format!("{:#x}/0xffffffff", fwmark);

    for peer in config.peers.iter().filter(|peer| peer_has_l4_proxy(peer)) {
        for allowed_ip in &peer.allowed_ips {
            ensure_tproxy_rule(*allowed_ip, tproxy_port, &mark_spec)?;
            let _ = ensure_mss_clamp_rule(*allowed_ip);
        }
    }
    Ok(())
}

pub fn cleanup_proxy_tproxy_rules(config: &GatewayConfig, interface_name: &str) {
    let Some(tproxy_port) = config.interface.tproxy_port else {
        return;
    };
    let (fwmark, _) = instance_routing_ids(interface_name);
    let mark_spec = format!("{:#x}/0xffffffff", fwmark);

    for peer in config.peers.iter().filter(|peer| peer_has_l4_proxy(peer)) {
        for allowed_ip in &peer.allowed_ips {
            cleanup_tproxy_rule(*allowed_ip, tproxy_port, &mark_spec);
            cleanup_mss_clamp_rule(*allowed_ip);
        }
    }
}

pub fn cleanup_peer_routes_and_tproxy(
    peer: &PeerConfig,
    tproxy_port: Option<u16>,
    interface_name: &str,
) -> Result<(), String> {
    let (fwmark, _) = instance_routing_ids(interface_name);
    let mark_spec = format!("{:#x}/0xffffffff", fwmark);
    let mut errors = Vec::new();
    for allowed_ip in &peer.allowed_ips {
        if let Some(port) = tproxy_port.filter(|_| peer_has_l4_proxy(peer)) {
            let (tool, rule) = tproxy_rule_spec(*allowed_ip, port, &mark_spec, true);
            let mut tproxy_args = vec!["-t".to_string(), "mangle".to_string(), "-D".to_string()];
            tproxy_args.extend(rule);
            if let Err(e) = run_command_checked(tool, &tproxy_args) {
                errors.push(e);
            }
            cleanup_legacy_tproxy_rule(*allowed_ip, port, &mark_spec);

            let mss_tool = if matches!(allowed_ip, ipnet::IpNet::V4(_)) {
                "iptables"
            } else {
                "ip6tables"
            };
            let mss_args = vec![
                "-t".to_string(),
                "mangle".to_string(),
                "-D".to_string(),
                "PREROUTING".to_string(),
                "-p".to_string(),
                "tcp".to_string(),
                "--tcp-flags".to_string(),
                "SYN,RST".to_string(),
                "SYN".to_string(),
                "-d".to_string(),
                allowed_ip.to_string(),
                "-j".to_string(),
                "TCPMSS".to_string(),
                "--clamp-mss-to-pmtud".to_string(),
            ];
            run_command_best_effort(mss_tool, &mss_args);
        }
        let route_result = if matches!(allowed_ip, ipnet::IpNet::V4(_)) {
            run_command_checked(
                "ip",
                &[
                    "route".to_string(),
                    "del".to_string(),
                    allowed_ip.to_string(),
                    "dev".to_string(),
                    interface_name.to_string(),
                ],
            )
        } else {
            run_command_checked(
                "ip",
                &[
                    "-6".to_string(),
                    "route".to_string(),
                    "del".to_string(),
                    allowed_ip.to_string(),
                    "dev".to_string(),
                    interface_name.to_string(),
                ],
            )
        };
        if let Err(e) = route_result {
            errors.push(e);
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

fn cleanup_routes_and_iptables(config: &GatewayConfig, interface_name: &str) {
    if let Some(ref t) = config.interface.table {
        if t.to_lowercase() == "off" {
            crate::wireguard::cleanup_device(interface_name);
            return;
        }
    }

    log::info!(
        "Cleaning up automatic routing and iptables for interface: {}",
        interface_name
    );

    if let Some(tproxy_port) = config.interface.tproxy_port {
        log::info!("Tearing down TPROXY iptables rules on port {}", tproxy_port);
        let (fwmark, route_table) = instance_routing_ids(interface_name);
        let mark_spec = format!("{:#x}/0xffffffff", fwmark);

        for peer in &config.peers {
            for allowed_ip in &peer.allowed_ips {
                cleanup_tproxy_rule(*allowed_ip, tproxy_port, &mark_spec);
                cleanup_mss_clamp_rule(*allowed_ip);
            }
        }

        run_command_best_effort(
            "ip",
            &[
                "rule".to_string(),
                "del".to_string(),
                "fwmark".to_string(),
                format!("{:#x}", fwmark),
                "lookup".to_string(),
                route_table.to_string(),
            ],
        );
        run_command_best_effort(
            "ip",
            &[
                "route".to_string(),
                "del".to_string(),
                "local".to_string(),
                "0.0.0.0/0".to_string(),
                "dev".to_string(),
                "lo".to_string(),
                "table".to_string(),
                route_table.to_string(),
            ],
        );
        run_command_best_effort(
            "ip",
            &[
                "-6".to_string(),
                "rule".to_string(),
                "del".to_string(),
                "fwmark".to_string(),
                format!("{:#x}", fwmark),
                "lookup".to_string(),
                route_table.to_string(),
            ],
        );
        run_command_best_effort(
            "ip",
            &[
                "-6".to_string(),
                "route".to_string(),
                "del".to_string(),
                "local".to_string(),
                "::/0".to_string(),
                "dev".to_string(),
                "lo".to_string(),
                "table".to_string(),
                route_table.to_string(),
            ],
        );
        cleanup_tproxy_divert_rules(fwmark);
    }

    for peer in &config.peers {
        for allowed_ip in &peer.allowed_ips {
            if matches!(allowed_ip, ipnet::IpNet::V4(_)) {
                run_command_best_effort(
                    "ip",
                    &[
                        "route".to_string(),
                        "del".to_string(),
                        allowed_ip.to_string(),
                        "dev".to_string(),
                        interface_name.to_string(),
                    ],
                );
            } else {
                run_command_best_effort(
                    "ip",
                    &[
                        "-6".to_string(),
                        "route".to_string(),
                        "del".to_string(),
                        allowed_ip.to_string(),
                        "dev".to_string(),
                        interface_name.to_string(),
                    ],
                );
            }
        }
    }

    for addr in &config.interface.addresses {
        run_command_best_effort(
            "ip",
            &[
                "addr".to_string(),
                "del".to_string(),
                addr.to_string(),
                "dev".to_string(),
                interface_name.to_string(),
            ],
        );
    }

    log::info!("Deleting virtual WireGuard interface '{}'", interface_name);
    crate::wireguard::cleanup_device(interface_name);
}

fn peer_has_l4_proxy(peer: &PeerConfig) -> bool {
    peer.endpoint.is_some() && peer.proxy_port.is_some()
}

fn instance_routing_ids(interface_name: &str) -> (u32, u32) {
    let mut hash = 0x811c9dc5u32;
    for byte in interface_name.as_bytes() {
        hash ^= *byte as u32;
        hash = hash.wrapping_mul(0x01000193);
    }
    let fwmark = 0x1000_0000 | (hash & 0x00ff_ffff);
    let table = 10_000 + (hash % 50_000);
    (fwmark, table)
}

fn ensure_mss_clamp_rule(allowed_ip: ipnet::IpNet) -> Result<(), String> {
    let tool = if matches!(allowed_ip, ipnet::IpNet::V4(_)) {
        "iptables"
    } else {
        "ip6tables"
    };
    let rule = vec![
        "PREROUTING".to_string(),
        "-p".to_string(),
        "tcp".to_string(),
        "--tcp-flags".to_string(),
        "SYN,RST".to_string(),
        "SYN".to_string(),
        "-d".to_string(),
        allowed_ip.to_string(),
        "-j".to_string(),
        "TCPMSS".to_string(),
        "--clamp-mss-to-pmtud".to_string(),
    ];
    ensure_iptables_rule(tool, &rule).map_err(|e| {
        log::warn!(
            "Failed to set TCPMSS clamping rule (might be unsupported in this environment): {}",
            e
        );
        e
    })
}

fn ensure_tproxy_rule(
    allowed_ip: ipnet::IpNet,
    tproxy_port: u16,
    mark_spec: &str,
) -> Result<(), String> {
    let (tool, rule) = tproxy_rule_spec(allowed_ip, tproxy_port, mark_spec, true);
    cleanup_legacy_tproxy_rule(allowed_ip, tproxy_port, mark_spec);
    ensure_iptables_rule(tool, &rule)
}

fn cleanup_tproxy_rule(allowed_ip: ipnet::IpNet, tproxy_port: u16, mark_spec: &str) {
    let (tool, rule) = tproxy_rule_spec(allowed_ip, tproxy_port, mark_spec, true);
    let mut args = vec!["-t".to_string(), "mangle".to_string(), "-D".to_string()];
    args.extend(rule);
    run_command_best_effort(tool, &args);
    cleanup_legacy_tproxy_rule(allowed_ip, tproxy_port, mark_spec);
}

fn cleanup_legacy_tproxy_rule(allowed_ip: ipnet::IpNet, tproxy_port: u16, mark_spec: &str) {
    let (tool, rule) = tproxy_rule_spec(allowed_ip, tproxy_port, mark_spec, false);
    let mut args = vec!["-t".to_string(), "mangle".to_string(), "-D".to_string()];
    args.extend(rule);
    run_command_best_effort(tool, &args);
}

fn tproxy_rule_spec(
    allowed_ip: ipnet::IpNet,
    tproxy_port: u16,
    mark_spec: &str,
    client_initiated_only: bool,
) -> (&'static str, Vec<String>) {
    let (tool, on_ip) = if matches!(allowed_ip, ipnet::IpNet::V4(_)) {
        ("iptables", "0.0.0.0")
    } else {
        ("ip6tables", "::")
    };
    let mut rule = vec![
        "PREROUTING".to_string(),
        "-p".to_string(),
        "tcp".to_string(),
    ];
    if client_initiated_only {
        rule.push("--syn".to_string());
    }
    rule.extend([
        "-d".to_string(),
        allowed_ip.to_string(),
        "-j".to_string(),
        "TPROXY".to_string(),
        "--on-port".to_string(),
        tproxy_port.to_string(),
        "--on-ip".to_string(),
        on_ip.to_string(),
        "--tproxy-mark".to_string(),
        mark_spec.to_string(),
    ]);
    (tool, rule)
}

fn ensure_tproxy_divert_rules(fwmark: u32) -> Result<(), String> {
    let mark = format!("{:#x}", fwmark);
    let chain = tproxy_divert_chain(fwmark);
    for tool in ["iptables", "ip6tables"] {
        run_command_best_effort(
            tool,
            &["-t".into(), "mangle".into(), "-N".into(), chain.clone()],
        );
        ensure_iptables_rule(
            tool,
            &[
                "PREROUTING".to_string(),
                "-p".to_string(),
                "tcp".to_string(),
                "-m".to_string(),
                "socket".to_string(),
                "--transparent".to_string(),
                "-j".to_string(),
                chain.clone(),
            ],
        )?;
        ensure_iptables_rule(
            tool,
            &[
                chain.clone(),
                "-j".to_string(),
                "MARK".to_string(),
                "--set-mark".to_string(),
                mark.clone(),
            ],
        )?;
        ensure_iptables_rule(
            tool,
            &[chain.clone(), "-j".to_string(), "ACCEPT".to_string()],
        )?;
    }
    Ok(())
}

fn cleanup_tproxy_divert_rules(fwmark: u32) {
    let chain = tproxy_divert_chain(fwmark);
    for tool in ["iptables", "ip6tables"] {
        run_command_best_effort(
            tool,
            &[
                "-t".to_string(),
                "mangle".to_string(),
                "-D".to_string(),
                "PREROUTING".to_string(),
                "-p".to_string(),
                "tcp".to_string(),
                "-m".to_string(),
                "socket".to_string(),
                "--transparent".to_string(),
                "-j".to_string(),
                chain.clone(),
            ],
        );
        run_command_best_effort(
            tool,
            &[
                "-t".to_string(),
                "mangle".to_string(),
                "-F".to_string(),
                chain.clone(),
            ],
        );
        run_command_best_effort(
            tool,
            &[
                "-t".to_string(),
                "mangle".to_string(),
                "-X".to_string(),
                chain.clone(),
            ],
        );
    }
}

fn tproxy_divert_chain(fwmark: u32) -> String {
    format!("NEW_PROXY_DIVERT_{:08x}", fwmark)
}

fn cleanup_mss_clamp_rule(allowed_ip: ipnet::IpNet) {
    let tool = if matches!(allowed_ip, ipnet::IpNet::V4(_)) {
        "iptables"
    } else {
        "ip6tables"
    };
    let args = vec![
        "-t".to_string(),
        "mangle".to_string(),
        "-D".to_string(),
        "PREROUTING".to_string(),
        "-p".to_string(),
        "tcp".to_string(),
        "--tcp-flags".to_string(),
        "SYN,RST".to_string(),
        "SYN".to_string(),
        "-d".to_string(),
        allowed_ip.to_string(),
        "-j".to_string(),
        "TCPMSS".to_string(),
        "--clamp-mss-to-pmtud".to_string(),
    ];
    run_command_best_effort(tool, &args);
}

fn ensure_iptables_rule(tool: &str, rule: &[String]) -> Result<(), String> {
    let mut check_args = vec!["-t".to_string(), "mangle".to_string(), "-C".to_string()];
    check_args.extend(rule.iter().cloned());
    if run_command_checked(tool, &check_args).is_ok() {
        return Ok(());
    }
    let mut add_args = vec!["-t".to_string(), "mangle".to_string(), "-A".to_string()];
    add_args.extend(rule.iter().cloned());
    run_command_checked(tool, &add_args)
}

fn run_command_checked(program: &str, args: &[String]) -> Result<(), String> {
    let output = std::process::Command::new(program)
        .args(args)
        .output()
        .map_err(|e| format!("failed to execute '{} {}': {}", program, args.join(" "), e))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "command '{} {}' failed with status {:?}: {}",
            program,
            args.join(" "),
            output.status.code(),
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

fn run_command_best_effort(program: &str, args: &[String]) {
    if let Err(e) = run_command_checked(program, args) {
        log::debug!("{}", e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tproxy_rule_only_matches_client_initiated_syn() {
        let allowed_ip = "10.0.0.1/32".parse().unwrap();
        let (tool, rule) = tproxy_rule_spec(allowed_ip, 1080, "0x1/0xffffffff", true);

        assert_eq!(tool, "iptables");
        assert!(has_pair(&rule, "-p", "tcp"));
        assert!(rule.iter().any(|part| part == "--syn"));
        assert!(has_pair(&rule, "-d", "10.0.0.1/32"));
        assert!(has_pair(&rule, "-j", "TPROXY"));
    }

    #[test]
    fn legacy_tproxy_rule_shape_remains_available_for_cleanup() {
        let allowed_ip = "fd00::1/128".parse().unwrap();
        let (tool, rule) = tproxy_rule_spec(allowed_ip, 1080, "0x1/0xffffffff", false);

        assert_eq!(tool, "ip6tables");
        assert!(!rule.iter().any(|part| part == "--syn"));
        assert!(has_pair(&rule, "-d", "fd00::1/128"));
    }

    #[test]
    fn divert_chain_is_instance_scoped() {
        assert_eq!(
            tproxy_divert_chain(0x1234_abcd),
            "NEW_PROXY_DIVERT_1234abcd"
        );
        assert!(tproxy_divert_chain(0x1234_abcd).len() < 29);
    }

    fn has_pair(rule: &[String], key: &str, value: &str) -> bool {
        rule.windows(2)
            .any(|parts| parts[0] == key && parts[1] == value)
    }
}
