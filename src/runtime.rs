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

    for peer in &config.peers {
        setup_peer_routes_and_tproxy(peer, config.interface.tproxy_port, interface_name)?;
    }

    if let Some(tproxy_port) = config.interface.tproxy_port {
        log::info!("Setting up TPROXY iptables rules on port {}", tproxy_port);
        let (fwmark, route_table) = instance_routing_ids(interface_name);

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
            let (tool, on_ip) = if matches!(allowed_ip, ipnet::IpNet::V4(_)) {
                ("iptables", "0.0.0.0")
            } else {
                ("ip6tables", "::")
            };
            let tproxy_args = vec![
                "-t".to_string(),
                "mangle".to_string(),
                "-D".to_string(),
                "PREROUTING".to_string(),
                "-p".to_string(),
                "tcp".to_string(),
                "-d".to_string(),
                allowed_ip.to_string(),
                "-j".to_string(),
                "TPROXY".to_string(),
                "--on-port".to_string(),
                port.to_string(),
                "--on-ip".to_string(),
                on_ip.to_string(),
                "--tproxy-mark".to_string(),
                mark_spec.clone(),
            ];
            if let Err(e) = run_command_checked(tool, &tproxy_args) {
                errors.push(e);
            }

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
            if let Err(e) = run_command_checked(mss_tool, &mss_args) {
                errors.push(e);
            }
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
    let (tool, on_ip) = if matches!(allowed_ip, ipnet::IpNet::V4(_)) {
        ("iptables", "0.0.0.0")
    } else {
        ("ip6tables", "::")
    };
    let rule = vec![
        "PREROUTING".to_string(),
        "-p".to_string(),
        "tcp".to_string(),
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
    ];
    ensure_iptables_rule(tool, &rule)
}

fn cleanup_tproxy_rule(allowed_ip: ipnet::IpNet, tproxy_port: u16, mark_spec: &str) {
    let (tool, on_ip) = if matches!(allowed_ip, ipnet::IpNet::V4(_)) {
        ("iptables", "0.0.0.0")
    } else {
        ("ip6tables", "::")
    };
    let args = vec![
        "-t".to_string(),
        "mangle".to_string(),
        "-D".to_string(),
        "PREROUTING".to_string(),
        "-p".to_string(),
        "tcp".to_string(),
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
    ];
    run_command_best_effort(tool, &args);
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
