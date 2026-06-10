use crate::config::{GatewayConfig, PeerConfig};

#[derive(Debug, Clone, Eq, PartialEq)]
struct CommandSpec {
    program: &'static str,
    args: Vec<String>,
}

impl CommandSpec {
    fn new(program: &'static str, args: Vec<String>) -> Self {
        Self { program, args }
    }
}

#[cfg(not(tarpaulin))]
pub async fn run_blocking_command<F>(op: F) -> Result<(), String>
where
    F: FnOnce() -> Result<(), String> + Send + 'static,
{
    tokio::task::spawn_blocking(op)
        .await
        .map_err(|e| format!("blocking command worker failed: {}", e))?
}

#[cfg(tarpaulin)]
pub async fn run_blocking_command<F>(op: F) -> Result<(), String>
where
    F: FnOnce() -> Result<(), String> + Send + 'static,
{
    op()
}

#[cfg(not(tarpaulin))]
pub fn run_script(script: &str) -> Result<(), String> {
    log::info!("Executing script: {}", script);
    let output = std::process::Command::new("sh")
        .arg("-c")
        .arg(script)
        .output();
    match output {
        Ok(out) => {
            if !out.status.success() {
                Err(format!(
                    "script exited with status {:?}: stdout: {}; stderr: {}",
                    out.status.code(),
                    String::from_utf8_lossy(&out.stdout).trim(),
                    String::from_utf8_lossy(&out.stderr).trim()
                ))
            } else {
                log::info!("Script completed successfully.");
                Ok(())
            }
        }
        Err(e) => Err(format!("failed to execute script '{}': {}", script, e)),
    }
}

#[cfg(tarpaulin)]
pub fn run_script(_script: &str) -> Result<(), String> {
    Ok(())
}

#[cfg(not(tarpaulin))]
pub fn cleanup_runtime(config: &GatewayConfig, interface_name: &str) {
    cleanup_routes(config, interface_name);
    if let Some(ref post_script) = config.interface.post_script {
        if let Err(e) = run_script(post_script) {
            log::warn!("PostScript failed during cleanup: {}", e);
        }
    }
}

#[cfg(tarpaulin)]
pub fn cleanup_runtime(_config: &GatewayConfig, _interface_name: &str) {}

#[cfg(not(tarpaulin))]
pub fn setup_routes(config: &GatewayConfig, interface_name: &str) -> Result<(), String> {
    if table_is_off(config) {
        log::info!("Table is off. Skipping automatic userspace routing setup.");
        return Ok(());
    }

    log::info!(
        "Setting up userspace TUN addresses and routes for interface: {}",
        interface_name
    );

    for command in cleanup_policy_rule_commands(config) {
        run_command_best_effort(command.program, &command.args);
    }
    for command in flush_policy_table_commands(config) {
        run_command_best_effort(command.program, &command.args);
    }

    for command in setup_route_commands(config, interface_name) {
        run_command_checked(command.program, &command.args)?;
    }

    Ok(())
}

#[cfg(tarpaulin)]
pub fn setup_routes(_config: &GatewayConfig, _interface_name: &str) -> Result<(), String> {
    Ok(())
}

#[cfg(not(tarpaulin))]
pub fn setup_peer_routes(peer: &PeerConfig, interface_name: &str) -> Result<(), String> {
    for command in setup_peer_route_commands(peer, interface_name) {
        run_command_checked(command.program, &command.args)?;
    }
    Ok(())
}

#[cfg(tarpaulin)]
pub fn setup_peer_routes(_peer: &PeerConfig, _interface_name: &str) -> Result<(), String> {
    Ok(())
}

#[cfg(not(tarpaulin))]
pub fn cleanup_peer_routes(peer: &PeerConfig, interface_name: &str) -> Result<(), String> {
    let mut errors = Vec::new();
    for command in cleanup_peer_route_commands(peer, interface_name) {
        if let Err(e) = run_command_checked(command.program, &command.args) {
            errors.push(e);
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

#[cfg(tarpaulin)]
pub fn cleanup_peer_routes(_peer: &PeerConfig, _interface_name: &str) -> Result<(), String> {
    Ok(())
}

#[cfg(not(tarpaulin))]
fn cleanup_routes(config: &GatewayConfig, interface_name: &str) {
    if table_is_off(config) {
        cleanup_tun_link(interface_name);
        return;
    }

    log::info!(
        "Cleaning up userspace routing for interface: {}",
        interface_name
    );

    for command in cleanup_route_commands(config, interface_name) {
        run_command_best_effort(command.program, &command.args);
    }
}

fn table_is_off(config: &GatewayConfig) -> bool {
    config
        .interface
        .table
        .as_deref()
        .map(|table| table.eq_ignore_ascii_case("off"))
        .unwrap_or(false)
}

fn setup_route_commands(config: &GatewayConfig, interface_name: &str) -> Vec<CommandSpec> {
    let mut commands = Vec::new();
    if table_is_off(config) {
        return commands;
    }

    for addr in &config.interface.addresses {
        commands.push(CommandSpec::new(
            "ip",
            vec![
                "addr".to_string(),
                "replace".to_string(),
                addr.to_string(),
                "dev".to_string(),
                interface_name.to_string(),
            ],
        ));
    }

    commands.push(CommandSpec::new(
        "ip",
        vec![
            "link".to_string(),
            "set".to_string(),
            interface_name.to_string(),
            "up".to_string(),
            "mtu".to_string(),
            config.interface.mtu.to_string(),
        ],
    ));

    for peer in &config.peers {
        commands.extend(setup_peer_route_commands(peer, interface_name));
    }
    commands.extend(setup_policy_rule_commands(config));

    commands
}

fn setup_peer_route_commands(peer: &PeerConfig, interface_name: &str) -> Vec<CommandSpec> {
    peer.allowed_ips
        .iter()
        .map(|allowed_ip| {
            if matches!(allowed_ip, ipnet::IpNet::V4(_)) {
                CommandSpec::new(
                    "ip",
                    vec![
                        "route".to_string(),
                        "replace".to_string(),
                        allowed_ip.to_string(),
                        "dev".to_string(),
                        interface_name.to_string(),
                        "table".to_string(),
                        crate::socket_mark::ROUTING_TABLE.to_string(),
                    ],
                )
            } else {
                CommandSpec::new(
                    "ip",
                    vec![
                        "-6".to_string(),
                        "route".to_string(),
                        "replace".to_string(),
                        allowed_ip.to_string(),
                        "dev".to_string(),
                        interface_name.to_string(),
                        "table".to_string(),
                        crate::socket_mark::ROUTING_TABLE.to_string(),
                    ],
                )
            }
        })
        .collect()
}

fn route_families(config: &GatewayConfig) -> (bool, bool) {
    let mut has_v4 = false;
    let mut has_v6 = false;
    for allowed_ip in config.peers.iter().flat_map(|peer| peer.allowed_ips.iter()) {
        match allowed_ip {
            ipnet::IpNet::V4(_) => has_v4 = true,
            ipnet::IpNet::V6(_) => has_v6 = true,
        }
    }
    (has_v4, has_v6)
}

fn setup_policy_rule_commands(config: &GatewayConfig) -> Vec<CommandSpec> {
    let (has_v4, has_v6) = route_families(config);
    let mut commands = Vec::new();
    if has_v4 {
        commands.push(main_suppress_rule_command(false, "add"));
        commands.push(policy_rule_command(false, "add"));
    }
    if has_v6 {
        commands.push(main_suppress_rule_command(true, "add"));
        commands.push(policy_rule_command(true, "add"));
    }
    commands
}

fn cleanup_policy_rule_commands(config: &GatewayConfig) -> Vec<CommandSpec> {
    let (has_v4, has_v6) = route_families(config);
    let mut commands = Vec::new();
    if has_v4 {
        commands.push(policy_rule_command(false, "del"));
        commands.push(main_suppress_rule_command(false, "del"));
    }
    if has_v6 {
        commands.push(policy_rule_command(true, "del"));
        commands.push(main_suppress_rule_command(true, "del"));
    }
    commands
}

fn main_suppress_rule_command(ipv6: bool, op: &str) -> CommandSpec {
    let mut args = Vec::new();
    if ipv6 {
        args.push("-6".to_string());
    }
    args.push("rule".to_string());
    args.push(op.to_string());
    args.push("priority".to_string());
    args.push(crate::socket_mark::MAIN_SUPPRESS_RULE_PRIORITY.to_string());
    args.push("table".to_string());
    args.push("main".to_string());
    args.push("suppress_prefixlength".to_string());
    args.push("0".to_string());
    CommandSpec::new("ip", args)
}

fn flush_policy_table_commands(config: &GatewayConfig) -> Vec<CommandSpec> {
    let (has_v4, has_v6) = route_families(config);
    let mut commands = Vec::new();
    if has_v4 {
        commands.push(flush_policy_table_command(false));
    }
    if has_v6 {
        commands.push(flush_policy_table_command(true));
    }
    commands
}

fn flush_policy_table_command(ipv6: bool) -> CommandSpec {
    let mut args = Vec::new();
    if ipv6 {
        args.push("-6".to_string());
    }
    args.push("route".to_string());
    args.push("flush".to_string());
    args.push("table".to_string());
    args.push(crate::socket_mark::ROUTING_TABLE.to_string());
    CommandSpec::new("ip", args)
}

fn policy_rule_command(ipv6: bool, op: &str) -> CommandSpec {
    let mut args = Vec::new();
    if ipv6 {
        args.push("-6".to_string());
    }
    args.push("rule".to_string());
    args.push(op.to_string());
    args.push("priority".to_string());
    args.push(crate::socket_mark::ROUTING_RULE_PRIORITY.to_string());
    args.push("not".to_string());
    args.push("fwmark".to_string());
    args.push(crate::socket_mark::OUTER_SOCKET_MARK.to_string());
    args.push("table".to_string());
    args.push(crate::socket_mark::ROUTING_TABLE.to_string());
    CommandSpec::new("ip", args)
}

fn cleanup_route_commands(config: &GatewayConfig, interface_name: &str) -> Vec<CommandSpec> {
    let mut commands = Vec::new();
    if !table_is_off(config) {
        for peer in &config.peers {
            commands.extend(cleanup_peer_route_commands(peer, interface_name));
        }
        commands.extend(flush_policy_table_commands(config));
        commands.extend(cleanup_policy_rule_commands(config));

        for addr in &config.interface.addresses {
            commands.push(CommandSpec::new(
                "ip",
                vec![
                    "addr".to_string(),
                    "del".to_string(),
                    addr.to_string(),
                    "dev".to_string(),
                    interface_name.to_string(),
                ],
            ));
        }
    }

    commands.push(tun_link_delete_command(interface_name));
    commands
}

fn cleanup_peer_route_commands(peer: &PeerConfig, interface_name: &str) -> Vec<CommandSpec> {
    peer.allowed_ips
        .iter()
        .map(|allowed_ip| {
            if matches!(allowed_ip, ipnet::IpNet::V4(_)) {
                CommandSpec::new(
                    "ip",
                    vec![
                        "route".to_string(),
                        "del".to_string(),
                        allowed_ip.to_string(),
                        "dev".to_string(),
                        interface_name.to_string(),
                        "table".to_string(),
                        crate::socket_mark::ROUTING_TABLE.to_string(),
                    ],
                )
            } else {
                CommandSpec::new(
                    "ip",
                    vec![
                        "-6".to_string(),
                        "route".to_string(),
                        "del".to_string(),
                        allowed_ip.to_string(),
                        "dev".to_string(),
                        interface_name.to_string(),
                        "table".to_string(),
                        crate::socket_mark::ROUTING_TABLE.to_string(),
                    ],
                )
            }
        })
        .collect()
}

fn tun_link_delete_command(interface_name: &str) -> CommandSpec {
    CommandSpec::new(
        "ip",
        vec![
            "link".to_string(),
            "delete".to_string(),
            interface_name.to_string(),
        ],
    )
}

#[cfg(not(tarpaulin))]
fn cleanup_tun_link(interface_name: &str) {
    let command = tun_link_delete_command(interface_name);
    run_command_best_effort(command.program, &command.args);
}

#[cfg(not(tarpaulin))]
fn run_command_checked(program: &str, args: &[String]) -> Result<(), String> {
    let mut attempts = 0;
    loop {
        attempts += 1;
        let output = std::process::Command::new(program)
            .args(args)
            .output()
            .map_err(|e| format!("failed to execute '{} {}': {}", program, args.join(" "), e))?;
        if output.status.success() {
            return Ok(());
        } else {
            let err_msg = String::from_utf8_lossy(&output.stderr);
            if attempts < 30 && err_msg.contains("No such device") {
                log::warn!(
                    "Command '{} {}' failed with 'No such device', retrying in 50ms... (attempt {})",
                    program,
                    args.join(" "),
                    attempts
                );
                std::thread::sleep(std::time::Duration::from_millis(50));
                continue;
            }
            return Err(format!(
                "command '{} {}' failed with status {:?}: {}",
                program,
                args.join(" "),
                output.status.code(),
                err_msg.trim()
            ));
        }
    }
}

#[cfg(not(tarpaulin))]
fn run_command_best_effort(program: &str, args: &[String]) {
    if let Err(e) = run_command_checked(program, args) {
        log::debug!("{}", e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{InterfaceConfig, PeerConfig, QUICPoolConfig};

    fn config_with_table(table: Option<&str>) -> GatewayConfig {
        GatewayConfig {
            interface: InterfaceConfig {
                private_key: [1u8; 32],
                addresses: vec!["10.0.0.2/24".parse().unwrap()],
                listen_port: None,
                listen_control_port: None,
                mtu: 1400,
                table: table.map(str::to_string),
                pre_script: None,
                post_script: None,
            },
            peers: Vec::new(),
            quic_pool: QUICPoolConfig {
                public_ipv4: None,
                public_ipv6: None,
                listen_ports: Vec::new(),
            },
        }
    }

    fn peer_with_allowed_ips(allowed_ips: &[&str]) -> PeerConfig {
        PeerConfig {
            public_key: [2u8; 32],
            allowed_ips: allowed_ips
                .iter()
                .map(|allowed_ip| allowed_ip.parse().unwrap())
                .collect(),
            endpoint: None,
            proxy_port: None,
        }
    }

    #[test]
    fn table_is_off_is_case_insensitive() {
        assert!(table_is_off(&config_with_table(Some("off"))));
        assert!(table_is_off(&config_with_table(Some("OFF"))));
        assert!(table_is_off(&config_with_table(Some("Off"))));
    }

    #[test]
    fn table_is_off_rejects_auto_and_missing_values() {
        assert!(!table_is_off(&config_with_table(Some("auto"))));
        assert!(!table_is_off(&config_with_table(None)));
    }

    #[test]
    fn setup_route_commands_include_addresses_link_and_peer_routes() {
        let mut config = config_with_table(Some("auto"));
        config.interface.addresses = vec![
            "10.0.0.2/24".parse().unwrap(),
            "fd00::2/64".parse().unwrap(),
        ];
        config.interface.mtu = 1280;
        config.peers = vec![peer_with_allowed_ips(&["10.10.0.0/16", "fd10::/64"])];

        let commands = setup_route_commands(&config, "np0");

        assert_eq!(
            commands,
            vec![
                CommandSpec::new(
                    "ip",
                    vec!["addr", "replace", "10.0.0.2/24", "dev", "np0"]
                        .into_iter()
                        .map(str::to_string)
                        .collect()
                ),
                CommandSpec::new(
                    "ip",
                    vec!["addr", "replace", "fd00::2/64", "dev", "np0"]
                        .into_iter()
                        .map(str::to_string)
                        .collect()
                ),
                CommandSpec::new(
                    "ip",
                    vec!["link", "set", "np0", "up", "mtu", "1280"]
                        .into_iter()
                        .map(str::to_string)
                        .collect()
                ),
                CommandSpec::new(
                    "ip",
                    vec![
                        "route",
                        "replace",
                        "10.10.0.0/16",
                        "dev",
                        "np0",
                        "table",
                        &crate::socket_mark::ROUTING_TABLE.to_string(),
                    ]
                    .into_iter()
                    .map(str::to_string)
                    .collect()
                ),
                CommandSpec::new(
                    "ip",
                    vec![
                        "-6",
                        "route",
                        "replace",
                        "fd10::/64",
                        "dev",
                        "np0",
                        "table",
                        &crate::socket_mark::ROUTING_TABLE.to_string(),
                    ]
                    .into_iter()
                    .map(str::to_string)
                    .collect()
                ),
                main_suppress_rule_command(false, "add"),
                policy_rule_command(false, "add"),
                main_suppress_rule_command(true, "add"),
                policy_rule_command(true, "add"),
            ]
        );
    }

    #[test]
    fn setup_route_commands_are_empty_when_table_is_off() {
        let mut config = config_with_table(Some("off"));
        config.peers = vec![peer_with_allowed_ips(&["10.10.0.0/16"])];

        assert!(setup_route_commands(&config, "np0").is_empty());
    }

    #[test]
    fn cleanup_route_commands_skip_routes_when_table_is_off_but_delete_link() {
        let mut config = config_with_table(Some("off"));
        config.peers = vec![peer_with_allowed_ips(&["10.10.0.0/16", "fd10::/64"])];

        assert_eq!(
            cleanup_route_commands(&config, "np0"),
            vec![CommandSpec::new(
                "ip",
                vec!["link", "delete", "np0"]
                    .into_iter()
                    .map(str::to_string)
                    .collect()
            )]
        );
    }

    #[test]
    fn cleanup_route_commands_delete_peer_routes_addresses_and_link() {
        let mut config = config_with_table(None);
        config.peers = vec![peer_with_allowed_ips(&["10.10.0.0/16", "fd10::/64"])];

        let commands = cleanup_route_commands(&config, "np0");

        assert_eq!(
            commands,
            vec![
                CommandSpec::new(
                    "ip",
                    vec![
                        "route",
                        "del",
                        "10.10.0.0/16",
                        "dev",
                        "np0",
                        "table",
                        &crate::socket_mark::ROUTING_TABLE.to_string(),
                    ]
                    .into_iter()
                    .map(str::to_string)
                    .collect()
                ),
                CommandSpec::new(
                    "ip",
                    vec![
                        "-6",
                        "route",
                        "del",
                        "fd10::/64",
                        "dev",
                        "np0",
                        "table",
                        &crate::socket_mark::ROUTING_TABLE.to_string(),
                    ]
                    .into_iter()
                    .map(str::to_string)
                    .collect()
                ),
                flush_policy_table_command(false),
                flush_policy_table_command(true),
                policy_rule_command(false, "del"),
                main_suppress_rule_command(false, "del"),
                policy_rule_command(true, "del"),
                main_suppress_rule_command(true, "del"),
                CommandSpec::new(
                    "ip",
                    vec!["addr", "del", "10.0.0.2/24", "dev", "np0"]
                        .into_iter()
                        .map(str::to_string)
                        .collect()
                ),
                CommandSpec::new(
                    "ip",
                    vec!["link", "delete", "np0"]
                        .into_iter()
                        .map(str::to_string)
                        .collect()
                ),
            ]
        );
    }

    #[test]
    fn policy_rule_commands_skip_marked_outer_sockets() {
        assert_eq!(
            main_suppress_rule_command(false, "add"),
            CommandSpec::new(
                "ip",
                vec![
                    "rule",
                    "add",
                    "priority",
                    &crate::socket_mark::MAIN_SUPPRESS_RULE_PRIORITY.to_string(),
                    "table",
                    "main",
                    "suppress_prefixlength",
                    "0",
                ]
                .into_iter()
                .map(str::to_string)
                .collect()
            )
        );
        assert_eq!(
            policy_rule_command(false, "add"),
            CommandSpec::new(
                "ip",
                vec![
                    "rule",
                    "add",
                    "priority",
                    &crate::socket_mark::ROUTING_RULE_PRIORITY.to_string(),
                    "not",
                    "fwmark",
                    &crate::socket_mark::OUTER_SOCKET_MARK.to_string(),
                    "table",
                    &crate::socket_mark::ROUTING_TABLE.to_string(),
                ]
                .into_iter()
                .map(str::to_string)
                .collect()
            )
        );
    }

    #[test]
    #[cfg(not(tarpaulin))]
    fn run_script_reports_failures() {
        assert!(run_script("exit 0").is_ok());
        let err = run_script("echo pre-script-failed >&2; exit 7").unwrap_err();
        assert!(err.contains("pre-script-failed"));
        assert!(err.contains("status"));
    }
}
