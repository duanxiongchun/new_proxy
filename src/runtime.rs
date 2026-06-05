use crate::config::{GatewayConfig, PeerConfig};
use std::collections::HashSet;
use std::net::IpAddr;

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

#[cfg(tarpaulin)]
pub fn run_script(_script: &str) {}

#[cfg(not(tarpaulin))]
pub fn cleanup_runtime(config: &GatewayConfig, interface_name: &str) {
    cleanup_routes(config, interface_name);
    if let Some(ref post_script) = config.interface.post_script {
        run_script(post_script);
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

    setup_endpoint_bypass_routes(config, interface_name)?;

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
    if let Some(endpoint) = peer.endpoint {
        setup_endpoint_bypass_route(endpoint.ip(), interface_name)?;
    }
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
    for command in cleanup_peer_endpoint_bypass_route_commands(peer) {
        run_command_best_effort(command.program, &command.args);
    }
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

    commands
}

#[cfg(not(tarpaulin))]
fn setup_endpoint_bypass_routes(
    config: &GatewayConfig,
    interface_name: &str,
) -> Result<(), String> {
    let endpoints = config
        .peers
        .iter()
        .filter_map(|peer| peer.endpoint.map(|endpoint| endpoint.ip()))
        .collect::<HashSet<_>>();

    for endpoint_ip in endpoints {
        setup_endpoint_bypass_route(endpoint_ip, interface_name)?;
    }

    Ok(())
}

#[cfg(tarpaulin)]
fn setup_endpoint_bypass_routes(
    _config: &GatewayConfig,
    _interface_name: &str,
) -> Result<(), String> {
    Ok(())
}

#[cfg(not(tarpaulin))]
fn setup_endpoint_bypass_route(endpoint_ip: IpAddr, interface_name: &str) -> Result<(), String> {
    let route = discover_endpoint_route(endpoint_ip)?;
    if route.dev == interface_name {
        return Err(format!(
            "outer endpoint {} already routes through {}; refusing to install recursive tunnel route",
            endpoint_ip, interface_name
        ));
    }
    let command = endpoint_bypass_route_command(endpoint_ip, route);
    run_command_checked(command.program, &command.args)
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct EndpointRoute {
    dev: String,
    via: Option<IpAddr>,
}

#[cfg(not(tarpaulin))]
fn discover_endpoint_route(endpoint_ip: IpAddr) -> Result<EndpointRoute, String> {
    let args = route_get_command(endpoint_ip);
    let output = std::process::Command::new("ip")
        .args(&args)
        .output()
        .map_err(|e| format!("failed to execute 'ip {}': {}", args.join(" "), e))?;
    if !output.status.success() {
        return Err(format!(
            "command 'ip {}' failed with status {:?}: {}",
            args.join(" "),
            output.status.code(),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    parse_route_get_output(endpoint_ip, &String::from_utf8_lossy(&output.stdout))
}

fn route_get_command(endpoint_ip: IpAddr) -> Vec<String> {
    if endpoint_ip.is_ipv6() {
        vec![
            "-6".to_string(),
            "route".to_string(),
            "get".to_string(),
            endpoint_ip.to_string(),
        ]
    } else {
        vec![
            "route".to_string(),
            "get".to_string(),
            endpoint_ip.to_string(),
        ]
    }
}

fn parse_route_get_output(endpoint_ip: IpAddr, output: &str) -> Result<EndpointRoute, String> {
    let tokens = output.split_whitespace().collect::<Vec<_>>();
    let dev = tokens
        .windows(2)
        .find_map(|window| (window[0] == "dev").then(|| window[1].to_string()))
        .ok_or_else(|| {
            format!(
                "failed to discover outgoing device for outer endpoint {} from route output: {}",
                endpoint_ip,
                output.trim()
            )
        })?;
    let via = tokens
        .windows(2)
        .find_map(|window| (window[0] == "via").then_some(window[1]))
        .map(|ip| {
            ip.parse::<IpAddr>().map_err(|e| {
                format!(
                    "failed to parse gateway '{}' for outer endpoint {}: {}",
                    ip, endpoint_ip, e
                )
            })
        })
        .transpose()?;
    Ok(EndpointRoute { dev, via })
}

fn endpoint_bypass_route_command(endpoint_ip: IpAddr, route: EndpointRoute) -> CommandSpec {
    let prefix = if endpoint_ip.is_ipv6() {
        format!("{}/128", endpoint_ip)
    } else {
        format!("{}/32", endpoint_ip)
    };
    let mut args = Vec::new();
    if endpoint_ip.is_ipv6() {
        args.push("-6".to_string());
    }
    args.extend(
        ["route", "replace", &prefix]
            .into_iter()
            .map(str::to_string),
    );
    if let Some(via) = route.via {
        args.push("via".to_string());
        args.push(via.to_string());
    }
    args.push("dev".to_string());
    args.push(route.dev);
    args.push("metric".to_string());
    args.push("1".to_string());
    CommandSpec::new("ip", args)
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
                    ],
                )
            }
        })
        .collect()
}

fn cleanup_route_commands(config: &GatewayConfig, interface_name: &str) -> Vec<CommandSpec> {
    let mut commands = Vec::new();
    if !table_is_off(config) {
        commands.extend(cleanup_endpoint_bypass_route_commands(config));

        for peer in &config.peers {
            commands.extend(cleanup_peer_route_commands(peer, interface_name));
        }

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

fn cleanup_endpoint_bypass_route_commands(config: &GatewayConfig) -> Vec<CommandSpec> {
    config
        .peers
        .iter()
        .filter_map(|peer| peer.endpoint.map(|endpoint| endpoint.ip()))
        .collect::<HashSet<_>>()
        .into_iter()
        .map(cleanup_endpoint_bypass_route_command)
        .collect()
}

fn cleanup_peer_endpoint_bypass_route_commands(peer: &PeerConfig) -> Vec<CommandSpec> {
    peer.endpoint
        .map(|endpoint| endpoint.ip())
        .map(cleanup_endpoint_bypass_route_command)
        .into_iter()
        .collect()
}

fn cleanup_endpoint_bypass_route_command(endpoint_ip: IpAddr) -> CommandSpec {
    let prefix = if endpoint_ip.is_ipv6() {
        format!("{}/128", endpoint_ip)
    } else {
        format!("{}/32", endpoint_ip)
    };
    let mut args = Vec::new();
    if endpoint_ip.is_ipv6() {
        args.push("-6".to_string());
    }
    args.extend(["route", "del", &prefix].into_iter().map(str::to_string));
    args.push("metric".to_string());
    args.push("1".to_string());
    CommandSpec::new("ip", args)
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
                    vec!["route", "replace", "10.10.0.0/16", "dev", "np0"]
                        .into_iter()
                        .map(str::to_string)
                        .collect()
                ),
                CommandSpec::new(
                    "ip",
                    vec!["-6", "route", "replace", "fd10::/64", "dev", "np0"]
                        .into_iter()
                        .map(str::to_string)
                        .collect()
                ),
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
                    vec!["route", "del", "10.10.0.0/16", "dev", "np0"]
                        .into_iter()
                        .map(str::to_string)
                        .collect()
                ),
                CommandSpec::new(
                    "ip",
                    vec!["-6", "route", "del", "fd10::/64", "dev", "np0"]
                        .into_iter()
                        .map(str::to_string)
                        .collect()
                ),
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
    fn parse_route_get_output_extracts_gateway_and_device() {
        let route = parse_route_get_output(
            "203.0.113.10".parse().unwrap(),
            "203.0.113.10 via 192.0.2.1 dev eth0 src 192.0.2.10 uid 1000\n    cache",
        )
        .unwrap();

        assert_eq!(
            route,
            EndpointRoute {
                dev: "eth0".to_string(),
                via: Some("192.0.2.1".parse().unwrap()),
            }
        );
    }

    #[test]
    fn endpoint_bypass_route_commands_are_host_routes() {
        let v4 = endpoint_bypass_route_command(
            "203.0.113.10".parse().unwrap(),
            EndpointRoute {
                dev: "eth0".to_string(),
                via: Some("192.0.2.1".parse().unwrap()),
            },
        );
        assert_eq!(
            v4,
            CommandSpec::new(
                "ip",
                vec![
                    "route",
                    "replace",
                    "203.0.113.10/32",
                    "via",
                    "192.0.2.1",
                    "dev",
                    "eth0",
                    "metric",
                    "1",
                ]
                .into_iter()
                .map(str::to_string)
                .collect()
            )
        );

        let v6 = endpoint_bypass_route_command(
            "2001:db8::10".parse().unwrap(),
            EndpointRoute {
                dev: "eth1".to_string(),
                via: None,
            },
        );
        assert_eq!(
            v6,
            CommandSpec::new(
                "ip",
                vec![
                    "-6",
                    "route",
                    "replace",
                    "2001:db8::10/128",
                    "dev",
                    "eth1",
                    "metric",
                    "1",
                ]
                .into_iter()
                .map(str::to_string)
                .collect()
            )
        );

        let cleanup = cleanup_endpoint_bypass_route_command("203.0.113.10".parse().unwrap());
        assert_eq!(
            cleanup,
            CommandSpec::new(
                "ip",
                vec!["route", "del", "203.0.113.10/32", "metric", "1"]
                    .into_iter()
                    .map(str::to_string)
                    .collect()
            )
        );
    }
}
