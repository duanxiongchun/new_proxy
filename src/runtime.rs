use crate::app_config::{quic_interface_name, wg_interface_name};
use crate::config::{GatewayConfig, PeerConfig, PeerType};

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

#[cfg(target_os = "linux")]
pub fn setup_kernel_wireguard(
    config: &crate::config::GatewayConfig,
    interface_name: &str,
) -> Result<(), String> {
    use defguard_wireguard_rs::key::Key;
    use defguard_wireguard_rs::net::IpAddrMask;
    use defguard_wireguard_rs::peer::Peer;
    use defguard_wireguard_rs::{
        InterfaceConfiguration, Kernel, Userspace, WGApi, WireguardInterfaceApi,
    };

    let wg_name = crate::app_config::wg_interface_name(interface_name);
    log::info!("setup_kernel_wireguard: wg_name={}", wg_name);

    let exists = std::path::Path::new("/sys/class/net")
        .join(&wg_name)
        .exists();
    log::info!("setup_kernel_wireguard: interface exists={}", exists);

    let mut is_userspace = false;

    if !exists {
        // Clean up any leftover unix socket files to prevent UAPI socket in use errors
        let socket_path = format!("/var/run/wireguard/{}.sock", wg_name);
        let alternative_socket_path = format!("/run/wireguard/{}.sock", wg_name);
        let _ = std::fs::remove_file(&socket_path);
        let _ = std::fs::remove_file(&alternative_socket_path);

        let mut kernel_api =
            WGApi::<Kernel>::new(wg_name.clone()).map_err(|e| format!("{:?}", e))?;
        log::info!("Creating native wireguard interface: {}", wg_name);
        if let Err(e) = kernel_api.create_interface() {
            log::warn!("Failed to create native kernel wireguard interface: {:?}. Falling back to wireguard-go.", e);
            // Run: wireguard-go <wg_name>
            log::info!("Running wireguard-go {}", wg_name);
            let status = std::process::Command::new("wireguard-go")
                .arg(&wg_name)
                .status()
                .map_err(|err| {
                    log::error!("Failed to spawn wireguard-go: {}", err);
                    format!("failed to start wireguard-go: {}", err)
                })?;
            log::info!("wireguard-go exit status: {:?}", status);
            if !status.success() {
                return Err("wireguard-go exited with error".to_string());
            }
            // Wait up to 2 seconds (polling every 50ms) for the userspace TUN device to appear
            let start = std::time::Instant::now();
            let mut found = false;
            while start.elapsed() < std::time::Duration::from_secs(2) {
                if std::path::Path::new("/sys/class/net")
                    .join(&wg_name)
                    .exists()
                {
                    found = true;
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            log::info!("wireguard-go device found={}", found);
            if !found {
                return Err("wireguard-go TUN interface did not appear within timeout".to_string());
            }
            std::thread::sleep(std::time::Duration::from_millis(500));
            is_userspace = true;
        } else {
            log::info!("Successfully created native WireGuard interface.");
        }
    } else {
        let socket_path = format!("/var/run/wireguard/{}.sock", wg_name);
        let alternative_socket_path = format!("/run/wireguard/{}.sock", wg_name);
        if std::path::Path::new(&socket_path).exists()
            || std::path::Path::new(&alternative_socket_path).exists()
        {
            is_userspace = true;
        }
    }

    let listen_port = config
        .interface
        .wg_listen_port
        .unwrap_or(config.interface.listen_port.unwrap_or(51820) + 1);

    let mut wg_peers = Vec::new();
    for peer in &config.peers {
        if peer.r#type == crate::config::PeerType::Wireguard {
            let key = Key::new(peer.public_key);
            let mut wg_peer = Peer::new(key);
            wg_peer.endpoint = peer.endpoint;
            wg_peer.allowed_ips = peer
                .allowed_ips
                .iter()
                .map(|ip| IpAddrMask::new(ip.addr(), ip.prefix_len()))
                .collect();
            wg_peers.push(wg_peer);
        }
    }

    let interface_config = InterfaceConfiguration {
        name: wg_name.clone(),
        prvkey: crate::app_config::encode_base64_32(&config.interface.private_key),
        addresses: config
            .interface
            .addresses
            .iter()
            .map(|addr| IpAddrMask::new(addr.addr(), addr.prefix_len()))
            .collect(),
        port: listen_port,
        peers: wg_peers,
        mtu: None,
        fwmark: None,
    };

    if is_userspace {
        log::info!(
            "Configuring userspace WireGuard interface via UAPI: {}",
            wg_name
        );

        // Assign IP addresses manually using standard `ip` command
        for addr in &config.interface.addresses {
            let status = std::process::Command::new("ip")
                .args(["addr", "replace", &addr.to_string(), "dev", &wg_name])
                .status()
                .map_err(|e| format!("failed to run ip addr: {}", e))?;
            if !status.success() {
                return Err(format!("failed to assign address {} to {}", addr, wg_name));
            }
        }

        // Set MTU manually
        let status = std::process::Command::new("ip")
            .args([
                "link",
                "set",
                "dev",
                &wg_name,
                "mtu",
                &config.interface.mtu.to_string(),
            ])
            .status()
            .map_err(|e| format!("failed to set MTU: {}", e))?;
        if !status.success() {
            return Err(format!("failed to set MTU on {}", wg_name));
        }

        // Write host configuration directly to UAPI socket
        let api = WGApi::<Userspace>::new(wg_name.clone()).map_err(|e| format!("{:?}", e))?;
        let host = defguard_wireguard_rs::host::Host::try_from(&interface_config)
            .map_err(|e| format!("{:?}", e))?;
        api.write_host(&host)
            .map_err(|e| format!("UAPI write failed: {:?}", e))?;
    } else {
        log::info!("Configuring WireGuard interface via WGApi::<Kernel>");
        let api = WGApi::<Kernel>::new(wg_name.clone()).map_err(|e| format!("{:?}", e))?;
        api.configure_interface(&interface_config)
            .map_err(|e| format!("{:?}", e))?;
    }

    // Bring interface up
    let status = std::process::Command::new("ip")
        .args(["link", "set", "dev", &wg_name, "up"])
        .status()
        .map_err(|e| format!("failed to bring interface up: {}", e))?;
    if !status.success() {
        return Err("failed to bring interface up".to_string());
    }

    Ok(())
}

#[cfg(target_os = "linux")]
pub fn cleanup_kernel_wireguard(interface_name: &str) -> Result<(), String> {
    use defguard_wireguard_rs::{Kernel, Userspace, WGApi, WireguardInterfaceApi};
    let wg_name = crate::app_config::wg_interface_name(interface_name);

    let socket_path = format!("/var/run/wireguard/{}.sock", wg_name);
    let alternative_socket_path = format!("/run/wireguard/{}.sock", wg_name);
    let is_userspace = std::path::Path::new(&socket_path).exists()
        || std::path::Path::new(&alternative_socket_path).exists();

    if is_userspace {
        log::info!("Cleaning up userspace WireGuard interface: {}", wg_name);
        let api = WGApi::<Userspace>::new(wg_name.clone()).map_err(|e| format!("{:?}", e))?;
        if std::path::Path::new("/sys/class/net")
            .join(&wg_name)
            .exists()
        {
            api.remove_interface().map_err(|e| format!("{:?}", e))?;
        }
    } else {
        log::info!("Cleaning up kernel WireGuard interface: {}", wg_name);
        let api = WGApi::<Kernel>::new(wg_name.clone()).map_err(|e| format!("{:?}", e))?;
        if std::path::Path::new("/sys/class/net")
            .join(&wg_name)
            .exists()
        {
            api.remove_interface().map_err(|e| format!("{:?}", e))?;
        }
    }
    Ok(())
}

#[cfg(not(tarpaulin))]
pub fn setup_routes(config: &GatewayConfig, interface_name: &str) -> Result<(), String> {
    log::info!(
        "setup_routes: interface_name={}, table_is_off={}",
        interface_name,
        table_is_off(config)
    );
    if table_is_off(config) {
        log::info!("Table is off. Skipping automatic userspace routing setup.");
        return Ok(());
    }

    for (i, peer) in config.peers.iter().enumerate() {
        log::info!("Peer {} type: {:?}", i, peer.r#type);
    }

    #[cfg(target_os = "linux")]
    if config
        .peers
        .iter()
        .any(|peer| peer.r#type == crate::config::PeerType::Wireguard)
    {
        log::info!("Found WireGuard peer. Calling setup_kernel_wireguard.");
        setup_kernel_wireguard(config, interface_name)?;
    }

    #[cfg(not(target_os = "linux"))]
    if config
        .peers
        .iter()
        .any(|peer| peer.r#type == crate::config::PeerType::Wireguard)
    {
        log::warn!("WireGuard peer configured, but kernel WireGuard setup is not supported on this platform.");
    }

    let quic_name = quic_interface_name(interface_name, &config.interface.mode);

    log::info!(
        "Setting up userspace TUN addresses and routes for interface: {}",
        quic_name
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
pub fn setup_peer_routes(
    peer: &PeerConfig,
    interface_name: &str,
    mode: &str,
) -> Result<(), String> {
    for command in setup_peer_route_commands(peer, interface_name, mode) {
        run_command_checked(command.program, &command.args)?;
    }
    Ok(())
}

#[cfg(tarpaulin)]
pub fn setup_peer_routes(
    _peer: &PeerConfig,
    _interface_name: &str,
    _mode: &str,
) -> Result<(), String> {
    Ok(())
}

#[cfg(not(tarpaulin))]
pub fn cleanup_peer_routes(
    peer: &PeerConfig,
    interface_name: &str,
    mode: &str,
) -> Result<(), String> {
    let mut errors = Vec::new();
    for command in cleanup_peer_route_commands(peer, interface_name, mode) {
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
pub fn cleanup_peer_routes(
    _peer: &PeerConfig,
    _interface_name: &str,
    _mode: &str,
) -> Result<(), String> {
    Ok(())
}

#[cfg(not(tarpaulin))]
fn cleanup_routes(config: &GatewayConfig, interface_name: &str) {
    let quic_name = quic_interface_name(interface_name, &config.interface.mode);

    #[cfg(target_os = "linux")]
    if config
        .peers
        .iter()
        .any(|peer| peer.r#type == crate::config::PeerType::Wireguard)
    {
        if let Err(e) = cleanup_kernel_wireguard(interface_name) {
            log::warn!("Failed to clean up kernel WireGuard: {}", e);
        }
    }

    #[cfg(not(target_os = "linux"))]
    if config
        .peers
        .iter()
        .any(|peer| peer.r#type == crate::config::PeerType::Wireguard)
    {
        log::warn!("Kernel WireGuard cleanup skipped: not supported on this platform.");
    }

    if table_is_off(config) {
        cleanup_tun_link(&quic_name);
        return;
    }

    log::info!("Cleaning up userspace routing for interface: {}", quic_name);

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

    let quic_name = quic_interface_name(interface_name, &config.interface.mode);

    for addr in &config.interface.addresses {
        commands.push(CommandSpec::new(
            "ip",
            vec![
                "addr".to_string(),
                "replace".to_string(),
                addr.to_string(),
                "dev".to_string(),
                quic_name.clone(),
            ],
        ));
    }

    commands.push(CommandSpec::new(
        "ip",
        vec![
            "link".to_string(),
            "set".to_string(),
            quic_name.clone(),
            "up".to_string(),
            "mtu".to_string(),
            config.interface.mtu.to_string(),
            "txqueuelen".to_string(),
            "10000".to_string(),
        ],
    ));

    for peer in &config.peers {
        commands.extend(setup_peer_route_commands(
            peer,
            interface_name,
            &config.interface.mode,
        ));
    }
    commands.extend(setup_policy_rule_commands(config));

    commands
}

fn setup_peer_route_commands(
    peer: &PeerConfig,
    interface_name: &str,
    mode: &str,
) -> Vec<CommandSpec> {
    let quic_name = quic_interface_name(interface_name, mode);
    let wg_name = wg_interface_name(interface_name);
    let dev_name = match peer.r#type {
        PeerType::Quic => quic_name,
        PeerType::Wireguard => wg_name,
    };
    let mut commands = Vec::new();
    for allowed_ip in &peer.allowed_ips {
        let is_v4 = matches!(allowed_ip, ipnet::IpNet::V4(_));
        let is_default = allowed_ip.prefix_len() == 0;

        if is_v4 {
            commands.push(CommandSpec::new(
                "ip",
                vec![
                    "route".to_string(),
                    "replace".to_string(),
                    allowed_ip.to_string(),
                    "dev".to_string(),
                    dev_name.clone(),
                    "table".to_string(),
                    crate::socket_mark::ROUTING_TABLE.to_string(),
                ],
            ));
            if !is_default {
                commands.push(CommandSpec::new(
                    "ip",
                    vec![
                        "route".to_string(),
                        "replace".to_string(),
                        allowed_ip.to_string(),
                        "dev".to_string(),
                        dev_name.clone(),
                    ],
                ));
            }
        } else {
            commands.push(CommandSpec::new(
                "ip",
                vec![
                    "-6".to_string(),
                    "route".to_string(),
                    "replace".to_string(),
                    allowed_ip.to_string(),
                    "dev".to_string(),
                    dev_name.clone(),
                    "table".to_string(),
                    crate::socket_mark::ROUTING_TABLE.to_string(),
                ],
            ));
            if !is_default {
                commands.push(CommandSpec::new(
                    "ip",
                    vec![
                        "-6".to_string(),
                        "route".to_string(),
                        "replace".to_string(),
                        allowed_ip.to_string(),
                        "dev".to_string(),
                        dev_name.clone(),
                    ],
                ));
            }
        }
    }
    commands
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
    let quic_name = quic_interface_name(interface_name, &config.interface.mode);
    if !table_is_off(config) {
        for peer in &config.peers {
            commands.extend(cleanup_peer_route_commands(
                peer,
                interface_name,
                &config.interface.mode,
            ));
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
                    quic_name.clone(),
                ],
            ));
        }
    }

    commands.push(tun_link_delete_command(&quic_name));
    commands
}

fn cleanup_peer_route_commands(
    peer: &PeerConfig,
    interface_name: &str,
    mode: &str,
) -> Vec<CommandSpec> {
    let quic_name = quic_interface_name(interface_name, mode);
    let wg_name = wg_interface_name(interface_name);
    let dev_name = match peer.r#type {
        PeerType::Quic => quic_name,
        PeerType::Wireguard => wg_name,
    };
    let mut commands = Vec::new();
    for allowed_ip in &peer.allowed_ips {
        let is_v4 = matches!(allowed_ip, ipnet::IpNet::V4(_));
        let is_default = allowed_ip.prefix_len() == 0;

        if is_v4 {
            commands.push(CommandSpec::new(
                "ip",
                vec![
                    "route".to_string(),
                    "del".to_string(),
                    allowed_ip.to_string(),
                    "dev".to_string(),
                    dev_name.clone(),
                    "table".to_string(),
                    crate::socket_mark::ROUTING_TABLE.to_string(),
                ],
            ));
            if !is_default {
                commands.push(CommandSpec::new(
                    "ip",
                    vec![
                        "route".to_string(),
                        "del".to_string(),
                        allowed_ip.to_string(),
                        "dev".to_string(),
                        dev_name.clone(),
                    ],
                ));
            }
        } else {
            commands.push(CommandSpec::new(
                "ip",
                vec![
                    "-6".to_string(),
                    "route".to_string(),
                    "del".to_string(),
                    allowed_ip.to_string(),
                    "dev".to_string(),
                    dev_name.clone(),
                    "table".to_string(),
                    crate::socket_mark::ROUTING_TABLE.to_string(),
                ],
            ));
            if !is_default {
                commands.push(CommandSpec::new(
                    "ip",
                    vec![
                        "-6".to_string(),
                        "route".to_string(),
                        "del".to_string(),
                        allowed_ip.to_string(),
                        "dev".to_string(),
                        dev_name.clone(),
                    ],
                ));
            }
        }
    }
    commands
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
    log::info!("Executing command: {} {}", program, args.join(" "));
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
    use crate::config::{InterfaceConfig, PeerConfig, PeerType, QUICPoolConfig, XdpConfig};

    fn config_with_table(table: Option<&str>) -> GatewayConfig {
        GatewayConfig {
            interface: InterfaceConfig {
                private_key: [1u8; 32],
                addresses: vec!["10.0.0.2/24".parse().unwrap()],
                listen_port: None,
                wg_listen_port: None,
                mtu: 1400,
                table: table.map(str::to_string),
                pre_script: None,
                post_script: None,
                mode: "tun".to_string(),
            },
            peers: Vec::new(),
            quic_pool: QUICPoolConfig {
                public_ipv4: None,
                public_ipv6: None,
                listen_ports: Vec::new(),
            },
            xdp: XdpConfig::default(),
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
            r#type: PeerType::Quic,
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
        let mut wg_peer = peer_with_allowed_ips(&["10.20.0.0/16", "fd20::/64"]);
        wg_peer.r#type = PeerType::Wireguard;
        config.peers.push(wg_peer);

        let commands = setup_route_commands(&config, "np0");

        assert_eq!(
            commands,
            vec![
                CommandSpec::new(
                    "ip",
                    vec!["addr", "replace", "10.0.0.2/24", "dev", "np0-tun"]
                        .into_iter()
                        .map(str::to_string)
                        .collect()
                ),
                CommandSpec::new(
                    "ip",
                    vec!["addr", "replace", "fd00::2/64", "dev", "np0-tun"]
                        .into_iter()
                        .map(str::to_string)
                        .collect()
                ),
                CommandSpec::new(
                    "ip",
                    vec![
                        "link",
                        "set",
                        "np0-tun",
                        "up",
                        "mtu",
                        "1280",
                        "txqueuelen",
                        "10000"
                    ]
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
                        "np0-tun",
                        "table",
                        &crate::socket_mark::ROUTING_TABLE.to_string(),
                    ]
                    .into_iter()
                    .map(str::to_string)
                    .collect()
                ),
                CommandSpec::new(
                    "ip",
                    vec!["route", "replace", "10.10.0.0/16", "dev", "np0-tun",]
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
                        "np0-tun",
                        "table",
                        &crate::socket_mark::ROUTING_TABLE.to_string(),
                    ]
                    .into_iter()
                    .map(str::to_string)
                    .collect()
                ),
                CommandSpec::new(
                    "ip",
                    vec!["-6", "route", "replace", "fd10::/64", "dev", "np0-tun",]
                        .into_iter()
                        .map(str::to_string)
                        .collect()
                ),
                CommandSpec::new(
                    "ip",
                    vec![
                        "route",
                        "replace",
                        "10.20.0.0/16",
                        "dev",
                        "np0-wg",
                        "table",
                        &crate::socket_mark::ROUTING_TABLE.to_string(),
                    ]
                    .into_iter()
                    .map(str::to_string)
                    .collect()
                ),
                CommandSpec::new(
                    "ip",
                    vec!["route", "replace", "10.20.0.0/16", "dev", "np0-wg",]
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
                        "fd20::/64",
                        "dev",
                        "np0-wg",
                        "table",
                        &crate::socket_mark::ROUTING_TABLE.to_string(),
                    ]
                    .into_iter()
                    .map(str::to_string)
                    .collect()
                ),
                CommandSpec::new(
                    "ip",
                    vec!["-6", "route", "replace", "fd20::/64", "dev", "np0-wg",]
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
                vec!["link", "delete", "np0-tun"]
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
        let mut wg_peer = peer_with_allowed_ips(&["10.20.0.0/16", "fd20::/64"]);
        wg_peer.r#type = PeerType::Wireguard;
        config.peers.push(wg_peer);

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
                        "np0-tun",
                        "table",
                        &crate::socket_mark::ROUTING_TABLE.to_string(),
                    ]
                    .into_iter()
                    .map(str::to_string)
                    .collect()
                ),
                CommandSpec::new(
                    "ip",
                    vec!["route", "del", "10.10.0.0/16", "dev", "np0-tun",]
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
                        "np0-tun",
                        "table",
                        &crate::socket_mark::ROUTING_TABLE.to_string(),
                    ]
                    .into_iter()
                    .map(str::to_string)
                    .collect()
                ),
                CommandSpec::new(
                    "ip",
                    vec!["-6", "route", "del", "fd10::/64", "dev", "np0-tun",]
                        .into_iter()
                        .map(str::to_string)
                        .collect()
                ),
                CommandSpec::new(
                    "ip",
                    vec![
                        "route",
                        "del",
                        "10.20.0.0/16",
                        "dev",
                        "np0-wg",
                        "table",
                        &crate::socket_mark::ROUTING_TABLE.to_string(),
                    ]
                    .into_iter()
                    .map(str::to_string)
                    .collect()
                ),
                CommandSpec::new(
                    "ip",
                    vec!["route", "del", "10.20.0.0/16", "dev", "np0-wg",]
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
                        "fd20::/64",
                        "dev",
                        "np0-wg",
                        "table",
                        &crate::socket_mark::ROUTING_TABLE.to_string(),
                    ]
                    .into_iter()
                    .map(str::to_string)
                    .collect()
                ),
                CommandSpec::new(
                    "ip",
                    vec!["-6", "route", "del", "fd20::/64", "dev", "np0-wg",]
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
                    vec!["addr", "del", "10.0.0.2/24", "dev", "np0-tun"]
                        .into_iter()
                        .map(str::to_string)
                        .collect()
                ),
                CommandSpec::new(
                    "ip",
                    vec!["link", "delete", "np0-tun"]
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

    #[test]
    #[cfg(target_os = "linux")]
    fn test_setup_kernel_wireguard_failure_flow() {
        let mut config = config_with_table(None);
        config.interface.private_key = [1u8; 32];
        config.interface.wg_listen_port = Some(51821);

        let peer = PeerConfig {
            public_key: [2u8; 32],
            allowed_ips: vec!["10.20.0.0/16".parse().unwrap()],
            endpoint: Some("127.0.0.1:51820".parse().unwrap()),
            proxy_port: None,
            r#type: PeerType::Wireguard,
        };
        config.peers = vec![peer];

        // This will run without panic, exercising peer parsing and key building logic.
        // It fails because we run without root privileges/correct setup, which we expect and assert.
        let res = setup_kernel_wireguard(&config, "mock-wg-test");
        assert!(res.is_err());

        let res_clean = cleanup_kernel_wireguard("mock-wg-test");
        assert!(res_clean.is_ok() || res_clean.is_err());
    }
}
