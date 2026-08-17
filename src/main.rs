use new_proxy::v1_config::{ApplianceConfig, IpPolicy};
use new_proxy::xdp_datapath::runtime;

#[cfg(target_os = "linux")]
#[global_allocator]
static GLOBAL_ALLOCATOR: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let config_path = parse_config_path(std::env::args().skip(1));
    let config = ApplianceConfig::load(&config_path).unwrap_or_else(|error| {
        eprintln!("failed to load v1 config {config_path}: {error}");
        std::process::exit(2);
    });
    log_config_summary(&config);
    if let Err(error) = runtime::run(config) {
        eprintln!("new_proxy v1 runtime failed: {error}");
        std::process::exit(1);
    }
}

fn parse_config_path(mut arguments: impl Iterator<Item = String>) -> String {
    let mut config_path = None;
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--config" => {
                config_path = Some(arguments.next().unwrap_or_else(|| {
                    eprintln!("{argument} requires a path");
                    std::process::exit(2);
                }));
            }
            "-h" | "--help" => {
                println!("Usage: new_proxy --config PATH");
                std::process::exit(0);
            }
            _ => {
                eprintln!("unknown argument: {argument}");
                std::process::exit(2);
            }
        }
    }
    config_path.unwrap_or_else(|| {
        eprintln!("missing required --config PATH");
        std::process::exit(2);
    })
}

fn log_config_summary(config: &ApplianceConfig) {
    let (mode, prefixes) = match &config.ip_policy {
        IpPolicy::TunnelPrefixes(prefixes) => ("tunnel-prefixes", prefixes),
        IpPolicy::DirectPrefixes(prefixes) => ("direct-prefixes", prefixes),
    };
    let ipv4_prefixes = prefixes
        .iter()
        .filter(|prefix| matches!(prefix, ipnet::IpNet::V4(_)))
        .count();
    let ipv6_prefixes = prefixes.len() - ipv4_prefixes;
    let remote_domains = config
        .dns
        .as_ref()
        .map_or(0, |dns| dns.remote_domains.len());
    log::info!(
        "loaded policy mode={mode} prefixes={} ipv4_prefixes={ipv4_prefixes} ipv6_prefixes={ipv6_prefixes} remote_domains={remote_domains}",
        prefixes.len()
    );
}
