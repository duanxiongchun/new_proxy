use new_proxy::v1_config::ApplianceConfig;
use new_proxy::xdp_datapath::runtime;

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let config_path = parse_config_path(std::env::args().skip(1));
    let config = ApplianceConfig::load(&config_path).unwrap_or_else(|error| {
        eprintln!("failed to load v1 config {config_path}: {error}");
        std::process::exit(2);
    });
    if let Err(error) = runtime::run(config) {
        eprintln!("new_proxy v1 runtime failed: {error}");
        std::process::exit(1);
    }
}

fn parse_config_path(mut arguments: impl Iterator<Item = String>) -> String {
    let mut config_path = "conf/client.conf".to_string();
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "-config" | "--config" => {
                config_path = arguments.next().unwrap_or_else(|| {
                    eprintln!("{argument} requires a path");
                    std::process::exit(2);
                });
            }
            "-h" | "--help" => {
                println!("Usage: new_proxy [-config PATH]");
                std::process::exit(0);
            }
            _ => {
                eprintln!("unknown argument: {argument}");
                std::process::exit(2);
            }
        }
    }
    config_path
}
