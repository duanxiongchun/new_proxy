use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=src/xdp_datapath/xdp_filter.c");

    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux") {
        return;
    }

    let output =
        PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is set")).join("xdp_filter.o");
    let clang = env::var("CLANG").unwrap_or_else(|_| "clang".to_string());
    let mut command = Command::new(clang);
    command.args(["-target", "bpf", "-g", "-O2"]);

    if let Some(multiarch) = multiarch_include() {
        command.arg(format!("-I/usr/include/{multiarch}"));
    }

    let status = command
        .args(["-c", "src/xdp_datapath/xdp_filter.c", "-o"])
        .arg(&output)
        .status()
        .expect("failed to execute clang for the XDP object");
    assert!(status.success(), "failed to compile the XDP object");
}

fn multiarch_include() -> Option<String> {
    if let Ok(value) = env::var("MULTIARCH") {
        return (!value.trim().is_empty()).then(|| value.trim().to_string());
    }

    let output = Command::new("gcc").arg("-print-multiarch").output().ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8(output.stdout).ok()?;
    (!value.trim().is_empty()).then(|| value.trim().to_string())
}
