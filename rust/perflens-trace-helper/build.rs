use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=bpf/perflens_sched.bpf.c");
    println!("cargo:rerun-if-changed=bpf/perflens_lock.bpf.c");

    let output = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is set by Cargo"));
    let architecture = env::var("CARGO_CFG_TARGET_ARCH").expect("target architecture is set");
    let target_macro = match architecture.as_str() {
        "x86_64" => "__TARGET_ARCH_x86",
        "aarch64" => "__TARGET_ARCH_arm64",
        other => panic!("unsupported eBPF target architecture: {other}"),
    };
    compile_bpf(
        Path::new("bpf/perflens_sched.bpf.c"),
        &output.join("perflens_sched.bpf.o"),
        target_macro,
    );
    compile_bpf(
        Path::new("bpf/perflens_lock.bpf.c"),
        &output.join("perflens_lock.bpf.o"),
        target_macro,
    );
}

fn compile_bpf(source: &Path, output: &Path, target_macro: &str) {
    let multiarch = Command::new("gcc")
        .arg("-dumpmachine")
        .output()
        .expect("gcc is required to locate Debian multiarch headers");
    assert!(multiarch.status.success(), "gcc -dumpmachine failed");
    let multiarch = String::from_utf8(multiarch.stdout)
        .expect("gcc multiarch output is UTF-8")
        .trim()
        .to_owned();
    let status = Command::new("clang")
        .args([
            "-O2",
            "-g",
            "-target",
            "bpf",
            "-Wall",
            "-Werror",
            "-D",
            target_macro,
            "-ffile-prefix-map=.=.",
            "-fdebug-prefix-map=.=.",
            "-I",
            &format!("/usr/include/{multiarch}"),
            "-c",
        ])
        .arg(source)
        .arg("-o")
        .arg(output)
        .status()
        .expect("clang is required to build the fixed eBPF objects");
    assert!(status.success(), "failed to build {}", source.display());
}
