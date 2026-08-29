use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

fn workspace() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("bloom-signer belongs to its workspace")
        .to_path_buf()
}

fn production_bloom_packages(package: &str) -> BTreeSet<String> {
    let output = Command::new(env!("CARGO"))
        .args([
            "tree",
            "-p",
            package,
            "--all-features",
            "--edges",
            "normal,build",
            "--prefix",
            "none",
        ])
        .current_dir(workspace())
        .output()
        .expect("run cargo tree for a production package graph");
    assert!(
        output.status.success(),
        "cargo tree failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("cargo tree output is UTF-8")
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .filter(|name| name.starts_with("bloom-"))
        .map(str::to_owned)
        .collect()
}

#[test]
fn production_signer_reports_its_semantic_version_without_starting_services() {
    let output = Command::new(env!("CARGO_BIN_EXE_bloom-signer"))
        .arg("--version")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap().trim(),
        format!("bloom-signer {}", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn production_signer_dependency_graph_has_no_machine_broker_or_debug_driver() {
    let actual = production_bloom_packages("bloom-signer");
    let allowed = BTreeSet::from_iter(
        [
            "bloom-audit-checkpoint",
            "bloom-platform-containment",
            "bloom-rpc-wire",
            "bloom-service-activation",
            "bloom-service-observability",
            "bloom-signer",
            "bloom-signer-api",
            "bloom-signer-backend-api",
            "bloom-signer-backend-aws-kms",
            "bloom-signer-backend-local",
            "bloom-triad-local-transport",
            "bloom-trusted-time",
        ]
        .map(str::to_owned),
    );
    assert_eq!(actual, allowed, "unexpected package crossed into Signer");
}

#[test]
fn signer_api_dependency_graph_contains_only_its_mechanical_wire_package() {
    assert_eq!(
        production_bloom_packages("bloom-signer-api"),
        BTreeSet::from(["bloom-rpc-wire".into(), "bloom-signer-api".into()]),
        "Signer API gained another Bloom domain or service dependency"
    );
}
