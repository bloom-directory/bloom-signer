use std::path::Path;
use std::process::Command;

#[test]
fn production_signer_dependency_graph_has_no_machine_broker_or_debug_driver() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("bloom-signer belongs to its workspace");
    let output = Command::new(env!("CARGO"))
        .args([
            "tree",
            "-p",
            "bloom-signer",
            "--edges",
            "normal,build",
            "--prefix",
            "none",
        ])
        .current_dir(workspace)
        .output()
        .expect("run cargo tree for the production Signer graph");
    assert!(
        output.status.success(),
        "cargo tree failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let graph = String::from_utf8(output.stdout).expect("cargo tree output is UTF-8");
    for forbidden in [
        "bloom-machine ",
        "bloom-machine-client ",
        "bloom-broker ",
        "bloom-broker-api ",
        "bloom-broker-debug-driver ",
    ] {
        assert!(
            !graph.contains(forbidden),
            "production Signer graph contains forbidden dependency {forbidden}:\n{graph}"
        );
    }
}
