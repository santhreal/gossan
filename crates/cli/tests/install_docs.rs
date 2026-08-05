//! Install surface contracts for the patch release.
//!
//! Guarantees the README still documents GitHub Releases copy-paste paths
//! and that the install scripts exist and parse.

#[test]
fn readme_documents_github_release_install_for_every_os() {
    let readme = include_str!("../../../README.md");
    for needle in [
        "scripts/install.sh",
        "scripts/install.ps1",
        "gossan-x86_64-unknown-linux-gnu.tar.gz",
        "gossan-aarch64-unknown-linux-gnu.tar.gz",
        "gossan-x86_64-apple-darwin.tar.gz",
        "gossan-aarch64-apple-darwin.tar.gz",
        "gossan-x86_64-pc-windows-msvc.zip",
        "releases/latest/download",
        "export PATH=",
        ".sha256",
    ] {
        assert!(
            readme.contains(needle),
            "README.md missing install contract needle: {needle}"
        );
    }
    let documents_modules_flag = readme.contains("--modules ");
    assert_eq!(
        documents_modules_flag,
        false,
        "README must not document nonexistent --modules flag"
    );
}

#[test]
fn install_scripts_exist_and_are_nonempty() {
    let sh = include_str!("../../../scripts/install.sh");
    let ps1 = include_str!("../../../scripts/install.ps1");
    assert!(sh.contains("releases/latest/download"));
    assert!(sh.contains("GOSSAN_INSTALL_DIR"));
    assert!(ps1.contains("releases/latest/download"));
    assert!(ps1.contains("InstallDir"));
}

#[test]
fn release_workflow_publishes_stable_asset_names() {
    let yml = include_str!("../../../.github/workflows/release.yml");
    assert!(yml.contains("gossan-${{ matrix.target }}"));
    assert!(yml.contains("softprops/action-gh-release"));
    assert!(
        yml.contains("scripts/publish.sh"),
        "release workflow must auto-publish crates.io packages on tag"
    );
    assert!(
        yml.contains("CARGO_REGISTRY_TOKEN"),
        "release workflow must pass CARGO_REGISTRY_TOKEN to publish"
    );
    for target in [
        "x86_64-unknown-linux-gnu",
        "aarch64-unknown-linux-gnu",
        "x86_64-apple-darwin",
        "aarch64-apple-darwin",
        "x86_64-pc-windows-msvc",
    ] {
        assert!(yml.contains(target), "release matrix missing {target}");
    }
}

#[test]
fn publish_script_exists_and_lists_workspace_crates() {
    let sh = include_str!("../../../scripts/publish.sh");
    assert!(sh.contains("CARGO_REGISTRY_TOKEN"));
    for crate_name in [
        "gossan-core",
        "gossan-keyhog-lite",
        "gossan-portscan",
        "gossan",
    ] {
        assert!(sh.contains(crate_name), "publish.sh missing {crate_name}");
    }
}
