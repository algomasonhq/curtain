use std::{fs, process::Command};
#[test]
fn cli_build_verify_and_bench() {
    let dir = std::env::temp_dir().join(format!("curtain-compact-test-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let input = dir.join("canonical.tsv");
    let artifact = dir.join("index.fc");
    let queries = dir.join("queries.tsv");
    fs::write(&input,"exact\ta.example\ts1\nexact\ta.example\ts2\nsuffix\ta.example\ts2\nallow-exact\tok.a.example\ts3\n").unwrap();
    fs::write(
        &queries,
        "hit\ta.example\nsubdomain\tx.a.example\nallow\tok.a.example\nmiss\tx.diverse.invalid\n",
    )
    .unwrap();
    let bin = env!("CARGO_BIN_EXE_compact-index");
    for args in [
        vec!["build", input.to_str().unwrap(), artifact.to_str().unwrap()],
        vec![
            "verify",
            artifact.to_str().unwrap(),
            input.to_str().unwrap(),
            queries.to_str().unwrap(),
        ],
        vec![
            "mmap",
            artifact.to_str().unwrap(),
            queries.to_str().unwrap(),
        ],
        vec!["hash", input.to_str().unwrap(), queries.to_str().unwrap()],
        vec!["sorted", input.to_str().unwrap(), queries.to_str().unwrap()],
    ] {
        let output = Command::new(bin).args(&args).output().unwrap();
        assert!(
            output.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap();
    }
    fs::write(&artifact, b"truncated").unwrap();
    assert!(
        !Command::new(bin)
            .args([
                "mmap",
                artifact.to_str().unwrap(),
                queries.to_str().unwrap()
            ])
            .output()
            .unwrap()
            .status
            .success()
    );
    fs::remove_dir_all(dir).unwrap();
}
