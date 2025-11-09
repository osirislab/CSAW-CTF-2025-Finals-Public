use std::env;
use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use jolt_sdk::{F, JoltProverPreprocessing, JoltVerifierPreprocessing, PCS};
use tempfile::Builder;

fn main() {
    if let Err(err) = run() {
        panic!("preprocessing build step failed: {err:#}");
    }
}

fn run() -> Result<()> {
    println!("cargo:rerun-if-changed=guest/");

    let manifest_dir = env::var("CARGO_MANIFEST_DIR").context("CARGO_MANIFEST_DIR not set")?;
    let artifacts_dir = PathBuf::from(&manifest_dir).join("artifacts");
    if artifacts_dir.exists() {
        fs::remove_dir_all(&artifacts_dir).context("remove existing artifacts directory")?;
    }
    fs::create_dir_all(&artifacts_dir).context("create artifacts directory")?;

    let artifacts_str = artifacts_dir
        .to_str()
        .map(|s| s.to_owned())
        .unwrap_or_else(|| artifacts_dir.to_string_lossy().into_owned());

    let temp_dir = Builder::new()
        .prefix("allocation-gate-build-")
        .tempdir()
        .context("create temporary compilation directory")?;
    let compile_path = temp_dir.path().to_string_lossy().into_owned();

    let mut program = guest::compile_process_heap(&compile_path);
    let prover: JoltProverPreprocessing<F, PCS> =
        guest::preprocess_prover_process_heap(&mut program);
    let verifier: JoltVerifierPreprocessing<F, PCS> =
        guest::verifier_preprocessing_from_prover_process_heap(&prover);

    prover
        .save_to_target_dir(&artifacts_str)
        .context("store prover preprocessing")?;
    verifier
        .save_to_target_dir(&artifacts_str)
        .context("store verifier preprocessing")?;

    let elf_src = program
        .elf
        .as_ref()
        .context("guest ELF path missing after compilation")?;
    let elf_dest = PathBuf::from(&manifest_dir).join("program.so");
    fs::copy(elf_src, &elf_dest)
        .with_context(|| format!("copy guest ELF to {}", elf_dest.display()))?;

    Ok(())
}
