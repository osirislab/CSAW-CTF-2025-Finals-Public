#![allow(unsafe_op_in_unsafe_fn)]

use std::fs;
use std::path::{Path};
use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use jolt_sdk::{
    F, Jolt, JoltDevice, JoltProverPreprocessing, JoltRV64IMAC, JoltVerifierPreprocessing,
    MemoryConfig, PCS, RV64IMACJoltProof, Serializable, host::Program,
};
use postcard::{from_bytes, to_allocvec};
use serde::{Deserialize, Serialize};

pub const MAX_CHUNKS: u64 = 64;
pub const CHUNK_SIZE: u64 = 0x40;
pub const TOTAL_SIZE: u64 = MAX_CHUNKS * CHUNK_SIZE;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeapState {
    pub base_ptr: u64,
    pub bin_mask: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Command {
    Alloc { requested_size: u32 },
    Free { ptr: u64 },
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllocationOutput {
    pub state: HeapState,
    pub ptr: u64,
}

struct ProofContext {
    program: Arc<Program>,
    prover: Arc<JoltProverPreprocessing<F, PCS>>,
    verifier: Arc<JoltVerifierPreprocessing<F, PCS>>,
}

impl ProofContext {
    fn new<P: AsRef<Path>, E: AsRef<Path>>(artifacts_dir: P, elf_path: E) -> Result<Self> {
        let (prover, verifier) = load_preprocessing(&artifacts_dir)?;

        let memory_config = MemoryConfig {
            max_input_size: 128,
            max_output_size: 128,
            stack_size: 4096,
            memory_size: 65536,
            program_size: None,
        };

        let mut program = Program::new("guest");
        program.set_func("process_heap");
        program.set_std(false);
        program.set_memory_config(memory_config);
        program.elf = Some(elf_path.as_ref().to_path_buf());

        Ok(Self {
            program: Arc::new(program),
            prover: Arc::new(prover),
            verifier: Arc::new(verifier),
        })
    }

    fn prove(&self, state: HeapState, command: Command) -> Result<(AllocationOutput, Vec<u8>)> {
        let mut input_bytes = Vec::new();
        input_bytes.extend(
            postcard::to_stdvec(&state).map_err(|e| anyhow!("serialize state for proof: {e}"))?,
        );
        input_bytes.extend(
            postcard::to_stdvec(&command)
                .map_err(|e| anyhow!("serialize command for proof: {e}"))?,
        );

        let elf_contents = self
            .program
            .get_elf_contents()
            .ok_or_else(|| anyhow!("elf contents is None"))?;

        let (jolt_proof, mut io_device, _) =
            JoltRV64IMAC::prove(&self.prover, &elf_contents, &input_bytes);

        io_device
            .outputs
            .resize(self.prover.shared.memory_layout.max_output_size as usize, 0);
        let allocation_output = postcard::from_bytes::<AllocationOutput>(&io_device.outputs)
            .map_err(|e| anyhow!("decode allocation output: {e}"))?;

        let proof_bytes = jolt_proof
            .serialize_to_bytes()
            .map_err(|e| anyhow!("serialize proof: {e}"))?;

        Ok((allocation_output, proof_bytes))
    }

    fn verify(
        &self,
        state: HeapState,
        command: Command,
        output: AllocationOutput,
        proof_bytes: &[u8],
    ) -> Result<()> {
        let verify_proof = RV64IMACJoltProof::deserialize_from_bytes(proof_bytes)
            .map_err(|e| anyhow!("deserialize proof for verify: {e}"))?;

        let memory_layout = &self.verifier.shared.memory_layout;
        let memory_config = MemoryConfig {
            max_input_size: memory_layout.max_input_size,
            max_output_size: memory_layout.max_output_size,
            stack_size: memory_layout.stack_size,
            memory_size: memory_layout.memory_size,
            program_size: Some(memory_layout.program_size),
        };

        let mut io_device = JoltDevice::new(&memory_config);
        io_device.inputs.extend(
            postcard::to_stdvec(&state).map_err(|e| anyhow!("serialize state for verify: {e}"))?,
        );
        io_device.inputs.extend(
            postcard::to_stdvec(&command)
                .map_err(|e| anyhow!("serialize command for verify: {e}"))?,
        );
        io_device.outputs.extend(
            postcard::to_stdvec(&output)
                .map_err(|e| anyhow!("serialize output for verify: {e}"))?,
        );
        io_device.panic = false;

        let is_valid = JoltRV64IMAC::verify(&self.verifier, verify_proof, io_device, None).is_ok();
        if !is_valid {
            return Err(anyhow!("proof verification failed"));
        }
        Ok(())
    }
}

fn generate_proof<A: AsRef<Path>, E: AsRef<Path>>(
    state_hex: &str,
    command: Command,
    artifacts_dir: A,
    elf_path: E,
) -> Result<(String, String)> {
    let state = parse_state(state_hex)?;
    let context = ProofContext::new(artifacts_dir, elf_path)?;
    let (output, proof_bytes) = context.prove(state, command)?;
    context.verify(state, command, output, &proof_bytes)?;

    let result_hex =
        hex::encode(to_allocvec(&output).map_err(|e| anyhow!("output encode failed: {e}"))?);
    let proof_b64 = BASE64.encode(&proof_bytes);
    Ok((result_hex, proof_b64))
}

fn parse_state(state_hex: &str) -> Result<HeapState> {
    let state_bytes = hex::decode(state_hex.trim()).context("invalid state hex")?;
    from_bytes(&state_bytes).map_err(|e| anyhow!("state decode failed: {e}"))
}

fn load_preprocessing<P: AsRef<Path>>(
    artifacts_dir: P,
) -> Result<(
    JoltProverPreprocessing<F, PCS>,
    JoltVerifierPreprocessing<F, PCS>,
)> {
    let artifacts_dir = artifacts_dir.as_ref();
    fs::create_dir_all(artifacts_dir).context("create artifacts directory")?;

    let artifacts_str = artifacts_dir
        .to_str()
        .map(|s| s.to_owned())
        .unwrap_or_else(|| artifacts_dir.to_string_lossy().into_owned());

    let prover = JoltProverPreprocessing::<F, PCS>::read_from_target_dir(&artifacts_str)
        .context("load prover preprocessing")?;
    let verifier = JoltVerifierPreprocessing::<F, PCS>::read_from_target_dir(&artifacts_str)
        .context("load verifier preprocessing")?;

    Ok((prover, verifier))
}

mod python_bindings {
    use super::*;
    use pyo3::exceptions::{PyRuntimeError, PyValueError};
    use pyo3::prelude::*;

    fn map_err(err: anyhow::Error) -> PyErr {
        PyErr::new::<PyRuntimeError, _>(err.to_string())
    }

    #[pyfunction(name = "generate_alloc_proof")]
    fn py_generate_alloc_proof(
        state_hex: &str,
        requested_size: u32,
        artifacts_dir: &str,
        elf_path: &str,
    ) -> PyResult<(String, String)> {
        if requested_size == 0 {
            return Err(PyErr::new::<PyValueError, _>("requested size must be > 0"));
        }
        generate_proof(
            state_hex,
            Command::Alloc { requested_size },
            artifacts_dir,
            elf_path,
        )
        .map_err(map_err)
    }

    #[pyfunction(name = "generate_free_proof")]
    fn py_generate_free_proof(
        state_hex: &str,
        ptr: u64,
        artifacts_dir: &str,
        elf_path: &str,
    ) -> PyResult<(String, String)> {
        generate_proof(state_hex, Command::Free { ptr }, artifacts_dir, elf_path).map_err(map_err)
    }

    #[pymodule]
    fn bb_farm_starter(_py: Python<'_>, m: &PyModule) -> PyResult<()> {
        m.add_function(wrap_pyfunction!(py_generate_alloc_proof, m)?)?;
        m.add_function(wrap_pyfunction!(py_generate_free_proof, m)?)?;
        Ok(())
    }
}
