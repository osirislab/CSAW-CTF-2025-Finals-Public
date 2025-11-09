use std::fs;
use std::path::Path;

use guest::{AllocationOutput, Command, HeapState};
use jolt_sdk::{F, JoltVerifierPreprocessing, PCS, RV64IMACJoltProof, Serializable};

type VerifyClosure = dyn Fn(HeapState, Command, AllocationOutput, bool, RV64IMACJoltProof) -> bool
    + Send
    + Sync
    + 'static;

pub struct ProofAllocator {
    pub state: HeapState,
    verifier: Box<VerifyClosure>,
}

impl ProofAllocator {
    #[inline(never)]
    pub fn new<P: AsRef<Path>>(target_dir: P, initial_state: HeapState) -> Self {
        let verifier = load_verifier(target_dir);
        let verify_fn = guest::build_verifier_process_heap(verifier);

        Self {
            verifier: Box::new(verify_fn),
            state: initial_state,
        }
    }

    #[inline(never)]
    pub fn verify_proof(
        &self,
        command: Command,
        output: AllocationOutput,
        proof: RV64IMACJoltProof,
    ) -> bool {
        (self.verifier)(self.state, command, output, false, proof)
    }

    #[inline(never)]
    pub fn parse_proof(&self, bytes: &[u8]) -> RV64IMACJoltProof {
        RV64IMACJoltProof::deserialize_from_bytes(bytes).unwrap()
    }
}

#[inline(never)]
fn load_verifier<P: AsRef<Path>>(target_dir: P) -> JoltVerifierPreprocessing<F, PCS> {
    let artifacts_dir = target_dir.as_ref();
    fs::create_dir_all(artifacts_dir).unwrap();

    let artifacts_str = artifacts_dir
        .to_str()
        .map(|s| s.to_owned())
        .unwrap_or_else(|| artifacts_dir.to_string_lossy().into_owned());

    JoltVerifierPreprocessing::<F, PCS>::read_from_target_dir(&artifacts_str).unwrap()
}
