use std::{convert::TryFrom, ptr};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use derive_more::Display;
use guest::{AllocationOutput, Command, HeapState, TOTAL_SIZE};
use libc::{MAP_ANON, MAP_FIXED, MAP_PRIVATE, PROT_READ, PROT_WRITE, c_void, mmap};
use postcard::from_bytes;

use crate::{prompt_line, proof_allocator::ProofAllocator};

#[derive(Default, Display)]
#[display(fmt = "{name}: {}", "hex::encode(self.label)")]
pub struct Plant {
    pub name: String,
    pub label: [u8; 8],
}

pub struct Farm {
    pub(crate) allocator: ProofAllocator,
    pub(crate) plants: [*mut Plant; 2],
}

const HEAP_BASE: usize = 0x0133_7000;

impl Farm {
    #[inline(never)]
    pub fn new(target_dir: &str) -> Self {
        let total_len = usize::try_from(TOTAL_SIZE).unwrap();
        let requested_base = HEAP_BASE as *mut c_void;
        let ptr = unsafe {
            mmap(
                requested_base,
                total_len,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANON | MAP_FIXED,
                -1,
                0,
            )
        };

        let base = ptr as *mut u8;
        assert!(base == HEAP_BASE as *mut u8);

        unsafe {
            ptr::write_bytes(base, 0, total_len);
        }

        let plants = [ptr::null_mut(); 2];
        let allocator = ProofAllocator::new(target_dir, HeapState::new(base as u64));

        Self { allocator, plants }
    }

    #[inline(never)]
    pub fn verify_proof(&self, command: Command) -> AllocationOutput {
        let proof_b64 = prompt_line("proof (base64)");
        let output_hex = prompt_line("result (hex: state+ptr)");

        let raw = hex::decode(output_hex.trim()).unwrap();
        let output = from_bytes(&raw).unwrap();
        let proof_bytes = BASE64.decode(proof_b64.trim()).unwrap();
        let proof = self.allocator.parse_proof(&proof_bytes);
        let valid = self.allocator.verify_proof(command, output, proof);
        assert!(valid);
        output
    }

    #[inline(never)]
    pub fn harvest(&mut self, idx: usize) -> u64 {
        assert!(!self.plants[idx].is_null());
        let data_ptr = self.plants[idx];
        let addr = data_ptr as u64;

        unsafe {
            ptr::drop_in_place(data_ptr);
            core::ptr::write_bytes(data_ptr, 0, 1);
        }
        self.plants[idx] = ptr::null_mut();
        addr
    }
}
