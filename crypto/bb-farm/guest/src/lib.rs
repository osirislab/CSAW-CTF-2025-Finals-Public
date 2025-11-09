#![cfg_attr(feature = "guest", no_std)]

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

impl HeapState {
    pub fn new(base_ptr: u64) -> Self {
        Self {
            base_ptr,
            bin_mask: 0,
        }
    }

    pub fn is_slot_free(&self, slot: u8) -> bool {
        (self.bin_mask & (1u64 << slot)) == 0
    }
}

#[jolt::provable(
    stack_size = 4096,
    memory_size = 65536,
    max_input_size = 128,
    max_output_size = 128,
    max_trace_length = 262144
)]
pub fn process_heap(state: HeapState, command: Command) -> AllocationOutput {
    match command {
        Command::Alloc { requested_size } => {
            assert!(requested_size as u64 == CHUNK_SIZE);
            assert!(state.base_ptr != 0);

            let mut new_state = state;
            let mut slot: u8 = 0;
            while slot < MAX_CHUNKS as u8 {
                if new_state.is_slot_free(slot) {
                    new_state.bin_mask |= 1u64 << slot;
                    let ptr = new_state.base_ptr + (slot as u64) * CHUNK_SIZE;
                    return AllocationOutput {
                        state: new_state,
                        ptr,
                    };
                }
                slot += 1;
            }

            panic!("heap full");
        }
        Command::Free { ptr } => {
            assert!(ptr >= state.base_ptr, "free pointer precedes heap base");
            let offset = ptr - state.base_ptr;
            assert!(
                offset % CHUNK_SIZE == 0,
                "free pointer not aligned to chunk size"
            );
            let slot = offset / CHUNK_SIZE;
            assert!(slot < MAX_CHUNKS as u64, "free pointer outside heap bounds");
            let slot = slot as u8;
            assert!(
                !state.is_slot_free(slot),
                "free pointer refers to an already free slot"
            );

            let mut new_state = state;
            new_state.bin_mask &= !(1u64 << slot);
            AllocationOutput {
                state: new_state,
                ptr: 0,
            }
        }
    }
}
