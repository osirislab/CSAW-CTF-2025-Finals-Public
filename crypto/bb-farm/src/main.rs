mod farm;
mod proof_allocator;

use std::io::{self, Read, Write};
use std::ptr;

use guest::{CHUNK_SIZE, Command};
use postcard::to_allocvec;

use crate::farm::{Farm, Plant};

fn main() {
    let mut farm = Farm::new("./artifacts");
    let stdin = io::stdin();

    println!("bob's barley farm");
    println!("powered by jolt (710e678)");

    let mut actions = 1;

    loop {
        print_menu(&farm, actions);
        let mut menu = String::new();
        stdin.read_line(&mut menu).unwrap();

        if actions > 5 {
            println!("time to sleep. bye!");
            break;
        }

        match menu.trim() {
            "1" => handle_plant(&mut farm),
            "2" => handle_show(&farm),
            "3" => handle_harvest(&mut farm),
            _ => {
                println!("bye");
                break;
            }
        }

        actions += 1;
    }
}

#[inline(never)]
fn print_menu(farm: &Farm, actions: u64) {
    let bytes = to_allocvec(&farm.allocator.state).unwrap();

    println!("state: {}", hex::encode(bytes));
    println!("actions: {actions}/5");
    println!("1) plant");
    println!("2) show");
    println!("3) harvest");
    print!("> ");

    io::stdout().flush().unwrap();
}

#[inline(never)]
fn handle_plant(farm: &mut Farm) {
    let idx: usize = prompt_parsed("idx");

    let command = Command::Alloc {
        requested_size: CHUNK_SIZE as u32,
    };
    let output = farm.verify_proof(command);

    assert!(farm.plants[idx].is_null());

    let data_ptr = output.ptr as *mut Plant;
    assert!(!data_ptr.is_null());

    let name = prompt_line("name");

    println!("send label (8 bytes)");
    let mut label = [0u8; 8];
    io::stdin().read_exact(&mut label).unwrap();

    unsafe {
        ptr::write(data_ptr, Plant { name, label });
    }

    farm.plants[idx] = data_ptr;
    farm.allocator.state = output.state;
    println!("planted #{idx} @ {:#x}", output.ptr);
}

#[inline(never)]
fn handle_show(farm: &Farm) {
    let idx: usize = prompt_parsed("idx");

    let data_ptr = farm.plants[idx];
    assert!(!data_ptr.is_null());

    let data = unsafe { &*data_ptr };
    println!("{data}");
}

#[inline(never)]
fn handle_harvest(farm: &mut Farm) {
    let idx: usize = prompt_parsed("idx");
    let addr = farm.harvest(idx);

    let command = Command::Free { ptr: addr };
    let output = farm.verify_proof(command);

    assert!(output.ptr == 0);

    farm.allocator.state = output.state;
}

#[inline(never)]
fn prompt_line(label: &str) -> String {
    print!("{label}: ");
    io::stdout().flush().unwrap();
    let mut buf = String::new();
    io::stdin().read_line(&mut buf).unwrap();
    buf.trim().to_string()
}

#[inline(never)]
fn prompt_parsed<T: std::str::FromStr>(label: &str) -> T {
    prompt_line(label)
        .parse()
        .unwrap_or_else(|_| panic!("invalid {label}"))
}
