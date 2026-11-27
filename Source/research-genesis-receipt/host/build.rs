use std::{env, fs, path::PathBuf};
use risc0_binfmt::{compute_image_id, ProgramBinary};
fn main() {
    let guest = PathBuf::from(env::var_os("GENESIS_GUEST_ELF").expect("build guest first; see build.sh"));
    println!("cargo:rerun-if-env-changed=GENESIS_GUEST_ELF");
    println!("cargo:rerun-if-changed={}", guest.display());
    let user = fs::read(guest).expect("read guest executable");
    let elf = ProgramBinary::new(&user, risc0_zkos_v1compat::V1COMPAT_ELF).encode();
    let output = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let id = compute_image_id(&elf).expect("compute trusted image id");
    fs::write(output.join("grin-genesis.elf"), elf).unwrap();
    fs::write(output.join("image-id.rs"), format!("{:?}", id.as_words())).unwrap();
}

