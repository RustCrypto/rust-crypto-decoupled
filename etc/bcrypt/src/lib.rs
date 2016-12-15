#![no_std]
#![feature(step_by)]
#![feature(test)]
extern crate test;
extern crate byte_tools;
extern crate blowfish;

use blowfish::Blowfish;
use byte_tools::write_u32_be;

fn setup(cost: u32, salt: &[u8], key: &[u8]) -> Blowfish {
    assert!(cost < 32);
    let mut state = Blowfish::bc_init_state();
    
    state.salted_expand_key(salt, key);
    for _ in 0..1u32 << cost {
        state.bc_expand_key(key);
        state.bc_expand_key(salt);
    }

    state
}

pub fn bcrypt(cost: u32, salt: &[u8], password: &[u8], output: &mut [u8]) {
    assert!(salt.len() == 16);
    assert!(0 < password.len() && password.len() <= 72);
    assert!(output.len() == 24);

    let state = setup(cost, salt, password);
    // OrpheanBeholderScryDoubt
    let mut ctext = [0x4f727068, 0x65616e42, 0x65686f6c,
                     0x64657253, 0x63727944, 0x6f756274];
    for i in (0..6).step_by(2) {
        for _ in 0..64 {
            let (l, r) = state.bc_encrypt(ctext[i], ctext[i+1]);
            ctext[i] = l;
            ctext[i+1] = r;
        }
        write_u32_be(&mut output[i*4..(i+1)*4], ctext[i]);
        write_u32_be(&mut output[(i+1)*4..(i+2)*4], ctext[i+1]);
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod bench;
