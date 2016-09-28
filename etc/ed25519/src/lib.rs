#![no_std]
extern crate crypto_ops;
extern crate crypto_digest;
extern crate sha2;
extern crate curve25519;

use crypto_digest::Digest;
use sha2::{Sha512};
use curve25519::{GeP2, GeP3, ge_scalarmult_base, sc_reduce, sc_muladd, curve25519, Fe};
use crypto_ops::{fixed_time_eq};
use core::ops::{Add, Sub, Mul};

static L: [u8; 32] =
      [ 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x14, 0xde, 0xf9, 0xde, 0xa2, 0xf7, 0x9c, 0xd6,
        0x58, 0x12, 0x63, 0x1a, 0x5c, 0xf5, 0xd3, 0xed ];

pub fn keypair(seed: &[u8]) -> ([u8; 64], [u8; 32]) {
    let mut secret: [u8; 64] = {
        let mut hash_output: [u8; 64] = [0; 64];
        let mut hasher = Sha512::new();
        hasher.input(seed);
        hasher.result(&mut hash_output);
        hash_output[0] &= 248;
        hash_output[31] &= 63;
        hash_output[31] |= 64;
        hash_output
    };

    let a = ge_scalarmult_base(&secret[0..32]);
    let public_key = a.to_bytes();
    for (dest, src) in (&mut secret[32..64]).iter_mut().zip(public_key.iter()) {
        *dest = *src;
    }
    for (dest, src) in (&mut secret[0..32]).iter_mut().zip(seed.iter()) {
        *dest = *src;
    }
    (secret, public_key)
}

pub fn signature(message: &[u8], secret_key: &[u8]) -> [u8; 64] {
    let seed = &secret_key[0..32];
    let public_key = &secret_key[32..64];
    let az: [u8; 64] = {
        let mut hash_output: [u8; 64] = [0; 64];
        let mut hasher = Sha512::new();
        hasher.input(seed);
        hasher.result(&mut hash_output);
        hash_output[0] &= 248;
        hash_output[31] &= 63;
        hash_output[31] |= 64;
        hash_output
    };

    let nonce = {
        let mut hash_output: [u8; 64] = [0; 64];
        let mut hasher = Sha512::new();
        hasher.input(&az[32..64]);
        hasher.input(message);
        hasher.result(&mut hash_output);
        sc_reduce(&mut hash_output[0..64]);
        hash_output
    };

    let mut signature: [u8; 64] = [0; 64];
    let r: GeP3 = ge_scalarmult_base(&nonce[0..32]);
    for (result_byte, source_byte) in (&mut signature[0..32]).iter_mut().zip(r.to_bytes().iter()) {
        *result_byte = *source_byte;
    }
    for (result_byte, source_byte) in (&mut signature[32..64]).iter_mut().zip(public_key.iter()) {
        *result_byte = *source_byte;
    }

    {
        let mut hasher = Sha512::new();
        hasher.input(signature.as_ref());
        hasher.input(message);
        let mut hram: [u8; 64] = [0; 64];
        hasher.result(&mut hram);
        sc_reduce(&mut hram);
        sc_muladd(&mut signature[32..64], &hram[0..32], &az[0..32], &nonce[0..32]);
    }

    signature
}

fn check_s_lt_l(s: &[u8]) -> bool
{
    let mut c: u8 = 0;
    let mut n: u8 = 1;

    let mut i = 31;
    loop {
        c |= ((((s[i] as i32) - (L[i] as i32)) >> 8) as u8) & n;
        n &= (((((s[i] ^ L[i]) as i32)) - 1) >> 8) as u8;
        if i == 0 {
            break;
        } else {
            i -= 1;
        }
    }

    c == 0
}

pub fn verify(message: &[u8], public_key: &[u8], signature: &[u8]) -> bool {
    if check_s_lt_l(&signature[32..64]) {
        return false;
    }

    let a = match GeP3::from_bytes_negate_vartime(public_key) {
        Some(g) => g,
        None => { return false; }
    };
    let mut d = 0;
    for pk_byte in public_key.iter() {
        d |= *pk_byte;
    }
    if d == 0 {
        return false;
    }

    let mut hasher = Sha512::new();
    hasher.input(&signature[0..32]);
    hasher.input(public_key);
    hasher.input(message);
    let mut hash: [u8; 64] = [0; 64];
    hasher.result(&mut hash);
    sc_reduce(&mut hash);

    let r = GeP2::double_scalarmult_vartime(hash.as_ref(), a, &signature[32..64]);
    let rcheck = r.to_bytes();

    fixed_time_eq(rcheck.as_ref(), &signature[0..32])
}

pub fn exchange(public_key: &[u8], private_key: &[u8]) -> [u8; 32] {
    let ed_y = Fe::from_bytes(&public_key);
    // Produce public key in Montgomery form.
    let mont_x = edwards_to_montgomery_x(ed_y);

    // Produce private key from seed component (bytes 0 to 32)
    // of the Ed25519 extended private key (64 bytes).
    let mut hasher = Sha512::new();
    hasher.input(&private_key[0..32]);
    let mut hash: [u8; 64] = [0; 64];
    hasher.result(&mut hash);
    // Clamp the hash such that it is a valid private key
    hash[0] &= 248;
    hash[31] &= 127;
    hash[31] |= 64;

    let shared_mont_x : [u8; 32] = curve25519(&hash, &mont_x.to_bytes()); // priv., pub.

    shared_mont_x
}

fn edwards_to_montgomery_x(ed_y: Fe) -> Fe {
    let ed_z = Fe([1,0,0,0,0,0,0,0,0,0]);
    let temp_x = ed_z.add(ed_y);
    let temp_z = ed_z.sub(ed_y);
    let temp_z_inv = temp_z.invert();

    let mont_x = temp_x.mul(temp_z_inv);

    mont_x
}

#[cfg(test)]
mod tests;
