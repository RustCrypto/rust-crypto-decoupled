#![no_std]
#![feature(test)]
extern crate test;
extern crate crypto_bytes;
extern crate crypto_buffers;
extern crate crypto_symmetric;

use crypto_buffers::{BufferResult, RefReadBuffer, RefWriteBuffer};
use crypto_symmetric::{Encryptor, Decryptor, SynchronousStreamCipher,
    SymmetricCipherError, symm_enc_or_dec};
use crypto_bytes::{read_u32_le, write_u32v_le, copy_memory};

mod consts;
use consts::{ALPHA_MUL_TABLE, ALPHA_DIV_TABLE};

#[derive(Copy)]
pub struct Sosemanuk {
    lfsr: [u32; 10],
    fsm_r: [u32; 2],
    subkeys: [u32; 100],
    output: [u8; 80],
    offset: u32
}

impl Clone for Sosemanuk { fn clone(&self) -> Sosemanuk { *self } }

impl Sosemanuk {
    pub fn new(key: &[u8], nonce: &[u8]) -> Sosemanuk {
        let mut sosemanuk = Sosemanuk { lfsr: [0; 10], fsm_r: [0; 2], subkeys: [0; 100], output: [0; 80], offset: 80 };

        assert!(key.len() <= 32);
        assert!(nonce.len() <= 16);

        key_setup(&key, &mut sosemanuk.subkeys);
        iv_setup(&nonce, &mut sosemanuk.subkeys, &mut sosemanuk.lfsr, &mut sosemanuk.fsm_r);

        sosemanuk
    }

    fn advance_state(&mut self) {
        let mut s0 = self.lfsr[0];
        let mut s1 = self.lfsr[1];
        let mut s2 = self.lfsr[2];
        let mut s3 = self.lfsr[3];
        let mut s4 = self.lfsr[4];
        let mut s5 = self.lfsr[5];
        let mut s6 = self.lfsr[6];
        let mut s7 = self.lfsr[7];
        let mut s8 = self.lfsr[8];
        let mut s9 = self.lfsr[9];
        let mut r1 = self.fsm_r[0];
        let mut r2 = self.fsm_r[1];
        let mut f0 : u32;
        let mut f1 : u32;
        let mut f2 : u32;
        let mut f3 : u32;
        let mut f4 : u32;
        let mut v0 : u32;
        let mut v1 : u32;
        let mut v2 : u32;
        let mut v3 : u32;
        let mut tt : u32;

        let ref mul_alpha = ALPHA_MUL_TABLE;
        let ref div_alpha = ALPHA_DIV_TABLE;

        tt = r1;
        //r1 = r2 + (s1 ^ ((r1 & 0x01) != 0 ? s8 : 0));
        r1 = r2.wrapping_add(s1 ^ match r1 & 0x01 {
            0 => 0,
            _ => s8
        });
        r2 = tt.wrapping_mul(0x54655307).rotate_left(7);
        v0 = s0;
        s0 = ((s0 << 8) ^ mul_alpha[s0 as usize >> 24])
            ^ ((s3 >> 8) ^ div_alpha[s3 as usize & 0xFF]) ^ s9;
        f0 = s9.wrapping_add(r1) ^ r2;

        tt = r1;
        //r1 = r2 + (s2 ^ ((r1 & 0x01) != 0 ? s9 : 0));
        r1 = r2.wrapping_add(s2 ^ match r1 & 0x01 {
            0 => 0,
            _ => s9
        });
        r2 = tt.wrapping_mul(0x54655307).rotate_left(7);
        v1 = s1;
        s1 = ((s1 << 8) ^ mul_alpha[s1 as usize >> 24])
            ^ ((s4 >> 8) ^ div_alpha[s4 as usize & 0xFF]) ^ s0;
        f1 = s0.wrapping_add(r1) ^ r2;

        tt = r1;
        //r1 = r2 + (s3 ^ ((r1 & 0x01) != 0 ? s0 : 0));
        r1 = r2.wrapping_add(s3 ^ match r1 & 0x01 {
            0 => 0,
            _ => s0
        });
        r2 = tt.wrapping_mul(0x54655307).rotate_left(7);
        v2 = s2;
        s2 = ((s2 << 8) ^ mul_alpha[s2 as usize >> 24])
            ^ ((s5 >> 8) ^ div_alpha[s5 as usize & 0xFF]) ^ s1;
        f2 = s1.wrapping_add(r1) ^ r2;

        tt = r1;
        //r1 = r2 + (s4 ^ ((r1 & 0x01) != 0 ? s1 : 0));
        r1 = r2.wrapping_add(s4 ^ match r1 & 0x01 {
            0 => 0,
            _ => s1
        });
        r2 = tt.wrapping_mul(0x54655307).rotate_left(7);
        v3 = s3;
        s3 = ((s3 << 8) ^ mul_alpha[s3 as usize >> 24])
            ^ ((s6 >> 8) ^ div_alpha[s6 as usize & 0xFF]) ^ s2;
        f3 = s2.wrapping_add(r1) ^ r2;

        /*
         * Apply the third S-box (number 2) on (f3, f2, f1, f0).
         */
        f4 = f0;
        f0 &= f2;
        f0 ^= f3;
        f2 ^= f1;
        f2 ^= f0;
        f3 |= f4;
        f3 ^= f1;
        f4 ^= f2;
        f1 = f3;
        f3 |= f4;
        f3 ^= f0;
        f0 &= f1;
        f4 ^= f0;
        f1 ^= f3;
        f1 ^= f4;
        f4 = !f4;

        /*
         * S-box result is in (f2, f3, f1, f4).
         */
        let sbox_res = [(f2 ^ v0), (f3 ^ v1), (f1 ^ v2), (f4 ^ v3)];
        write_u32v_le(&mut self.output[0..16], &sbox_res);

        tt = r1;
        //r1 = r2 + (s5 ^ ((r1 & 0x01) != 0 ? s2 : 0));
        r1 = r2.wrapping_add(s5 ^ match r1 & 0x01 {
            0 => 0,
            _ => s2
        });
        r2 = tt.wrapping_mul(0x54655307).rotate_left(7);
        v0 = s4;
        s4 = ((s4 << 8) ^ mul_alpha[s4 as usize >> 24])
            ^ ((s7 >> 8) ^ div_alpha[s7 as usize & 0xFF]) ^ s3;
        f0 = s3.wrapping_add(r1) ^ r2;

        tt = r1;
        //r1 = r2 + (s6 ^ ((r1 & 0x01) != 0 ? s3 : 0));
        r1 = r2.wrapping_add(s6 ^ match r1 & 0x01 {
            0 => 0,
            _ => s3
        });
        r2 = tt.wrapping_mul(0x54655307).rotate_left(7);
        v1 = s5;
        s5 = ((s5 << 8) ^ mul_alpha[s5 as usize >> 24])
            ^ ((s8 >> 8) ^ div_alpha[s8 as usize & 0xFF]) ^ s4;
        f1 = s4.wrapping_add(r1) ^ r2;

        tt = r1;
        //r1 = r2 + (s7 ^ ((r1 & 0x01) != 0 ? s4 : 0));
        r1 = r2.wrapping_add(s7 ^ match r1 & 0x01 {
            0 => 0,
            _ => s4
        });
        r2 = tt.wrapping_mul(0x54655307).rotate_left(7);
        v2 = s6;
        s6 = ((s6 << 8) ^ mul_alpha[s6 as usize >> 24])
            ^ ((s9 >> 8) ^ div_alpha[s9 as usize & 0xFF]) ^ s5;
        f2 = s5.wrapping_add(r1) ^ r2;

        tt = r1;
        //r1 = r2 + (s8 ^ ((r1 & 0x01) != 0 ? s5 : 0));
        r1 = r2.wrapping_add(s8 ^ match r1 & 0x01 {
            0 => 0,
            _ => s5
        });
        r2 = tt.wrapping_mul(0x54655307).rotate_left(7);
        v3 = s7;
        s7 = ((s7 << 8) ^ mul_alpha[s7 as usize >> 24])
            ^ ((s0 >> 8) ^ div_alpha[s0 as usize & 0xFF]) ^ s6;
        f3 = s6.wrapping_add(r1) ^ r2;

        /*
         * Apply the third S-box (number 2) on (f3, f2, f1, f0).
         */
        f4 = f0;
        f0 &= f2;
        f0 ^= f3;
        f2 ^= f1;
        f2 ^= f0;
        f3 |= f4;
        f3 ^= f1;
        f4 ^= f2;
        f1 = f3;
        f3 |= f4;
        f3 ^= f0;
        f0 &= f1;
        f4 ^= f0;
        f1 ^= f3;
        f1 ^= f4;
        f4 = !f4;

        /*
         * S-box result is in (f2, f3, f1, f4).
         */
        let sbox_res = [(f2 ^ v0), (f3 ^ v1), (f1 ^ v2), (f4 ^ v3)];
        write_u32v_le(&mut self.output[16..32], &sbox_res);

        tt = r1;
        //r1 = r2 + (s9 ^ ((r1 & 0x01) != 0 ? s6 : 0));
        r1 = r2.wrapping_add(s9 ^ match r1 & 0x01 {
            0 => 0,
            _ => s6
        });
        r2 = tt.wrapping_mul(0x54655307).rotate_left(7);
        v0 = s8;
        s8 = ((s8 << 8) ^ mul_alpha[s8 as usize >> 24])
            ^ ((s1 >> 8) ^ div_alpha[s1 as usize & 0xFF]) ^ s7;
        f0 = s7.wrapping_add(r1) ^ r2;

        tt = r1;
        //r1 = r2 + (s0 ^ ((r1 & 0x01) != 0 ? s7 : 0));
        r1 = r2.wrapping_add(s0 ^ match r1 & 0x01 {
            0 => 0,
            _ => s7
        });
        r2 = tt.wrapping_mul(0x54655307).rotate_left(7);
        v1 = s9;
        s9 = ((s9 << 8) ^ mul_alpha[s9 as usize >> 24])
            ^ ((s2 >> 8) ^ div_alpha[s2 as usize & 0xFF]) ^ s8;
        f1 = s8.wrapping_add(r1) ^ r2;

        tt = r1;
        //r1 = r2 + (s1 ^ ((r1 & 0x01) != 0 ? s8 : 0));
        r1 = r2.wrapping_add(s1 ^ match r1 & 0x01 {
            0 => 0,
            _ => s8
        });
        r2 = tt.wrapping_mul(0x54655307).rotate_left(7);
        v2 = s0;
        s0 = ((s0 << 8) ^ mul_alpha[s0 as usize >> 24])
            ^ ((s3 >> 8) ^ div_alpha[s3 as usize & 0xFF]) ^ s9;
        f2 = s9.wrapping_add(r1) ^ r2;

        tt = r1;
        //r1 = r2 + (s2 ^ ((r1 & 0x01) != 0 ? s9 : 0));
        r1 = r2.wrapping_add(s2 ^ match r1 & 0x01 {
            0 => 0,
            _ => s9
        });
        r2 = tt.wrapping_mul(0x54655307).rotate_left(7);
        v3 = s1;
        s1 = ((s1 << 8) ^ mul_alpha[s1 as usize >> 24])
            ^ ((s4 >> 8) ^ div_alpha[s4 as usize & 0xFF]) ^ s0;
        f3 = s0.wrapping_add(r1) ^ r2;

        /*
         * Apply the third S-box (number 2) on (f3, f2, f1, f0).
         */
        f4 = f0;
        f0 &= f2;
        f0 ^= f3;
        f2 ^= f1;
        f2 ^= f0;
        f3 |= f4;
        f3 ^= f1;
        f4 ^= f2;
        f1 = f3;
        f3 |= f4;
        f3 ^= f0;
        f0 &= f1;
        f4 ^= f0;
        f1 ^= f3;
        f1 ^= f4;
        f4 = !f4;

        /*
         * S-box result is in (f2, f3, f1, f4).
         */
        let sbox_res = [(f2 ^ v0), (f3 ^ v1), (f1 ^ v2), (f4 ^ v3)];
        write_u32v_le(&mut self.output[32..48], &sbox_res);

        tt = r1;
        //r1 = r2 + (s3 ^ ((r1 & 0x01) != 0 ? s0 : 0));
        r1 = r2.wrapping_add(s3 ^ match r1 & 0x01 {
            0 => 0,
            _ => s0
        });
        r2 = tt.wrapping_mul(0x54655307).rotate_left(7);
        v0 = s2;
        s2 = ((s2 << 8) ^ mul_alpha[s2 as usize >> 24])
            ^ ((s5 >> 8) ^ div_alpha[s5 as usize & 0xFF]) ^ s1;
        f0 = s1.wrapping_add(r1) ^ r2;

        tt = r1;
        //r1 = r2 + (s4 ^ ((r1 & 0x01) != 0 ? s1 : 0));
        r1 = r2.wrapping_add(s4 ^ match r1 & 0x01 {
            0 => 0,
            _ => s1
        });
        r2 = tt.wrapping_mul(0x54655307).rotate_left(7);
        v1 = s3;
        s3 = ((s3 << 8) ^ mul_alpha[s3 as usize >> 24])
            ^ ((s6 >> 8) ^ div_alpha[s6 as usize & 0xFF]) ^ s2;
        f1 = s2.wrapping_add(r1) ^ r2;

        tt = r1;
        //r1 = r2 + (s5 ^ ((r1 & 0x01) != 0 ? s2 : 0));
        r1 = r2.wrapping_add(s5 ^ match r1 & 0x01 {
            0 => 0,
            _ => s2
        });
        r2 = tt.wrapping_mul(0x54655307).rotate_left(7);
        v2 = s4;
        s4 = ((s4 << 8) ^ mul_alpha[s4 as usize >> 24])
            ^ ((s7 >> 8) ^ div_alpha[s7 as usize & 0xFF]) ^ s3;
        f2 = s3.wrapping_add(r1) ^ r2;

        tt = r1;
        //r1 = r2 + (s6 ^ ((r1 & 0x01) != 0 ? s3 : 0));
        r1 = r2.wrapping_add(s6 ^ match r1 & 0x01 {
            0 => 0,
            _ => s3
        });
        r2 = tt.wrapping_mul(0x54655307).rotate_left(7);
        v3 = s5;
        s5 = ((s5 << 8) ^ mul_alpha[s5 as usize >> 24])
            ^ ((s8 >> 8) ^ div_alpha[s8 as usize & 0xFF]) ^ s4;
        f3 = s4.wrapping_add(r1) ^ r2;

        /*
         * Apply the third S-box (number 2) on (f3, f2, f1, f0).
         */
        f4 = f0;
        f0 &= f2;
        f0 ^= f3;
        f2 ^= f1;
        f2 ^= f0;
        f3 |= f4;
        f3 ^= f1;
        f4 ^= f2;
        f1 = f3;
        f3 |= f4;
        f3 ^= f0;
        f0 &= f1;
        f4 ^= f0;
        f1 ^= f3;
        f1 ^= f4;
        f4 = !f4;

        /*
         * S-box result is in (f2, f3, f1, f4).
         */
        let sbox_res = [(f2 ^ v0), (f3 ^ v1), (f1 ^ v2), (f4 ^ v3)];
        write_u32v_le(&mut self.output[48..64], &sbox_res);

        tt = r1;
        //r1 = r2 + (s7 ^ ((r1 & 0x01) != 0 ? s4 : 0));
        r1 = r2.wrapping_add(s7 ^ match r1 & 0x01 {
            0 => 0,
            _ => s4
        });
        r2 = tt.wrapping_mul(0x54655307).rotate_left(7);
        v0 = s6;
        s6 = ((s6 << 8) ^ mul_alpha[s6 as usize >> 24])
            ^ ((s9 >> 8) ^ div_alpha[s9 as usize & 0xFF]) ^ s5;
        f0 = s5.wrapping_add(r1) ^ r2;

        tt = r1;
        //r1 = r2 + (s8 ^ ((r1 & 0x01) != 0 ? s5 : 0));
        r1 = r2.wrapping_add(s8 ^ match r1 & 0x01 {
            0 => 0,
            _ => s5
        });
        r2 = tt.wrapping_mul(0x54655307).rotate_left(7);
        v1 = s7;
        s7 = ((s7 << 8) ^ mul_alpha[s7 as usize >> 24])
            ^ ((s0 >> 8) ^ div_alpha[s0 as usize & 0xFF]) ^ s6;
        f1 = s6.wrapping_add(r1) ^ r2;

        tt = r1;
        //r1 = r2 + (s9 ^ ((r1 & 0x01) != 0 ? s6 : 0));
        r1 = r2.wrapping_add(s9 ^ match r1 & 0x01 {
            0 => 0,
            _ => s6
        });
        r2 = tt.wrapping_mul(0x54655307).rotate_left(7);
        v2 = s8;
        s8 = ((s8 << 8) ^ mul_alpha[s8 as usize >> 24])
            ^ ((s1 >> 8) ^ div_alpha[s1 as usize & 0xFF]) ^ s7;
        f2 = s7.wrapping_add(r1) ^ r2;

        tt = r1;
        //r1 = r2 + (s0 ^ ((r1 & 0x01) != 0 ? s7 : 0));
        r1 = r2.wrapping_add(s0 ^ match r1 & 0x01 {
            0 => 0,
            _ => s7
        });
        r2 = tt.wrapping_mul(0x54655307).rotate_left(7);
        v3 = s9;
        s9 = ((s9 << 8) ^ mul_alpha[s9 as usize >> 24])
            ^ ( ( s2 >> 8) ^ div_alpha[s2 as usize & 0xFF]) ^ s8;
        f3 = s8.wrapping_add(r1) ^ r2;

        /*
         * Apply the third S-box (number 2) on (f3, f2, f1, f0).
         */
        f4 = f0;
        f0 &= f2;
        f0 ^= f3;
        f2 ^= f1;
        f2 ^= f0;
        f3 |= f4;
        f3 ^= f1;
        f4 ^= f2;
        f1 = f3;
        f3 |= f4;
        f3 ^= f0;
        f0 &= f1;
        f4 ^= f0;
        f1 ^= f3;
        f1 ^= f4;
        f4 = !f4;

        /*
         * S-box result is in (f2, f3, f1, f4).
         */
        let sbox_res = [(f2 ^ v0), (f3 ^ v1), (f1 ^ v2), (f4 ^ v3)];
        write_u32v_le(&mut self.output[64..80], &sbox_res);

        self.lfsr[0] = s0;
        self.lfsr[1] = s1;
        self.lfsr[2] = s2;
        self.lfsr[3] = s3;
        self.lfsr[4] = s4;
        self.lfsr[5] = s5;
        self.lfsr[6] = s6;
        self.lfsr[7] = s7;
        self.lfsr[8] = s8;
        self.lfsr[9] = s9;
        self.fsm_r[0] = r1;
        self.fsm_r[1] = r2;
        self.offset = 0;
    }

    fn next(&mut self) -> u8 {
        if self.offset == 80 {
            self.advance_state();
        }
        let ret = self.output[self.offset as usize];
        self.offset += 1;
        ret
    }
}


fn key_setup(key : &[u8], subkeys : &mut[u32; 100]) {
    let mut full_key : [u8; 32] = [0; 32];
    if key.len() < 32 {
        copy_memory(&key, &mut full_key[0..key.len()]);
        full_key[key.len()] = 0x01;
    } else {
        copy_memory(&key[0..32], &mut full_key[0..32]);
    }

    let mut w0 = read_u32_le(&full_key[0..4]);
    let mut w1 = read_u32_le(&full_key[4..8]);
    let mut w2 = read_u32_le(&full_key[8..12]);
    let mut w3 = read_u32_le(&full_key[12..16]);
    let mut w4 = read_u32_le(&full_key[16..20]);
    let mut w5 = read_u32_le(&full_key[20..24]);
    let mut w6 = read_u32_le(&full_key[24..28]);
    let mut w7 = read_u32_le(&full_key[28..32]);
    let mut r0 : u32;
    let mut r1 : u32;
    let mut r2 : u32;
    let mut r3 : u32;
    let mut r4 : u32;
    let mut tt : u32;
    let mut i = 0;

    tt = w0 ^ w3 ^ w5 ^ w7 ^ (0x9E3779B9 ^ (0));
    w0 = tt.rotate_left(11);
    tt = w1 ^ w4 ^ w6 ^ w0 ^ (0x9E3779B9 ^ (0 + 1));
    w1 = tt.rotate_left(11);
    tt = w2 ^ w5 ^ w7 ^ w1 ^ (0x9E3779B9 ^ (0 + 2));
    w2 = tt.rotate_left(11);
    tt = w3 ^ w6 ^ w0 ^ w2 ^ (0x9E3779B9 ^ (0 + 3));
    w3 = tt.rotate_left(11);
    r0 = w0;
    r1 = w1;
    r2 = w2;
    r3 = w3;
    r4 = r0;
    r0 |= r3;
    r3 ^= r1;
    r1 &= r4;
    r4 ^= r2;
    r2 ^= r3;
    r3 &= r0;
    r4 |= r1;
    r3 ^= r4;
    r0 ^= r1;
    r4 &= r0;
    r1 ^= r3;
    r4 ^= r2;
    r1 |= r0;
    r1 ^= r2;
    r0 ^= r3;
    r2 = r1;
    r1 |= r3;
    r1 ^= r0;
    subkeys[i] = r1; i+=1;
    subkeys[i] = r2; i+=1;
    subkeys[i] = r3; i+=1;
    subkeys[i] = r4; i+=1;
    tt = w4 ^ w7 ^ w1 ^ w3 ^ (0x9E3779B9 ^ (4));
    w4 = tt.rotate_left(11);
    tt = w5 ^ w0 ^ w2 ^ w4 ^ (0x9E3779B9 ^ (4 + 1));
    w5 = tt.rotate_left(11);
    tt = w6 ^ w1 ^ w3 ^ w5 ^ (0x9E3779B9 ^ (4 + 2));
    w6 = tt.rotate_left(11);
    tt = w7 ^ w2 ^ w4 ^ w6 ^ (0x9E3779B9 ^ (4 + 3));
    w7 = tt.rotate_left(11);
    r0 = w4;
    r1 = w5;
    r2 = w6;
    r3 = w7;
    r4 = r0;
    r0 &= r2;
    r0 ^= r3;
    r2 ^= r1;
    r2 ^= r0;
    r3 |= r4;
    r3 ^= r1;
    r4 ^= r2;
    r1 = r3;
    r3 |= r4;
    r3 ^= r0;
    r0 &= r1;
    r4 ^= r0;
    r1 ^= r3;
    r1 ^= r4;
    r4 = !r4;
    subkeys[i] = r2; i+=1;
    subkeys[i] = r3; i+=1;
    subkeys[i] = r1; i+=1;
    subkeys[i] = r4; i+=1;
    tt = w0 ^ w3 ^ w5 ^ w7 ^ (0x9E3779B9 ^ (8));
    w0 = tt.rotate_left(11);
    tt = w1 ^ w4 ^ w6 ^ w0 ^ (0x9E3779B9 ^ (8 + 1));
    w1 = tt.rotate_left(11);
    tt = w2 ^ w5 ^ w7 ^ w1 ^ (0x9E3779B9 ^ (8 + 2));
    w2 = tt.rotate_left(11);
    tt = w3 ^ w6 ^ w0 ^ w2 ^ (0x9E3779B9 ^ (8 + 3));
    w3 = tt.rotate_left(11);
    r0 = w0;
    r1 = w1;
    r2 = w2;
    r3 = w3;
    r0 = !r0;
    r2 = !r2;
    r4 = r0;
    r0 &= r1;
    r2 ^= r0;
    r0 |= r3;
    r3 ^= r2;
    r1 ^= r0;
    r0 ^= r4;
    r4 |= r1;
    r1 ^= r3;
    r2 |= r0;
    r2 &= r4;
    r0 ^= r1;
    r1 &= r2;
    r1 ^= r0;
    r0 &= r2;
    r0 ^= r4;
    subkeys[i] = r2; i+=1;
    subkeys[i] = r0; i+=1;
    subkeys[i] = r3; i+=1;
    subkeys[i] = r1; i+=1;
    tt = w4 ^ w7 ^ w1 ^ w3 ^ (0x9E3779B9 ^ (12));
    w4 = tt.rotate_left(11);
    tt = w5 ^ w0 ^ w2 ^ w4 ^ (0x9E3779B9 ^ (12 + 1));
    w5 = tt.rotate_left(11);
    tt = w6 ^ w1 ^ w3 ^ w5 ^ (0x9E3779B9 ^ (12 + 2));
    w6 = tt.rotate_left(11);
    tt = w7 ^ w2 ^ w4 ^ w6 ^ (0x9E3779B9 ^ (12 + 3));
    w7 = tt.rotate_left(11);
    r0 = w4;
    r1 = w5;
    r2 = w6;
    r3 = w7;
    r3 ^= r0;
    r4 = r1;
    r1 &= r3;
    r4 ^= r2;
    r1 ^= r0;
    r0 |= r3;
    r0 ^= r4;
    r4 ^= r3;
    r3 ^= r2;
    r2 |= r1;
    r2 ^= r4;
    r4 = !r4;
    r4 |= r1;
    r1 ^= r3;
    r1 ^= r4;
    r3 |= r0;
    r1 ^= r3;
    r4 ^= r3;
    subkeys[i] = r1; i+=1;
    subkeys[i] = r4; i+=1;
    subkeys[i] = r2; i+=1;
    subkeys[i] = r0; i+=1;
    tt = w0 ^ w3 ^ w5 ^ w7 ^ (0x9E3779B9 ^ (16));
    w0 = tt.rotate_left(11);
    tt = w1 ^ w4 ^ w6 ^ w0 ^ (0x9E3779B9 ^ (16 + 1));
    w1 = tt.rotate_left(11);
    tt = w2 ^ w5 ^ w7 ^ w1 ^ (0x9E3779B9 ^ (16 + 2));
    w2 = tt.rotate_left(11);
    tt = w3 ^ w6 ^ w0 ^ w2 ^ (0x9E3779B9 ^ (16 + 3));
    w3 = tt.rotate_left(11);
    r0 = w0;
    r1 = w1;
    r2 = w2;
    r3 = w3;
    r4 = r1;
    r1 |= r2;
    r1 ^= r3;
    r4 ^= r2;
    r2 ^= r1;
    r3 |= r4;
    r3 &= r0;
    r4 ^= r2;
    r3 ^= r1;
    r1 |= r4;
    r1 ^= r0;
    r0 |= r4;
    r0 ^= r2;
    r1 ^= r4;
    r2 ^= r1;
    r1 &= r0;
    r1 ^= r4;
    r2 = !r2;
    r2 |= r0;
    r4 ^= r2;
    subkeys[i] = r4; i+=1;
    subkeys[i] = r3; i+=1;
    subkeys[i] = r1; i+=1;
    subkeys[i] = r0; i+=1;
    tt = w4 ^ w7 ^ w1 ^ w3 ^ (0x9E3779B9 ^ (20));
    w4 = tt.rotate_left(11);
    tt = w5 ^ w0 ^ w2 ^ w4 ^ (0x9E3779B9 ^ (20 + 1));
    w5 = tt.rotate_left(11);
    tt = w6 ^ w1 ^ w3 ^ w5 ^ (0x9E3779B9 ^ (20 + 2));
    w6 = tt.rotate_left(11);
    tt = w7 ^ w2 ^ w4 ^ w6 ^ (0x9E3779B9 ^ (20 + 3));
    w7 = tt.rotate_left(11);
    r0 = w4;
    r1 = w5;
    r2 = w6;
    r3 = w7;
    r2 = !r2;
    r4 = r3;
    r3 &= r0;
    r0 ^= r4;
    r3 ^= r2;
    r2 |= r4;
    r1 ^= r3;
    r2 ^= r0;
    r0 |= r1;
    r2 ^= r1;
    r4 ^= r0;
    r0 |= r3;
    r0 ^= r2;
    r4 ^= r3;
    r4 ^= r0;
    r3 = !r3;
    r2 &= r4;
    r2 ^= r3;
    subkeys[i] = r0; i+=1;
    subkeys[i] = r1; i+=1;
    subkeys[i] = r4; i+=1;
    subkeys[i] = r2; i+=1;
    tt = w0 ^ w3 ^ w5 ^ w7 ^ (0x9E3779B9 ^ (24));
    w0 = tt.rotate_left(11);
    tt = w1 ^ w4 ^ w6 ^ w0 ^ (0x9E3779B9 ^ (24 + 1));
    w1 = tt.rotate_left(11);
    tt = w2 ^ w5 ^ w7 ^ w1 ^ (0x9E3779B9 ^ (24 + 2));
    w2 = tt.rotate_left(11);
    tt = w3 ^ w6 ^ w0 ^ w2 ^ (0x9E3779B9 ^ (24 + 3));
    w3 = tt.rotate_left(11);
    r0 = w0;
    r1 = w1;
    r2 = w2;
    r3 = w3;
    r0 ^= r1;
    r1 ^= r3;
    r3 = !r3;
    r4 = r1;
    r1 &= r0;
    r2 ^= r3;
    r1 ^= r2;
    r2 |= r4;
    r4 ^= r3;
    r3 &= r1;
    r3 ^= r0;
    r4 ^= r1;
    r4 ^= r2;
    r2 ^= r0;
    r0 &= r3;
    r2 = !r2;
    r0 ^= r4;
    r4 |= r3;
    r2 ^= r4;
    subkeys[i] = r1; i+=1;
    subkeys[i] = r3; i+=1;
    subkeys[i] = r0; i+=1;
    subkeys[i] = r2; i+=1;
    tt = w4 ^ w7 ^ w1 ^ w3 ^ (0x9E3779B9 ^ (28));
    w4 = tt.rotate_left(11);
    tt = w5 ^ w0 ^ w2 ^ w4 ^ (0x9E3779B9 ^ (28 + 1));
    w5 = tt.rotate_left(11);
    tt = w6 ^ w1 ^ w3 ^ w5 ^ (0x9E3779B9 ^ (28 + 2));
    w6 = tt.rotate_left(11);
    tt = w7 ^ w2 ^ w4 ^ w6 ^ (0x9E3779B9 ^ (28 + 3));
    w7 = tt.rotate_left(11);
    r0 = w4;
    r1 = w5;
    r2 = w6;
    r3 = w7;
    r1 ^= r3;
    r3 = !r3;
    r2 ^= r3;
    r3 ^= r0;
    r4 = r1;
    r1 &= r3;
    r1 ^= r2;
    r4 ^= r3;
    r0 ^= r4;
    r2 &= r4;
    r2 ^= r0;
    r0 &= r1;
    r3 ^= r0;
    r4 |= r1;
    r4 ^= r0;
    r0 |= r3;
    r0 ^= r2;
    r2 &= r3;
    r0 = !r0;
    r4 ^= r2;
    subkeys[i] = r1; i+=1;
    subkeys[i] = r4; i+=1;
    subkeys[i] = r0; i+=1;
    subkeys[i] = r3; i+=1;
    tt = w0 ^ w3 ^ w5 ^ w7 ^ (0x9E3779B9 ^ (32));
    w0 = tt.rotate_left(11);
    tt = w1 ^ w4 ^ w6 ^ w0 ^ (0x9E3779B9 ^ (32 + 1));
    w1 = tt.rotate_left(11);
    tt = w2 ^ w5 ^ w7 ^ w1 ^ (0x9E3779B9 ^ (32 + 2));
    w2 = tt.rotate_left(11);
    tt = w3 ^ w6 ^ w0 ^ w2 ^ (0x9E3779B9 ^ (32 + 3));
    w3 = tt.rotate_left(11);
    r0 = w0;
    r1 = w1;
    r2 = w2;
    r3 = w3;
    r4 = r0;
    r0 |= r3;
    r3 ^= r1;
    r1 &= r4;
    r4 ^= r2;
    r2 ^= r3;
    r3 &= r0;
    r4 |= r1;
    r3 ^= r4;
    r0 ^= r1;
    r4 &= r0;
    r1 ^= r3;
    r4 ^= r2;
    r1 |= r0;
    r1 ^= r2;
    r0 ^= r3;
    r2 = r1;
    r1 |= r3;
    r1 ^= r0;
    subkeys[i] = r1; i+=1;
    subkeys[i] = r2; i+=1;
    subkeys[i] = r3; i+=1;
    subkeys[i] = r4; i+=1;
    tt = w4 ^ w7 ^ w1 ^ w3 ^ (0x9E3779B9 ^ (36));
    w4 = tt.rotate_left(11);
    tt = w5 ^ w0 ^ w2 ^ w4 ^ (0x9E3779B9 ^ (36 + 1));
    w5 = tt.rotate_left(11);
    tt = w6 ^ w1 ^ w3 ^ w5 ^ (0x9E3779B9 ^ (36 + 2));
    w6 = tt.rotate_left(11);
    tt = w7 ^ w2 ^ w4 ^ w6 ^ (0x9E3779B9 ^ (36 + 3));
    w7 = tt.rotate_left(11);
    r0 = w4;
    r1 = w5;
    r2 = w6;
    r3 = w7;
    r4 = r0;
    r0 &= r2;
    r0 ^= r3;
    r2 ^= r1;
    r2 ^= r0;
    r3 |= r4;
    r3 ^= r1;
    r4 ^= r2;
    r1 = r3;
    r3 |= r4;
    r3 ^= r0;
    r0 &= r1;
    r4 ^= r0;
    r1 ^= r3;
    r1 ^= r4;
    r4 = !r4;
    subkeys[i] = r2; i+=1;
    subkeys[i] = r3; i+=1;
    subkeys[i] = r1; i+=1;
    subkeys[i] = r4; i+=1;
    tt = w0 ^ w3 ^ w5 ^ w7 ^ (0x9E3779B9 ^ (40));
    w0 = tt.rotate_left(11);
    tt = w1 ^ w4 ^ w6 ^ w0 ^ (0x9E3779B9 ^ (40 + 1));
    w1 = tt.rotate_left(11);
    tt = w2 ^ w5 ^ w7 ^ w1 ^ (0x9E3779B9 ^ (40 + 2));
    w2 = tt.rotate_left(11);
    tt = w3 ^ w6 ^ w0 ^ w2 ^ (0x9E3779B9 ^ (40 + 3));
    w3 = tt.rotate_left(11);
    r0 = w0;
    r1 = w1;
    r2 = w2;
    r3 = w3;
    r0 = !r0;
    r2 = !r2;
    r4 = r0;
    r0 &= r1;
    r2 ^= r0;
    r0 |= r3;
    r3 ^= r2;
    r1 ^= r0;
    r0 ^= r4;
    r4 |= r1;
    r1 ^= r3;
    r2 |= r0;
    r2 &= r4;
    r0 ^= r1;
    r1 &= r2;
    r1 ^= r0;
    r0 &= r2;
    r0 ^= r4;
    subkeys[i] = r2; i+=1;
    subkeys[i] = r0; i+=1;
    subkeys[i] = r3; i+=1;
    subkeys[i] = r1; i+=1;
    tt = w4 ^ w7 ^ w1 ^ w3 ^ (0x9E3779B9 ^ (44));
    w4 = tt.rotate_left(11);
    tt = w5 ^ w0 ^ w2 ^ w4 ^ (0x9E3779B9 ^ (44 + 1));
    w5 = tt.rotate_left(11);
    tt = w6 ^ w1 ^ w3 ^ w5 ^ (0x9E3779B9 ^ (44 + 2));
    w6 = tt.rotate_left(11);
    tt = w7 ^ w2 ^ w4 ^ w6 ^ (0x9E3779B9 ^ (44 + 3));
    w7 = tt.rotate_left(11);
    r0 = w4;
    r1 = w5;
    r2 = w6;
    r3 = w7;
    r3 ^= r0;
    r4 = r1;
    r1 &= r3;
    r4 ^= r2;
    r1 ^= r0;
    r0 |= r3;
    r0 ^= r4;
    r4 ^= r3;
    r3 ^= r2;
    r2 |= r1;
    r2 ^= r4;
    r4 = !r4;
    r4 |= r1;
    r1 ^= r3;
    r1 ^= r4;
    r3 |= r0;
    r1 ^= r3;
    r4 ^= r3;
    subkeys[i] = r1; i+=1;
    subkeys[i] = r4; i+=1;
    subkeys[i] = r2; i+=1;
    subkeys[i] = r0; i+=1;
    tt = w0 ^ w3 ^ w5 ^ w7 ^ (0x9E3779B9 ^ (48));
    w0 = tt.rotate_left(11);
    tt = w1 ^ w4 ^ w6 ^ w0 ^ (0x9E3779B9 ^ (48 + 1));
    w1 = tt.rotate_left(11);
    tt = w2 ^ w5 ^ w7 ^ w1 ^ (0x9E3779B9 ^ (48 + 2));
    w2 = tt.rotate_left(11);
    tt = w3 ^ w6 ^ w0 ^ w2 ^ (0x9E3779B9 ^ (48 + 3));
    w3 = tt.rotate_left(11);
    r0 = w0;
    r1 = w1;
    r2 = w2;
    r3 = w3;
    r4 = r1;
    r1 |= r2;
    r1 ^= r3;
    r4 ^= r2;
    r2 ^= r1;
    r3 |= r4;
    r3 &= r0;
    r4 ^= r2;
    r3 ^= r1;
    r1 |= r4;
    r1 ^= r0;
    r0 |= r4;
    r0 ^= r2;
    r1 ^= r4;
    r2 ^= r1;
    r1 &= r0;
    r1 ^= r4;
    r2 = !r2;
    r2 |= r0;
    r4 ^= r2;
    subkeys[i] = r4; i+=1;
    subkeys[i] = r3; i+=1;
    subkeys[i] = r1; i+=1;
    subkeys[i] = r0; i+=1;
    tt = w4 ^ w7 ^ w1 ^ w3 ^ (0x9E3779B9 ^ (52));
    w4 = tt.rotate_left(11);
    tt = w5 ^ w0 ^ w2 ^ w4 ^ (0x9E3779B9 ^ (52 + 1));
    w5 = tt.rotate_left(11);
    tt = w6 ^ w1 ^ w3 ^ w5 ^ (0x9E3779B9 ^ (52 + 2));
    w6 = tt.rotate_left(11);
    tt = w7 ^ w2 ^ w4 ^ w6 ^ (0x9E3779B9 ^ (52 + 3));
    w7 = tt.rotate_left(11);
    r0 = w4;
    r1 = w5;
    r2 = w6;
    r3 = w7;
    r2 = !r2;
    r4 = r3;
    r3 &= r0;
    r0 ^= r4;
    r3 ^= r2;
    r2 |= r4;
    r1 ^= r3;
    r2 ^= r0;
    r0 |= r1;
    r2 ^= r1;
    r4 ^= r0;
    r0 |= r3;
    r0 ^= r2;
    r4 ^= r3;
    r4 ^= r0;
    r3 = !r3;
    r2 &= r4;
    r2 ^= r3;
    subkeys[i] = r0; i+=1;
    subkeys[i] = r1; i+=1;
    subkeys[i] = r4; i+=1;
    subkeys[i] = r2; i+=1;
    tt = w0 ^ w3 ^ w5 ^ w7 ^ (0x9E3779B9 ^ (56));
    w0 = tt.rotate_left(11);
    tt = w1 ^ w4 ^ w6 ^ w0 ^ (0x9E3779B9 ^ (56 + 1));
    w1 = tt.rotate_left(11);
    tt = w2 ^ w5 ^ w7 ^ w1 ^ (0x9E3779B9 ^ (56 + 2));
    w2 = tt.rotate_left(11);
    tt = w3 ^ w6 ^ w0 ^ w2 ^ (0x9E3779B9 ^ (56 + 3));
    w3 = tt.rotate_left(11);
    r0 = w0;
    r1 = w1;
    r2 = w2;
    r3 = w3;
    r0 ^= r1;
    r1 ^= r3;
    r3 = !r3;
    r4 = r1;
    r1 &= r0;
    r2 ^= r3;
    r1 ^= r2;
    r2 |= r4;
    r4 ^= r3;
    r3 &= r1;
    r3 ^= r0;
    r4 ^= r1;
    r4 ^= r2;
    r2 ^= r0;
    r0 &= r3;
    r2 = !r2;
    r0 ^= r4;
    r4 |= r3;
    r2 ^= r4;
    subkeys[i] = r1; i+=1;
    subkeys[i] = r3; i+=1;
    subkeys[i] = r0; i+=1;
    subkeys[i] = r2; i+=1;
    tt = w4 ^ w7 ^ w1 ^ w3 ^ (0x9E3779B9 ^ (60));
    w4 = tt.rotate_left(11);
    tt = w5 ^ w0 ^ w2 ^ w4 ^ (0x9E3779B9 ^ (60 + 1));
    w5 = tt.rotate_left(11);
    tt = w6 ^ w1 ^ w3 ^ w5 ^ (0x9E3779B9 ^ (60 + 2));
    w6 = tt.rotate_left(11);
    tt = w7 ^ w2 ^ w4 ^ w6 ^ (0x9E3779B9 ^ (60 + 3));
    w7 = tt.rotate_left(11);
    r0 = w4;
    r1 = w5;
    r2 = w6;
    r3 = w7;
    r1 ^= r3;
    r3 = !r3;
    r2 ^= r3;
    r3 ^= r0;
    r4 = r1;
    r1 &= r3;
    r1 ^= r2;
    r4 ^= r3;
    r0 ^= r4;
    r2 &= r4;
    r2 ^= r0;
    r0 &= r1;
    r3 ^= r0;
    r4 |= r1;
    r4 ^= r0;
    r0 |= r3;
    r0 ^= r2;
    r2 &= r3;
    r0 = !r0;
    r4 ^= r2;
    subkeys[i] = r1; i+=1;
    subkeys[i] = r4; i+=1;
    subkeys[i] = r0; i+=1;
    subkeys[i] = r3; i+=1;
    tt = w0 ^ w3 ^ w5 ^ w7 ^ (0x9E3779B9 ^ (64));
    w0 = tt.rotate_left(11);
    tt = w1 ^ w4 ^ w6 ^ w0 ^ (0x9E3779B9 ^ (64 + 1));
    w1 = tt.rotate_left(11);
    tt = w2 ^ w5 ^ w7 ^ w1 ^ (0x9E3779B9 ^ (64 + 2));
    w2 = tt.rotate_left(11);
    tt = w3 ^ w6 ^ w0 ^ w2 ^ (0x9E3779B9 ^ (64 + 3));
    w3 = tt.rotate_left(11);
    r0 = w0;
    r1 = w1;
    r2 = w2;
    r3 = w3;
    r4 = r0;
    r0 |= r3;
    r3 ^= r1;
    r1 &= r4;
    r4 ^= r2;
    r2 ^= r3;
    r3 &= r0;
    r4 |= r1;
    r3 ^= r4;
    r0 ^= r1;
    r4 &= r0;
    r1 ^= r3;
    r4 ^= r2;
    r1 |= r0;
    r1 ^= r2;
    r0 ^= r3;
    r2 = r1;
    r1 |= r3;
    r1 ^= r0;
    subkeys[i] = r1; i+=1;
    subkeys[i] = r2; i+=1;
    subkeys[i] = r3; i+=1;
    subkeys[i] = r4; i+=1;
    tt = w4 ^ w7 ^ w1 ^ w3 ^ (0x9E3779B9 ^ (68));
    w4 = tt.rotate_left(11);
    tt = w5 ^ w0 ^ w2 ^ w4 ^ (0x9E3779B9 ^ (68 + 1));
    w5 = tt.rotate_left(11);
    tt = w6 ^ w1 ^ w3 ^ w5 ^ (0x9E3779B9 ^ (68 + 2));
    w6 = tt.rotate_left(11);
    tt = w7 ^ w2 ^ w4 ^ w6 ^ (0x9E3779B9 ^ (68 + 3));
    w7 = tt.rotate_left(11);
    r0 = w4;
    r1 = w5;
    r2 = w6;
    r3 = w7;
    r4 = r0;
    r0 &= r2;
    r0 ^= r3;
    r2 ^= r1;
    r2 ^= r0;
    r3 |= r4;
    r3 ^= r1;
    r4 ^= r2;
    r1 = r3;
    r3 |= r4;
    r3 ^= r0;
    r0 &= r1;
    r4 ^= r0;
    r1 ^= r3;
    r1 ^= r4;
    r4 = !r4;
    subkeys[i] = r2; i+=1;
    subkeys[i] = r3; i+=1;
    subkeys[i] = r1; i+=1;
    subkeys[i] = r4; i+=1;
    tt = w0 ^ w3 ^ w5 ^ w7 ^ (0x9E3779B9 ^ (72));
    w0 = tt.rotate_left(11);
    tt = w1 ^ w4 ^ w6 ^ w0 ^ (0x9E3779B9 ^ (72 + 1));
    w1 = tt.rotate_left(11);
    tt = w2 ^ w5 ^ w7 ^ w1 ^ (0x9E3779B9 ^ (72 + 2));
    w2 = tt.rotate_left(11);
    tt = w3 ^ w6 ^ w0 ^ w2 ^ (0x9E3779B9 ^ (72 + 3));
    w3 = tt.rotate_left(11);
    r0 = w0;
    r1 = w1;
    r2 = w2;
    r3 = w3;
    r0 = !r0;
    r2 = !r2;
    r4 = r0;
    r0 &= r1;
    r2 ^= r0;
    r0 |= r3;
    r3 ^= r2;
    r1 ^= r0;
    r0 ^= r4;
    r4 |= r1;
    r1 ^= r3;
    r2 |= r0;
    r2 &= r4;
    r0 ^= r1;
    r1 &= r2;
    r1 ^= r0;
    r0 &= r2;
    r0 ^= r4;
    subkeys[i] = r2; i+=1;
    subkeys[i] = r0; i+=1;
    subkeys[i] = r3; i+=1;
    subkeys[i] = r1; i+=1;
    tt = w4 ^ w7 ^ w1 ^ w3 ^ (0x9E3779B9 ^ (76));
    w4 = tt.rotate_left(11);
    tt = w5 ^ w0 ^ w2 ^ w4 ^ (0x9E3779B9 ^ (76 + 1));
    w5 = tt.rotate_left(11);
    tt = w6 ^ w1 ^ w3 ^ w5 ^ (0x9E3779B9 ^ (76 + 2));
    w6 = tt.rotate_left(11);
    tt = w7 ^ w2 ^ w4 ^ w6 ^ (0x9E3779B9 ^ (76 + 3));
    w7 = tt.rotate_left(11);
    r0 = w4;
    r1 = w5;
    r2 = w6;
    r3 = w7;
    r3 ^= r0;
    r4 = r1;
    r1 &= r3;
    r4 ^= r2;
    r1 ^= r0;
    r0 |= r3;
    r0 ^= r4;
    r4 ^= r3;
    r3 ^= r2;
    r2 |= r1;
    r2 ^= r4;
    r4 = !r4;
    r4 |= r1;
    r1 ^= r3;
    r1 ^= r4;
    r3 |= r0;
    r1 ^= r3;
    r4 ^= r3;
    subkeys[i] = r1; i+=1;
    subkeys[i] = r4; i+=1;
    subkeys[i] = r2; i+=1;
    subkeys[i] = r0; i+=1;
    tt = w0 ^ w3 ^ w5 ^ w7 ^ (0x9E3779B9 ^ (80));
    w0 = tt.rotate_left(11);
    tt = w1 ^ w4 ^ w6 ^ w0 ^ (0x9E3779B9 ^ (80 + 1));
    w1 = tt.rotate_left(11);
    tt = w2 ^ w5 ^ w7 ^ w1 ^ (0x9E3779B9 ^ (80 + 2));
    w2 = tt.rotate_left(11);
    tt = w3 ^ w6 ^ w0 ^ w2 ^ (0x9E3779B9 ^ (80 + 3));
    w3 = tt.rotate_left(11);
    r0 = w0;
    r1 = w1;
    r2 = w2;
    r3 = w3;
    r4 = r1;
    r1 |= r2;
    r1 ^= r3;
    r4 ^= r2;
    r2 ^= r1;
    r3 |= r4;
    r3 &= r0;
    r4 ^= r2;
    r3 ^= r1;
    r1 |= r4;
    r1 ^= r0;
    r0 |= r4;
    r0 ^= r2;
    r1 ^= r4;
    r2 ^= r1;
    r1 &= r0;
    r1 ^= r4;
    r2 = !r2;
    r2 |= r0;
    r4 ^= r2;
    subkeys[i] = r4; i+=1;
    subkeys[i] = r3; i+=1;
    subkeys[i] = r1; i+=1;
    subkeys[i] = r0; i+=1;
    tt = w4 ^ w7 ^ w1 ^ w3 ^ (0x9E3779B9 ^ (84));
    w4 = tt.rotate_left(11);
    tt = w5 ^ w0 ^ w2 ^ w4 ^ (0x9E3779B9 ^ (84 + 1));
    w5 = tt.rotate_left(11);
    tt = w6 ^ w1 ^ w3 ^ w5 ^ (0x9E3779B9 ^ (84 + 2));
    w6 = tt.rotate_left(11);
    tt = w7 ^ w2 ^ w4 ^ w6 ^ (0x9E3779B9 ^ (84 + 3));
    w7 = tt.rotate_left(11);
    r0 = w4;
    r1 = w5;
    r2 = w6;
    r3 = w7;
    r2 = !r2;
    r4 = r3;
    r3 &= r0;
    r0 ^= r4;
    r3 ^= r2;
    r2 |= r4;
    r1 ^= r3;
    r2 ^= r0;
    r0 |= r1;
    r2 ^= r1;
    r4 ^= r0;
    r0 |= r3;
    r0 ^= r2;
    r4 ^= r3;
    r4 ^= r0;
    r3 = !r3;
    r2 &= r4;
    r2 ^= r3;
    subkeys[i] = r0; i+=1;
    subkeys[i] = r1; i+=1;
    subkeys[i] = r4; i+=1;
    subkeys[i] = r2; i+=1;
    tt = w0 ^ w3 ^ w5 ^ w7 ^ (0x9E3779B9 ^ (88));
    w0 = tt.rotate_left(11);
    tt = w1 ^ w4 ^ w6 ^ w0 ^ (0x9E3779B9 ^ (88 + 1));
    w1 = tt.rotate_left(11);
    tt = w2 ^ w5 ^ w7 ^ w1 ^ (0x9E3779B9 ^ (88 + 2));
    w2 = tt.rotate_left(11);
    tt = w3 ^ w6 ^ w0 ^ w2 ^ (0x9E3779B9 ^ (88 + 3));
    w3 = tt.rotate_left(11);
    r0 = w0;
    r1 = w1;
    r2 = w2;
    r3 = w3;
    r0 ^= r1;
    r1 ^= r3;
    r3 = !r3;
    r4 = r1;
    r1 &= r0;
    r2 ^= r3;
    r1 ^= r2;
    r2 |= r4;
    r4 ^= r3;
    r3 &= r1;
    r3 ^= r0;
    r4 ^= r1;
    r4 ^= r2;
    r2 ^= r0;
    r0 &= r3;
    r2 = !r2;
    r0 ^= r4;
    r4 |= r3;
    r2 ^= r4;
    subkeys[i] = r1; i+=1;
    subkeys[i] = r3; i+=1;
    subkeys[i] = r0; i+=1;
    subkeys[i] = r2; i+=1;
    tt = w4 ^ w7 ^ w1 ^ w3 ^ (0x9E3779B9 ^ (92));
    w4 = tt.rotate_left(11);
    tt = w5 ^ w0 ^ w2 ^ w4 ^ (0x9E3779B9 ^ (92 + 1));
    w5 = tt.rotate_left(11);
    tt = w6 ^ w1 ^ w3 ^ w5 ^ (0x9E3779B9 ^ (92 + 2));
    w6 = tt.rotate_left(11);
    tt = w7 ^ w2 ^ w4 ^ w6 ^ (0x9E3779B9 ^ (92 + 3));
    w7 = tt.rotate_left(11);
    r0 = w4;
    r1 = w5;
    r2 = w6;
    r3 = w7;
    r1 ^= r3;
    r3 = !r3;
    r2 ^= r3;
    r3 ^= r0;
    r4 = r1;
    r1 &= r3;
    r1 ^= r2;
    r4 ^= r3;
    r0 ^= r4;
    r2 &= r4;
    r2 ^= r0;
    r0 &= r1;
    r3 ^= r0;
    r4 |= r1;
    r4 ^= r0;
    r0 |= r3;
    r0 ^= r2;
    r2 &= r3;
    r0 = !r0;
    r4 ^= r2;
    subkeys[i] = r1; i+=1;
    subkeys[i] = r4; i+=1;
    subkeys[i] = r0; i+=1;
    subkeys[i] = r3; i+=1;
    tt = w0 ^ w3 ^ w5 ^ w7 ^ (0x9E3779B9 ^ (96));
    w0 = tt.rotate_left(11);
    tt = w1 ^ w4 ^ w6 ^ w0 ^ (0x9E3779B9 ^ (96 + 1));
    w1 = tt.rotate_left(11);
    tt = w2 ^ w5 ^ w7 ^ w1 ^ (0x9E3779B9 ^ (96 + 2));
    w2 = tt.rotate_left(11);
    tt = w3 ^ w6 ^ w0 ^ w2 ^ (0x9E3779B9 ^ (96 + 3));
    w3 = tt.rotate_left(11);
    r0 = w0;
    r1 = w1;
    r2 = w2;
    r3 = w3;
    r4 = r0;
    r0 |= r3;
    r3 ^= r1;
    r1 &= r4;
    r4 ^= r2;
    r2 ^= r3;
    r3 &= r0;
    r4 |= r1;
    r3 ^= r4;
    r0 ^= r1;
    r4 &= r0;
    r1 ^= r3;
    r4 ^= r2;
    r1 |= r0;
    r1 ^= r2;
    r0 ^= r3;
    r2 = r1;
    r1 |= r3;
    r1 ^= r0;
    subkeys[i] = r1; i+=1;
    subkeys[i] = r2; i+=1;
    subkeys[i] = r3; i+=1;
    subkeys[i] = r4;
}

fn iv_setup(iv : &[u8], subkeys : &mut[u32; 100], lfsr : &mut[u32; 10], fsm_r : &mut[u32; 2]) {
    let mut nonce : [u8; 16] = [0; 16];
    if iv.len() < 16 {
        copy_memory(&iv, &mut nonce[0..iv.len()]);
    } else {
        copy_memory(&iv[0..16], &mut nonce[0..16]);
    }

    let mut r0 : u32;
    let mut r1 : u32;
    let mut r2 : u32;
    let mut r3 : u32;
    let mut r4 : u32;
    r0 = read_u32_le(&nonce[0..4]);
    r1 = read_u32_le(&nonce[4..8]);
    r2 = read_u32_le(&nonce[8..12]);
    r3 = read_u32_le(&nonce[12..16]);

    r0 ^= subkeys[0];
    r1 ^= subkeys[0 + 1];
    r2 ^= subkeys[0 + 2];
    r3 ^= subkeys[0 + 3];
    r3 ^= r0;
    r4 = r1;
    r1 &= r3;
    r4 ^= r2;
    r1 ^= r0;
    r0 |= r3;
    r0 ^= r4;
    r4 ^= r3;
    r3 ^= r2;
    r2 |= r1;
    r2 ^= r4;
    r4 = !r4;
    r4 |= r1;
    r1 ^= r3;
    r1 ^= r4;
    r3 |= r0;
    r1 ^= r3;
    r4 ^= r3;
    r1 = r1.rotate_left(13);
    r2 = r2.rotate_left(3);
    r4 = r4 ^ r1 ^ r2;
    r0 = r0 ^ r2 ^ (r1 << 3);
    r4 = r4.rotate_left(1);
    r0 = r0.rotate_left(7);
    r1 = r1 ^ r4 ^ r0;
    r2 = r2 ^ r0 ^ (r4 << 7);
    r1 = r1.rotate_left(5);
    r2 = r2.rotate_left(22);
    r1 ^= subkeys[4];
    r4 ^= subkeys[4 + 1];
    r2 ^= subkeys[4 + 2];
    r0 ^= subkeys[4 + 3];
    r1 = !r1;
    r2 = !r2;
    r3 = r1;
    r1 &= r4;
    r2 ^= r1;
    r1 |= r0;
    r0 ^= r2;
    r4 ^= r1;
    r1 ^= r3;
    r3 |= r4;
    r4 ^= r0;
    r2 |= r1;
    r2 &= r3;
    r1 ^= r4;
    r4 &= r2;
    r4 ^= r1;
    r1 &= r2;
    r1 ^= r3;
    r2 = r2.rotate_left(13);
    r0 = r0.rotate_left(3);
    r1 = r1 ^ r2 ^ r0;
    r4 = r4 ^ r0 ^ (r2 << 3);
    r1 = r1.rotate_left(1);
    r4 = r4.rotate_left(7);
    r2 = r2 ^ r1 ^ r4;
    r0 = r0 ^ r4 ^ (r1 << 7);
    r2 = r2.rotate_left(5);
    r0 = r0.rotate_left(22);
    r2 ^= subkeys[8];
    r1 ^= subkeys[8 + 1];
    r0 ^= subkeys[8 + 2];
    r4 ^= subkeys[8 + 3];
    r3 = r2;
    r2 &= r0;
    r2 ^= r4;
    r0 ^= r1;
    r0 ^= r2;
    r4 |= r3;
    r4 ^= r1;
    r3 ^= r0;
    r1 = r4;
    r4 |= r3;
    r4 ^= r2;
    r2 &= r1;
    r3 ^= r2;
    r1 ^= r4;
    r1 ^= r3;
    r3 = !r3;
    r0 = r0.rotate_left(13);
    r1 = r1.rotate_left(3);
    r4 = r4 ^ r0 ^ r1;
    r3 = r3 ^ r1 ^ (r0 << 3);
    r4 = r4.rotate_left(1);
    r3 = r3.rotate_left(7);
    r0 = r0 ^ r4 ^ r3;
    r1 = r1 ^ r3 ^ (r4 << 7);
    r0 = r0.rotate_left(5);
    r1 = r1.rotate_left(22);
    r0 ^= subkeys[12];
    r4 ^= subkeys[12 + 1];
    r1 ^= subkeys[12 + 2];
    r3 ^= subkeys[12 + 3];
    r2 = r0;
    r0 |= r3;
    r3 ^= r4;
    r4 &= r2;
    r2 ^= r1;
    r1 ^= r3;
    r3 &= r0;
    r2 |= r4;
    r3 ^= r2;
    r0 ^= r4;
    r2 &= r0;
    r4 ^= r3;
    r2 ^= r1;
    r4 |= r0;
    r4 ^= r1;
    r0 ^= r3;
    r1 = r4;
    r4 |= r3;
    r4 ^= r0;
    r4 = r4.rotate_left(13);
    r3 = r3.rotate_left(3);
    r1 = r1 ^ r4 ^ r3;
    r2 = r2 ^ r3 ^ (r4 << 3);
    r1 = r1.rotate_left(1);
    r2 = r2.rotate_left(7);
    r4 = r4 ^ r1 ^ r2;
    r3 = r3 ^ r2 ^ (r1 << 7);
    r4 = r4.rotate_left(5);
    r3 = r3.rotate_left(22);
    r4 ^= subkeys[16];
    r1 ^= subkeys[16 + 1];
    r3 ^= subkeys[16 + 2];
    r2 ^= subkeys[16 + 3];
    r1 ^= r2;
    r2 = !r2;
    r3 ^= r2;
    r2 ^= r4;
    r0 = r1;
    r1 &= r2;
    r1 ^= r3;
    r0 ^= r2;
    r4 ^= r0;
    r3 &= r0;
    r3 ^= r4;
    r4 &= r1;
    r2 ^= r4;
    r0 |= r1;
    r0 ^= r4;
    r4 |= r2;
    r4 ^= r3;
    r3 &= r2;
    r4 = !r4;
    r0 ^= r3;
    r1 = r1.rotate_left(13);
    r4 = r4.rotate_left(3);
    r0 = r0 ^ r1 ^ r4;
    r2 = r2 ^ r4 ^ (r1 << 3);
    r0 = r0.rotate_left(1);
    r2 = r2.rotate_left(7);
    r1 = r1 ^ r0 ^ r2;
    r4 = r4 ^ r2 ^ (r0 << 7);
    r1 = r1.rotate_left(5);
    r4 = r4.rotate_left(22);
    r1 ^= subkeys[20];
    r0 ^= subkeys[20 + 1];
    r4 ^= subkeys[20 + 2];
    r2 ^= subkeys[20 + 3];
    r1 ^= r0;
    r0 ^= r2;
    r2 = !r2;
    r3 = r0;
    r0 &= r1;
    r4 ^= r2;
    r0 ^= r4;
    r4 |= r3;
    r3 ^= r2;
    r2 &= r0;
    r2 ^= r1;
    r3 ^= r0;
    r3 ^= r4;
    r4 ^= r1;
    r1 &= r2;
    r4 = !r4;
    r1 ^= r3;
    r3 |= r2;
    r4 ^= r3;
    r0 = r0.rotate_left(13);
    r1 = r1.rotate_left(3);
    r2 = r2 ^ r0 ^ r1;
    r4 = r4 ^ r1 ^ (r0 << 3);
    r2 = r2.rotate_left(1);
    r4 = r4.rotate_left(7);
    r0 = r0 ^ r2 ^ r4;
    r1 = r1 ^ r4 ^ (r2 << 7);
    r0 = r0.rotate_left(5);
    r1 = r1.rotate_left(22);
    r0 ^= subkeys[24];
    r2 ^= subkeys[24 + 1];
    r1 ^= subkeys[24 + 2];
    r4 ^= subkeys[24 + 3];
    r1 = !r1;
    r3 = r4;
    r4 &= r0;
    r0 ^= r3;
    r4 ^= r1;
    r1 |= r3;
    r2 ^= r4;
    r1 ^= r0;
    r0 |= r2;
    r1 ^= r2;
    r3 ^= r0;
    r0 |= r4;
    r0 ^= r1;
    r3 ^= r4;
    r3 ^= r0;
    r4 = !r4;
    r1 &= r3;
    r1 ^= r4;
    r0 = r0.rotate_left(13);
    r3 = r3.rotate_left(3);
    r2 = r2 ^ r0 ^ r3;
    r1 = r1 ^ r3 ^ (r0 << 3);
    r2 = r2.rotate_left(1);
    r1 = r1.rotate_left(7);
    r0 = r0 ^ r2 ^ r1;
    r3 = r3 ^ r1 ^ (r2 << 7);
    r0 = r0.rotate_left(5);
    r3 = r3.rotate_left(22);
    r0 ^= subkeys[28];
    r2 ^= subkeys[28 + 1];
    r3 ^= subkeys[28 + 2];
    r1 ^= subkeys[28 + 3];
    r4 = r2;
    r2 |= r3;
    r2 ^= r1;
    r4 ^= r3;
    r3 ^= r2;
    r1 |= r4;
    r1 &= r0;
    r4 ^= r3;
    r1 ^= r2;
    r2 |= r4;
    r2 ^= r0;
    r0 |= r4;
    r0 ^= r3;
    r2 ^= r4;
    r3 ^= r2;
    r2 &= r0;
    r2 ^= r4;
    r3 = !r3;
    r3 |= r0;
    r4 ^= r3;
    r4 = r4.rotate_left(13);
    r2 = r2.rotate_left(3);
    r1 = r1 ^ r4 ^ r2;
    r0 = r0 ^ r2 ^ (r4 << 3);
    r1 = r1.rotate_left(1);
    r0 = r0.rotate_left(7);
    r4 = r4 ^ r1 ^ r0;
    r2 = r2 ^ r0 ^ (r1 << 7);
    r4 = r4.rotate_left(5);
    r2 = r2.rotate_left(22);
    r4 ^= subkeys[32];
    r1 ^= subkeys[32 + 1];
    r2 ^= subkeys[32 + 2];
    r0 ^= subkeys[32 + 3];
    r0 ^= r4;
    r3 = r1;
    r1 &= r0;
    r3 ^= r2;
    r1 ^= r4;
    r4 |= r0;
    r4 ^= r3;
    r3 ^= r0;
    r0 ^= r2;
    r2 |= r1;
    r2 ^= r3;
    r3 = !r3;
    r3 |= r1;
    r1 ^= r0;
    r1 ^= r3;
    r0 |= r4;
    r1 ^= r0;
    r3 ^= r0;
    r1 = r1.rotate_left(13);
    r2 = r2.rotate_left(3);
    r3 = r3 ^ r1 ^ r2;
    r4 = r4 ^ r2 ^ (r1 << 3);
    r3 = r3.rotate_left(1);
    r4 = r4.rotate_left(7);
    r1 = r1 ^ r3 ^ r4;
    r2 = r2 ^ r4 ^ (r3 << 7);
    r1 = r1.rotate_left(5);
    r2 = r2.rotate_left(22);
    r1 ^= subkeys[36];
    r3 ^= subkeys[36 + 1];
    r2 ^= subkeys[36 + 2];
    r4 ^= subkeys[36 + 3];
    r1 = !r1;
    r2 = !r2;
    r0 = r1;
    r1 &= r3;
    r2 ^= r1;
    r1 |= r4;
    r4 ^= r2;
    r3 ^= r1;
    r1 ^= r0;
    r0 |= r3;
    r3 ^= r4;
    r2 |= r1;
    r2 &= r0;
    r1 ^= r3;
    r3 &= r2;
    r3 ^= r1;
    r1 &= r2;
    r1 ^= r0;
    r2 = r2.rotate_left(13);
    r4 = r4.rotate_left(3);
    r1 = r1 ^ r2 ^ r4;
    r3 = r3 ^ r4 ^ (r2 << 3);
    r1 = r1.rotate_left(1);
    r3 = r3.rotate_left(7);
    r2 = r2 ^ r1 ^ r3;
    r4 = r4 ^ r3 ^ (r1 << 7);
    r2 = r2.rotate_left(5);
    r4 = r4.rotate_left(22);
    r2 ^= subkeys[40];
    r1 ^= subkeys[40 + 1];
    r4 ^= subkeys[40 + 2];
    r3 ^= subkeys[40 + 3];
    r0 = r2;
    r2 &= r4;
    r2 ^= r3;
    r4 ^= r1;
    r4 ^= r2;
    r3 |= r0;
    r3 ^= r1;
    r0 ^= r4;
    r1 = r3;
    r3 |= r0;
    r3 ^= r2;
    r2 &= r1;
    r0 ^= r2;
    r1 ^= r3;
    r1 ^= r0;
    r0 = !r0;
    r4 = r4.rotate_left(13);
    r1 = r1.rotate_left(3);
    r3 = r3 ^ r4 ^ r1;
    r0 = r0 ^ r1 ^ (r4 << 3);
    r3 = r3.rotate_left(1);
    r0 = r0.rotate_left(7);
    r4 = r4 ^ r3 ^ r0;
    r1 = r1 ^ r0 ^ (r3 << 7);
    r4 = r4.rotate_left(5);
    r1 = r1.rotate_left(22);
    r4 ^= subkeys[44];
    r3 ^= subkeys[44 + 1];
    r1 ^= subkeys[44 + 2];
    r0 ^= subkeys[44 + 3];
    r2 = r4;
    r4 |= r0;
    r0 ^= r3;
    r3 &= r2;
    r2 ^= r1;
    r1 ^= r0;
    r0 &= r4;
    r2 |= r3;
    r0 ^= r2;
    r4 ^= r3;
    r2 &= r4;
    r3 ^= r0;
    r2 ^= r1;
    r3 |= r4;
    r3 ^= r1;
    r4 ^= r0;
    r1 = r3;
    r3 |= r0;
    r3 ^= r4;
    r3 = r3.rotate_left(13);
    r0 = r0.rotate_left(3);
    r1 = r1 ^ r3 ^ r0;
    r2 = r2 ^ r0 ^ (r3 << 3);
    r1 = r1.rotate_left(1);
    r2 = r2.rotate_left(7);
    r3 = r3 ^ r1 ^ r2;
    r0 = r0 ^ r2 ^ (r1 << 7);
    r3 = r3.rotate_left(5);
    r0 = r0.rotate_left(22);
    lfsr[9] = r3;
    lfsr[8] = r1;
    lfsr[7] = r0;
    lfsr[6] = r2;
    r3 ^= subkeys[48];
    r1 ^= subkeys[48 + 1];
    r0 ^= subkeys[48 + 2];
    r2 ^= subkeys[48 + 3];
    r1 ^= r2;
    r2 = !r2;
    r0 ^= r2;
    r2 ^= r3;
    r4 = r1;
    r1 &= r2;
    r1 ^= r0;
    r4 ^= r2;
    r3 ^= r4;
    r0 &= r4;
    r0 ^= r3;
    r3 &= r1;
    r2 ^= r3;
    r4 |= r1;
    r4 ^= r3;
    r3 |= r2;
    r3 ^= r0;
    r0 &= r2;
    r3 = !r3;
    r4 ^= r0;
    r1 = r1.rotate_left(13);
    r3 = r3.rotate_left(3);
    r4 = r4 ^ r1 ^ r3;
    r2 = r2 ^ r3 ^ (r1 << 3);
    r4 = r4.rotate_left(1);
    r2 = r2.rotate_left(7);
    r1 = r1 ^ r4 ^ r2;
    r3 = r3 ^ r2 ^ (r4 << 7);
    r1 = r1.rotate_left(5);
    r3 = r3.rotate_left(22);
    r1 ^= subkeys[52];
    r4 ^= subkeys[52 + 1];
    r3 ^= subkeys[52 + 2];
    r2 ^= subkeys[52 + 3];
    r1 ^= r4;
    r4 ^= r2;
    r2 = !r2;
    r0 = r4;
    r4 &= r1;
    r3 ^= r2;
    r4 ^= r3;
    r3 |= r0;
    r0 ^= r2;
    r2 &= r4;
    r2 ^= r1;
    r0 ^= r4;
    r0 ^= r3;
    r3 ^= r1;
    r1 &= r2;
    r3 = !r3;
    r1 ^= r0;
    r0 |= r2;
    r3 ^= r0;
    r4 = r4.rotate_left(13);
    r1 = r1.rotate_left(3);
    r2 = r2 ^ r4 ^ r1;
    r3 = r3 ^ r1 ^ (r4 << 3);
    r2 = r2.rotate_left(1);
    r3 = r3.rotate_left(7);
    r4 = r4 ^ r2 ^ r3;
    r1 = r1 ^ r3 ^ (r2 << 7);
    r4 = r4.rotate_left(5);
    r1 = r1.rotate_left(22);
    r4 ^= subkeys[56];
    r2 ^= subkeys[56 + 1];
    r1 ^= subkeys[56 + 2];
    r3 ^= subkeys[56 + 3];
    r1 = !r1;
    r0 = r3;
    r3 &= r4;
    r4 ^= r0;
    r3 ^= r1;
    r1 |= r0;
    r2 ^= r3;
    r1 ^= r4;
    r4 |= r2;
    r1 ^= r2;
    r0 ^= r4;
    r4 |= r3;
    r4 ^= r1;
    r0 ^= r3;
    r0 ^= r4;
    r3 = !r3;
    r1 &= r0;
    r1 ^= r3;
    r4 = r4.rotate_left(13);
    r0 = r0.rotate_left(3);
    r2 = r2 ^ r4 ^ r0;
    r1 = r1 ^ r0 ^ (r4 << 3);
    r2 = r2.rotate_left(1);
    r1 = r1.rotate_left(7);
    r4 = r4 ^ r2 ^ r1;
    r0 = r0 ^ r1 ^ (r2 << 7);
    r4 = r4.rotate_left(5);
    r0 = r0.rotate_left(22);
    r4 ^= subkeys[60];
    r2 ^= subkeys[60 + 1];
    r0 ^= subkeys[60 + 2];
    r1 ^= subkeys[60 + 3];
    r3 = r2;
    r2 |= r0;
    r2 ^= r1;
    r3 ^= r0;
    r0 ^= r2;
    r1 |= r3;
    r1 &= r4;
    r3 ^= r0;
    r1 ^= r2;
    r2 |= r3;
    r2 ^= r4;
    r4 |= r3;
    r4 ^= r0;
    r2 ^= r3;
    r0 ^= r2;
    r2 &= r4;
    r2 ^= r3;
    r0 = !r0;
    r0 |= r4;
    r3 ^= r0;
    r3 = r3.rotate_left(13);
    r2 = r2.rotate_left(3);
    r1 = r1 ^ r3 ^ r2;
    r4 = r4 ^ r2 ^ (r3 << 3);
    r1 = r1.rotate_left(1);
    r4 = r4.rotate_left(7);
    r3 = r3 ^ r1 ^ r4;
    r2 = r2 ^ r4 ^ (r1 << 7);
    r3 = r3.rotate_left(5);
    r2 = r2.rotate_left(22);
    r3 ^= subkeys[64];
    r1 ^= subkeys[64 + 1];
    r2 ^= subkeys[64 + 2];
    r4 ^= subkeys[64 + 3];
    r4 ^= r3;
    r0 = r1;
    r1 &= r4;
    r0 ^= r2;
    r1 ^= r3;
    r3 |= r4;
    r3 ^= r0;
    r0 ^= r4;
    r4 ^= r2;
    r2 |= r1;
    r2 ^= r0;
    r0 = !r0;
    r0 |= r1;
    r1 ^= r4;
    r1 ^= r0;
    r4 |= r3;
    r1 ^= r4;
    r0 ^= r4;
    r1 = r1.rotate_left(13);
    r2 = r2.rotate_left(3);
    r0 = r0 ^ r1 ^ r2;
    r3 = r3 ^ r2 ^ (r1 << 3);
    r0 = r0.rotate_left(1);
    r3 = r3.rotate_left(7);
    r1 = r1 ^ r0 ^ r3;
    r2 = r2 ^ r3 ^ (r0 << 7);
    r1 = r1.rotate_left(5);
    r2 = r2.rotate_left(22);
    r1 ^= subkeys[68];
    r0 ^= subkeys[68 + 1];
    r2 ^= subkeys[68 + 2];
    r3 ^= subkeys[68 + 3];
    r1 = !r1;
    r2 = !r2;
    r4 = r1;
    r1 &= r0;
    r2 ^= r1;
    r1 |= r3;
    r3 ^= r2;
    r0 ^= r1;
    r1 ^= r4;
    r4 |= r0;
    r0 ^= r3;
    r2 |= r1;
    r2 &= r4;
    r1 ^= r0;
    r0 &= r2;
    r0 ^= r1;
    r1 &= r2;
    r1 ^= r4;
    r2 = r2.rotate_left(13);
    r3 = r3.rotate_left(3);
    r1 = r1 ^ r2 ^ r3;
    r0 = r0 ^ r3 ^ (r2 << 3);
    r1 = r1.rotate_left(1);
    r0 = r0.rotate_left(7);
    r2 = r2 ^ r1 ^ r0;
    r3 = r3 ^ r0 ^ (r1 << 7);
    r2 = r2.rotate_left(5);
    r3 = r3.rotate_left(22);
    fsm_r[0] = r2;
    lfsr[4] = r1;
    fsm_r[1] = r3;
    lfsr[5] = r0;
    r2 ^= subkeys[72];
    r1 ^= subkeys[72 + 1];
    r3 ^= subkeys[72 + 2];
    r0 ^= subkeys[72 + 3];
    r4 = r2;
    r2 &= r3;
    r2 ^= r0;
    r3 ^= r1;
    r3 ^= r2;
    r0 |= r4;
    r0 ^= r1;
    r4 ^= r3;
    r1 = r0;
    r0 |= r4;
    r0 ^= r2;
    r2 &= r1;
    r4 ^= r2;
    r1 ^= r0;
    r1 ^= r4;
    r4 = !r4;
    r3 = r3.rotate_left(13);
    r1 = r1.rotate_left(3);
    r0 = r0 ^ r3 ^ r1;
    r4 = r4 ^ r1 ^ (r3 << 3);
    r0 = r0.rotate_left(1);
    r4 = r4.rotate_left(7);
    r3 = r3 ^ r0 ^ r4;
    r1 = r1 ^ r4 ^ (r0 << 7);
    r3 = r3.rotate_left(5);
    r1 = r1.rotate_left(22);
    r3 ^= subkeys[76];
    r0 ^= subkeys[76 + 1];
    r1 ^= subkeys[76 + 2];
    r4 ^= subkeys[76 + 3];
    r2 = r3;
    r3 |= r4;
    r4 ^= r0;
    r0 &= r2;
    r2 ^= r1;
    r1 ^= r4;
    r4 &= r3;
    r2 |= r0;
    r4 ^= r2;
    r3 ^= r0;
    r2 &= r3;
    r0 ^= r4;
    r2 ^= r1;
    r0 |= r3;
    r0 ^= r1;
    r3 ^= r4;
    r1 = r0;
    r0 |= r4;
    r0 ^= r3;
    r0 = r0.rotate_left(13);
    r4 = r4.rotate_left(3);
    r1 = r1 ^ r0 ^ r4;
    r2 = r2 ^ r4 ^ (r0 << 3);
    r1 = r1.rotate_left(1);
    r2 = r2.rotate_left(7);
    r0 = r0 ^ r1 ^ r2;
    r4 = r4 ^ r2 ^ (r1 << 7);
    r0 = r0.rotate_left(5);
    r4 = r4.rotate_left(22);
    r0 ^= subkeys[80];
    r1 ^= subkeys[80 + 1];
    r4 ^= subkeys[80 + 2];
    r2 ^= subkeys[80 + 3];
    r1 ^= r2;
    r2 = !r2;
    r4 ^= r2;
    r2 ^= r0;
    r3 = r1;
    r1 &= r2;
    r1 ^= r4;
    r3 ^= r2;
    r0 ^= r3;
    r4 &= r3;
    r4 ^= r0;
    r0 &= r1;
    r2 ^= r0;
    r3 |= r1;
    r3 ^= r0;
    r0 |= r2;
    r0 ^= r4;
    r4 &= r2;
    r0 = !r0;
    r3 ^= r4;
    r1 = r1.rotate_left(13);
    r0 = r0.rotate_left(3);
    r3 = r3 ^ r1 ^ r0;
    r2 = r2 ^ r0 ^ (r1 << 3);
    r3 = r3.rotate_left(1);
    r2 = r2.rotate_left(7);
    r1 = r1 ^ r3 ^ r2;
    r0 = r0 ^ r2 ^ (r3 << 7);
    r1 = r1.rotate_left(5);
    r0 = r0.rotate_left(22);
    r1 ^= subkeys[84];
    r3 ^= subkeys[84 + 1];
    r0 ^= subkeys[84 + 2];
    r2 ^= subkeys[84 + 3];
    r1 ^= r3;
    r3 ^= r2;
    r2 = !r2;
    r4 = r3;
    r3 &= r1;
    r0 ^= r2;
    r3 ^= r0;
    r0 |= r4;
    r4 ^= r2;
    r2 &= r3;
    r2 ^= r1;
    r4 ^= r3;
    r4 ^= r0;
    r0 ^= r1;
    r1 &= r2;
    r0 = !r0;
    r1 ^= r4;
    r4 |= r2;
    r0 ^= r4;
    r3 = r3.rotate_left(13);
    r1 = r1.rotate_left(3);
    r2 = r2 ^ r3 ^ r1;
    r0 = r0 ^ r1 ^ (r3 << 3);
    r2 = r2.rotate_left(1);
    r0 = r0.rotate_left(7);
    r3 = r3 ^ r2 ^ r0;
    r1 = r1 ^ r0 ^ (r2 << 7);
    r3 = r3.rotate_left(5);
    r1 = r1.rotate_left(22);
    r3 ^= subkeys[88];
    r2 ^= subkeys[88 + 1];
    r1 ^= subkeys[88 + 2];
    r0 ^= subkeys[88 + 3];
    r1 = !r1;
    r4 = r0;
    r0 &= r3;
    r3 ^= r4;
    r0 ^= r1;
    r1 |= r4;
    r2 ^= r0;
    r1 ^= r3;
    r3 |= r2;
    r1 ^= r2;
    r4 ^= r3;
    r3 |= r0;
    r3 ^= r1;
    r4 ^= r0;
    r4 ^= r3;
    r0 = !r0;
    r1 &= r4;
    r1 ^= r0;
    r3 = r3.rotate_left(13);
    r4 = r4.rotate_left(3);
    r2 = r2 ^ r3 ^ r4;
    r1 = r1 ^ r4 ^ (r3 << 3);
    r2 = r2.rotate_left(1);
    r1 = r1.rotate_left(7);
    r3 = r3 ^ r2 ^ r1;
    r4 = r4 ^ r1 ^ (r2 << 7);
    r3 = r3.rotate_left(5);
    r4 = r4.rotate_left(22);
    r3 ^= subkeys[92];
    r2 ^= subkeys[92 + 1];
    r4 ^= subkeys[92 + 2];
    r1 ^= subkeys[92 + 3];
    r0 = r2;
    r2 |= r4;
    r2 ^= r1;
    r0 ^= r4;
    r4 ^= r2;
    r1 |= r0;
    r1 &= r3;
    r0 ^= r4;
    r1 ^= r2;
    r2 |= r0;
    r2 ^= r3;
    r3 |= r0;
    r3 ^= r4;
    r2 ^= r0;
    r4 ^= r2;
    r2 &= r3;
    r2 ^= r0;
    r4 = !r4;
    r4 |= r3;
    r0 ^= r4;
    r0 = r0.rotate_left(13);
    r2 = r2.rotate_left(3);
    r1 = r1 ^ r0 ^ r2;
    r3 = r3 ^ r2 ^ (r0 << 3);
    r1 = r1.rotate_left(1);
    r3 = r3.rotate_left(7);
    r0 = r0 ^ r1 ^ r3;
    r2 = r2 ^ r3 ^ (r1 << 7);
    r0 = r0.rotate_left(5);
    r2 = r2.rotate_left(22);
    r0 ^= subkeys[96];
    r1 ^= subkeys[96 + 1];
    r2 ^= subkeys[96 + 2];
    r3 ^= subkeys[96 + 3];
    lfsr[3] = r0;
    lfsr[2] = r1;
    lfsr[1] = r2;
    lfsr[0] = r3;
}


impl SynchronousStreamCipher for Sosemanuk {
    fn process(&mut self, input: &[u8], output: &mut [u8]) {
        assert!(input.len() == output.len());
        for (x, y) in input.iter().zip(output.iter_mut()) {
            *y = *x ^ self.next();
        }
    }
}

impl Encryptor for Sosemanuk {
    fn encrypt(&mut self, input: &mut RefReadBuffer, output: &mut RefWriteBuffer, _: bool)
            -> Result<BufferResult, SymmetricCipherError> {
        symm_enc_or_dec(self, input, output)
    }
}

impl Decryptor for Sosemanuk {
    fn decrypt(&mut self, input: &mut RefReadBuffer, output: &mut RefWriteBuffer, _: bool)
            -> Result<BufferResult, SymmetricCipherError> {
        symm_enc_or_dec(self, input, output)
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod bench;
