#![no_std]
#![feature(test)]
extern crate test;
extern crate byte_tools;
extern crate crypto_symmetric;
extern crate generic_array;

use byte_tools::{read_u32v_be, write_u32_be};
use crypto_symmetric::{Block64, BlockCipher};

use generic_array::typenum::U8;

mod consts;

#[derive(Clone,Copy)]
pub struct Blowfish {
    s: [[u32; 256]; 4],
    p: [u32; 18]
}

fn next_u32_wrap(buf: &[u8], offset: &mut usize) -> u32 {
    let mut v = 0;
    for _ in 0..4 {
        if *offset >= buf.len() {
            *offset = 0;
        }
        v = (v << 8) | buf[*offset] as u32;
        *offset += 1;
    }
    v
}

impl Blowfish {
    pub fn new(key: &[u8]) -> Blowfish {
        assert!(4 <= key.len() && key.len() <= 56);
        let mut blowfish = Blowfish::init_state();
        blowfish.expand_key(key);
        blowfish
    }

    fn init_state() -> Blowfish {
        Blowfish {
            p: consts::P,
            s: consts::S,
        }
    }

    fn expand_key(&mut self, key: &[u8]) {
        let mut key_pos = 0;
        for i in 0..18 {
            self.p[i] ^= next_u32_wrap(key, &mut key_pos);
        }
        let mut lr = (0u32, 0u32);
        for i in 0..9 {
            lr = self.encrypt(lr.0, lr.1);
            self.p[2*i] = lr.0;
            self.p[2*i+1] = lr.1;
        }
        for i in 0..4 {
            for j in 0..128 {
                lr = self.encrypt(lr.0, lr.1);
                self.s[i][2*j] = lr.0;
                self.s[i][2*j+1] = lr.1;
            }
        }
    }


    fn round_function(&self, x: u32) -> u32 {
        let a = self.s[0][(x >> 24) as usize];
        let b = self.s[1][((x >> 16) & 0xff) as usize];
        let c = self.s[2][((x >> 8) & 0xff) as usize];
        let d = self.s[3][(x & 0xff) as usize];
        (a.wrapping_add(b) ^ c).wrapping_add(d)
    }

    fn encrypt(&self, mut l: u32, mut r: u32) -> (u32, u32) {
        for i in 0..8 {
            l ^= self.p[2*i];
            r ^= self.round_function(l);
            r ^= self.p[2*i+1];
            l ^= self.round_function(r);
        }
        l ^= self.p[16];
        r ^= self.p[17];
        (r, l)
    }

    fn decrypt(&self, mut l: u32, mut r: u32) -> (u32, u32) {
        for i in (1..9).rev() {
            l ^= self.p[2*i+1];
            r ^= self.round_function(l);
            r ^= self.p[2*i];
            l ^= self.round_function(r);
        }
        l ^= self.p[1];
        r ^= self.p[0];
        (r, l)
    }
}

impl BlockCipher for Blowfish {
    type BlockSize = U8;

    fn encrypt_block(&self, input: &Block64, output: &mut Block64) {
        let mut block = [0u32, 0u32];
        read_u32v_be(&mut block, input);
        let (l, r) = self.encrypt(block[0], block[1]);
        write_u32_be(&mut output[0..4], l);
        write_u32_be(&mut output[4..8], r);
    }

    fn decrypt_block(&self, input: &Block64, output: &mut Block64) {
        let mut block = [0u32, 0u32];
        read_u32v_be(&mut block, input);
        let (l, r) = self.decrypt(block[0], block[1]);
        write_u32_be(&mut output[0..4], l);
        write_u32_be(&mut output[4..8], r);
    }
}


/// Bcrypt extension of blowfish
#[cfg(feature = "bcrypt")]
impl Blowfish {
    pub fn salted_expand_key(&mut self, salt: &[u8], key: &[u8]) {
        let mut key_pos = 0;
        for i in 0..18 {
            self.p[i] ^= next_u32_wrap(key, &mut key_pos);
        }
        let mut lr = (0u32, 0u32);
        let mut salt_pos = 0;
        for i in 0..9 {
            let lk = next_u32_wrap(salt, &mut salt_pos);
            let rk = next_u32_wrap(salt, &mut salt_pos);
            lr = self.encrypt(lr.0 ^ lk, lr.1 ^ rk);

            self.p[2*i] = lr.0;
            self.p[2*i+1] = lr.1;
        }
        for i in 0..4 {
            for j in 0..64 {
                let lk = next_u32_wrap(salt, &mut salt_pos);
                let rk = next_u32_wrap(salt, &mut salt_pos);
                lr = self.encrypt(lr.0 ^ lk, lr.1 ^ rk);

                self.s[i][4*j] = lr.0;
                self.s[i][4*j+1] = lr.1;

                let lk = next_u32_wrap(salt, &mut salt_pos);
                let rk = next_u32_wrap(salt, &mut salt_pos);
                lr = self.encrypt(lr.0 ^ lk, lr.1 ^ rk);

                self.s[i][4*j+2] = lr.0;
                self.s[i][4*j+3] = lr.1;
            }
        }
    }

    pub fn bc_init_state() -> Blowfish {
        Blowfish::init_state()
    }

    pub fn bc_encrypt(&self, l: u32, r: u32) -> (u32, u32) {
        self.encrypt(l, r)
    }

    pub fn bc_expand_key(&mut self, key: &[u8]) {
        self.expand_key(key)
    }
}


#[cfg(test)]
mod tests;