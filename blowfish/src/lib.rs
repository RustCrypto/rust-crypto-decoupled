#![no_std]
#![feature(step_by)]
#![feature(test)]
extern crate test;
extern crate crypto_bytes;
extern crate crypto_symmetric;

use crypto_bytes::{read_u32v_be, write_u32_be};
use crypto_symmetric::{BlockEncryptor, BlockDecryptor};

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

    // For bcrypt. Use Blowfish::new instead.
    pub fn init_state() -> Blowfish {
        Blowfish {
            p: consts::P,
            s: consts::S,
        }
    }

    // For bcrypt. Use Blowfish::new instead.
    pub fn expand_key(&mut self, key: &[u8]) {
        let mut key_pos = 0;
        for i in 0..18 {
            self.p[i] ^= next_u32_wrap(key, &mut key_pos);
        }
        let mut l = 0u32;
        let mut r = 0u32;
        for i in (0..18).step_by(2) {
            let (new_l, new_r) = self.encrypt(l, r);
            l = new_l;
            r = new_r;
            self.p[i] = l;
            self.p[i+1] = r;
        }
        for i in 0..4 {
            for j in (0..256).step_by(2) {
                let (new_l, new_r) = self.encrypt(l, r);
                l = new_l;
                r = new_r;
                self.s[i][j] = l;
                self.s[i][j+1] = r;
            }
        }
    }

    // Bcrypt key schedule.
    pub fn salted_expand_key(&mut self, salt: &[u8], key: &[u8]) {
        let mut key_pos = 0;
        for i in 0..18 {
            self.p[i] ^= next_u32_wrap(key, &mut key_pos);
        }
        let mut l = 0u32;
        let mut r = 0u32;
        let mut salt_pos = 0;
        for i in (0..18).step_by(2) {
            let (new_l, new_r) = self.encrypt(l ^ next_u32_wrap(salt, &mut salt_pos), r ^ next_u32_wrap(salt, &mut salt_pos));
            l = new_l;
            r = new_r;
            self.p[i] = l;
            self.p[i+1] = r;
        }
        for i in 0..4 {
            for j in (0..256).step_by(4) {
                let (new_l, new_r) = self.encrypt(l ^ next_u32_wrap(salt, &mut salt_pos), r ^ next_u32_wrap(salt, &mut salt_pos));
                l = new_l;
                r = new_r;
                self.s[i][j] = l;
                self.s[i][j+1] = r;

                let (new_l, new_r) = self.encrypt(l ^ next_u32_wrap(salt, &mut salt_pos), r ^ next_u32_wrap(salt, &mut salt_pos));
                l = new_l;
                r = new_r;
                self.s[i][j+2] = l;
                self.s[i][j+3] = r;
            }
        }
    }

    fn round_function(&self, x: u32) -> u32 {
        ((self.s[0][(x >> 24) as usize].wrapping_add(self.s[1][((x >> 16) & 0xff) as usize])) ^ self.s[2][((x >> 8) & 0xff) as usize]).wrapping_add(self.s[3][(x & 0xff) as usize])
    }

    // Public for bcrypt.
    pub fn encrypt(&self, mut l: u32, mut r: u32) -> (u32, u32) {
        for i in (0..16).step_by(2) {
            l ^= self.p[i];
            r ^= self.round_function(l);
            r ^= self.p[i+1];
            l ^= self.round_function(r);
        }
        l ^= self.p[16];
        r ^= self.p[17];
        (r, l)
    }

    fn decrypt(&self, mut l: u32, mut r: u32) -> (u32, u32) {
        let mut i = 16;
        while i > 0 {
            l ^= self.p[i+1];
            r ^= self.round_function(l);
            r ^= self.p[i];
            l ^= self.round_function(r);
            i -= 2;
        }
        l ^= self.p[1];
        r ^= self.p[0];
        (r, l)
    }
}

impl BlockEncryptor for Blowfish {
    fn block_size(&self) -> usize {
        8
    }

    fn encrypt_block(&self, input: &[u8], output: &mut [u8]) {
        assert!(input.len() == 8);
        assert!(output.len() == 8);
        let mut block = [0u32, 0u32];
        read_u32v_be(&mut block, input);
        let (l, r) = self.encrypt(block[0], block[1]);
        write_u32_be(&mut output[0..4], l);
        write_u32_be(&mut output[4..8], r);
    }
}

impl BlockDecryptor for Blowfish {
    fn block_size(&self) -> usize {
        8
    }

    fn decrypt_block(&self, input: &[u8], output: &mut [u8]) {
        assert!(input.len() == 8);
        assert!(output.len() == 8);
        let mut block = [0u32, 0u32];
        read_u32v_be(&mut block, input);
        let (l, r) = self.decrypt(block[0], block[1]);
        write_u32_be(&mut output[0..4], l);
        write_u32_be(&mut output[4..8], r);
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod bench;
