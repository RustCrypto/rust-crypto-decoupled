use generic_array::GenericArray;
use digest::Digest;
use digest_buffer::DigestBuffer;
use generic_array::typenum::{U28, U32, U64};
use byte_tools::{write_u32_be, add_bytes_to_bits};

use consts::{STATE_LEN, H224, H256};

use sha256_utils::sha256_digest_block;


/// A structure that represents that state of a digest computation for the
/// SHA-2 512 family of digest functions
#[derive(Clone, Copy)]
struct Engine256State {
    h: [u32; 8],
}

impl Engine256State {
    fn new(h: &[u32; STATE_LEN]) -> Engine256State { Engine256State { h: *h } }

    pub fn process_block(&mut self, data: &[u8]) {
        sha256_digest_block(&mut self.h, data);
    }
}

/// A structure that keeps track of the state of the Sha-256 operation and
/// contains the logic necessary to perform the final calculations.
#[derive(Clone, Copy)]
struct Engine256 {
    length_bits: u64,
    buffer: DigestBuffer<U64>,
    state: Engine256State,
}

impl Engine256 {
    fn new(h: &[u32; STATE_LEN]) -> Engine256 {
        Engine256 {
            length_bits: 0,
            buffer: Default::default(),
            state: Engine256State::new(h),
        }
    }

    fn input(&mut self, input: &[u8]) {
        // Assumes that input.len() can be converted to u64 without overflow
        self.length_bits = add_bytes_to_bits(self.length_bits,
                                             input.len() as u64);
        let self_state = &mut self.state;
        self.buffer
            .input(input, |input: &[u8]| self_state.process_block(input));
    }

    fn finish(&mut self) {
        let self_state = &mut self.state;
        self.buffer.standard_padding(8, |input: &[u8]| {
            self_state.process_block(input)
        });
        write_u32_be(self.buffer.next(4), (self.length_bits >> 32) as u32);
        write_u32_be(self.buffer.next(4), self.length_bits as u32);
        self_state.process_block(self.buffer.full_buffer());
    }
}


/// The SHA-256 hash algorithm with the SHA-256 initial hash value.
#[derive(Clone, Copy)]
pub struct Sha256 {
    engine: Engine256,
}

impl Sha256 {
    /// Construct an new instance of a SHA-256 digest.
    pub fn new() -> Sha256 { Sha256 { engine: Engine256::new(&H256) } }
}

impl Default for Sha256 {
    fn default() -> Self { Self::new() }
}

impl Digest for Sha256 {
    type N = U32;

    fn input(&mut self, msg: &[u8]) { self.engine.input(msg); }

    fn result(mut self) -> GenericArray<u8, Self::N> {
        self.engine.finish();

        // TODO: replace with write_u32v_be
        let mut out = GenericArray::new();
        write_u32_be(&mut out[0..4], self.engine.state.h[0]);
        write_u32_be(&mut out[4..8], self.engine.state.h[1]);
        write_u32_be(&mut out[8..12], self.engine.state.h[2]);
        write_u32_be(&mut out[12..16], self.engine.state.h[3]);
        write_u32_be(&mut out[16..20], self.engine.state.h[4]);
        write_u32_be(&mut out[20..24], self.engine.state.h[5]);
        write_u32_be(&mut out[24..28], self.engine.state.h[6]);
        write_u32_be(&mut out[28..32], self.engine.state.h[7]);
        out
    }

    fn block_size(&self) -> usize { self.engine.buffer.size() }
}

/// The SHA-256 hash algorithm with the SHA-224 initial hash value. The result
/// is truncated to 224 bits.
#[derive(Clone, Copy)]
pub struct Sha224 {
    engine: Engine256,
}

impl Sha224 {
    /// Construct an new instance of a SHA-224 digest.
    pub fn new() -> Sha224 { Sha224 { engine: Engine256::new(&H224) } }
}

impl Default for Sha224 {
    fn default() -> Self { Self::new() }
}

impl Digest for Sha224 {
    type N = U28;

    fn input(&mut self, msg: &[u8]) { self.engine.input(msg); }

    fn result(mut self) -> GenericArray<u8, Self::N> {
        self.engine.finish();

        // TODO: replace with write_u32v_be
        let mut out = GenericArray::new();
        write_u32_be(&mut out[0..4], self.engine.state.h[0]);
        write_u32_be(&mut out[4..8], self.engine.state.h[1]);
        write_u32_be(&mut out[8..12], self.engine.state.h[2]);
        write_u32_be(&mut out[12..16], self.engine.state.h[3]);
        write_u32_be(&mut out[16..20], self.engine.state.h[4]);
        write_u32_be(&mut out[20..24], self.engine.state.h[5]);
        write_u32_be(&mut out[24..28], self.engine.state.h[6]);
        out
    }

    fn block_size(&self) -> usize { self.engine.buffer.size() }
}
