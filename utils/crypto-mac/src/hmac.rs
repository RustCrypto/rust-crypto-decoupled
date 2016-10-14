use byte_tools::copy_memory;
use digest::Digest;
use mac::{Mac, MacResult};
use generic_array::GenericArray;

const IPAD: u8 = 0x36;
const OPAD: u8 = 0x5c;

/// The Hmac struct represents an Hmac function - a Message Authentication Code
/// using a Digest.
pub struct Hmac<D: Digest> {
    digest: D,
    exp_key: GenericArray<u8, D::B>,
}

/// The key that Hmac processes must be the same as the block size of the
/// underlying Digest. If the provided key is smaller than that, we just pad it
/// with zeros. If its larger, we hash it and then pad it with zeros.
fn expand_key<D: Digest>(key: &[u8]) -> GenericArray<u8, D::B> {
    let mut exp_key = GenericArray::new();
    
    if key.len() <= exp_key.len() {
        copy_memory(key, &mut exp_key);
    } else {
        let mut digest = D::new();
        digest.input(key);
        let output = digest.result();
        copy_memory(&output, &mut exp_key[..output.len()]);
    }
    exp_key
}

impl <D: Digest> Hmac<D> {
    /// Create a new Hmac instance.
    pub fn new(key: &[u8]) -> Hmac<D> {
        let exp_key = expand_key::<D>(key);
        let mut hmac = Hmac {
            digest: D::new(),
            exp_key: exp_key,
        };
        hmac.init();
        hmac
    }

    fn derive_key(&self, mask: u8) -> GenericArray<u8, D::B> {
        let mut key = self.exp_key.clone();
        for elem in key.iter_mut() {
            *elem ^ mask;
        }
        key
    }

    fn init(&mut self) {
        let i_key_pad = self.derive_key(IPAD);
        self.digest.input(&i_key_pad);
    }
}

impl <D: Digest> Mac for Hmac<D> {
    type R = D::R;

    fn input(&mut self, data: &[u8]) {
        self.digest.input(data);
    }

    fn result(self) -> MacResult<D::R> {
        let o_key_pad = self.derive_key(OPAD);
        let output = self.digest.result();
        let mut digest = D::new();
        digest.input(&o_key_pad);
        digest.input(&output);
        MacResult::new(digest.result())
    }

    fn output_bytes(&self) -> usize { self.digest.output_bytes() }
}
