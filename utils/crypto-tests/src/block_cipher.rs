use block_cipher_trait::BlockCipher;
use generic_array::{GenericArray, ArrayLength};

/// Temporary here before it's merged into generic-array
#[inline]
fn from_slice<T, N: ArrayLength<T>>(slice: &[T]) -> &GenericArray<T, N> {
    assert_eq!(slice.len(), N::to_usize());
    unsafe {
        &*(slice.as_ptr() as *const GenericArray<T, N>)
    }
}

pub struct BlockCipherTest {
    pub name: &'static str,
    pub key: &'static [u8],
    pub input: &'static [u8],
    pub output: &'static [u8],
}

#[macro_export]
macro_rules! new_block_cipher_tests {
    ( $( $name:expr ),*  ) => {
        [$(
            BlockCipherTest {
                name: $name,
                key: include_bytes!(concat!("data/", $name, ".key.bin")),
                input: include_bytes!(concat!("data/", $name, ".input.bin")),
                output: include_bytes!(concat!("data/", $name, ".output.bin")),
            },
        )*]
    };
}

pub fn encrypt_decrypt<B: BlockCipher>(tests: &[BlockCipherTest]) {
    let mut buf = GenericArray::new();
    // test encryption
    for test in tests {
        let state = B::new(test.key);
        let input = from_slice(test.input);
        state.encrypt_block(input, &mut buf);
        assert_eq!(test.output, &buf[..]);
    }

    // test decription
    for test in tests {
        let state = B::new(test.key);
        let output = from_slice(test.output);
        state.decrypt_block(output, &mut buf);
        assert_eq!(test.input, &buf[..]);
    }
}

#[macro_export]
macro_rules! bench_block_cipher {
    ($cipher:path, $key:expr) => {
        extern crate test;
        extern crate block_cipher_trait;
        extern crate generic_array;

        use test::Bencher;
        use block_cipher_trait::BlockCipher;
        use generic_array::GenericArray;

        #[bench]
        pub fn encrypt(bh: &mut Bencher) {
            let state = blowfish::Blowfish::new($key);
            let input = GenericArray::new();
            let mut output = GenericArray::new();

            bh.iter(|| {
                state.encrypt_block(&input, &mut output);
            });
            bh.bytes = 8u64;
        }
    }
}
