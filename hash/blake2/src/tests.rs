use super::{Blake2b, Blake2s};
use crypto_tests::hash::{Test, main_test};
use crypto_mac::Mac;

#[test]
fn blake2b() {
    let tests = new_tests!("blake2b/1", "blake2b/2", "blake2b/3");
    // Tests without key
    main_test(&mut Blake2b::new(64), &tests[..2]);
    // Test with key
    let key = include_bytes!("data/blake2b/3.key.bin");
    main_test(&mut Blake2b::new_keyed(64, key), &tests[2..]);
}

#[test]
fn blake2b_mac() {
    let key = include_bytes!("data/blake2b/mac.key.bin");
    let input = include_bytes!("data/blake2b/mac.input.bin");
    let output = include_bytes!("data/blake2b/mac.output.bin");
    let mut d = Blake2b::new_keyed(64, key);
    d.input(input);
    assert_eq!(d.result().code(), &output[..]);
}

#[test]
fn blake2s() {
    let tests = new_tests!("blake2s/1");
    let key = include_bytes!("data/blake2s/1.key.bin");
    main_test(&mut Blake2s::new_keyed(32, key), &tests);
}

#[test]
fn blake2s_mac() {
    let key = include_bytes!("data/blake2s/mac.key.bin");
    let input = include_bytes!("data/blake2s/mac.input.bin");
    let output = include_bytes!("data/blake2s/mac.output.bin");
    let mut d = Blake2s::new_keyed(32, key);
    d.input(input);
    assert_eq!(d.result().code(), &output[..]);
}