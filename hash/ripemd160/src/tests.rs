use super::Ripemd160;
use crypto_tests::hash::{Test, main_test, one_million_a};

#[test]
fn ripemd160_main() {
    // Test messages from FIPS 180-1
    let tests = new_tests!("test1", "test2", "test3", "test4");
    main_test(&mut Ripemd160::new(), &tests);
}

#[test]
fn ripemd160_1million_a() {
    let output = include_bytes!("data/one_million_a.output");
    one_million_a(&mut Ripemd160::new(), output);
}
