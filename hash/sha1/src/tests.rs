use super::Sha1;
use crypto_tests::hash::{Test, main_test, one_million_a};

#[test]
fn sha1_main() {
    // Examples from wikipedia
    let tests = new_tests!("test1", "test2", "test3");
    main_test(&mut Sha1::new(), &tests);
}

#[test]
fn sha1_1million_a() {
    let output = include_bytes!("data/one_million_a.output");
    one_million_a(&mut Sha1::new(), output);
}
