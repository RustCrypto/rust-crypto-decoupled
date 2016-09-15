use super::Md5;
use crypto_tests::hash::{Test, main_test, one_million_a};

#[test]
fn md5_main() {
    // Examples from wikipedia
    let tests = new_tests!("test1", "test2", "test3");
    main_test(&mut Md5::new(), &tests);
}

#[test]
fn md5_1million_a() {
    let output = include_bytes!("data/one_million_a.output");
    one_million_a(&mut Md5::new(), output);
}
