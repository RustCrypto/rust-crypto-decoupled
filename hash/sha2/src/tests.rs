use super::{Sha512, Sha384, Sha512Trunc256, Sha512Trunc224, Sha256, Sha224};
use crypto_tests::hash::{Test, main_test, one_million_a};

#[test]
fn sha2_224_main() {
    let tests = new_tests!("sha224/test1", "sha224/test2", "sha224/test3");
    main_test(&mut Sha224::new(), &tests);
}

#[test]
fn sha2_256_main() {
    let tests = new_tests!("sha256/test1", "sha256/test2", "sha256/test3");
    main_test(&mut Sha256::new(), &tests);
}

#[test]
fn sha2_384_main() {
    let tests = new_tests!("sha384/test1", "sha384/test2", "sha384/test3");
    main_test(&mut Sha384::new(), &tests);
}

#[test]
fn sha2_512_main() {
    let tests = new_tests!("sha512/test1", "sha512/test2", "sha512/test3");
    main_test(&mut Sha512::new(), &tests);
}

#[test]
fn sha2_512_trunc_256_main() {
    let tests = new_tests!("sha512_256/test1", "sha512_256/test2", "sha512_256/test3");
    main_test(&mut Sha512Trunc256::new(), &tests);
}

#[test]
fn sha2_512_trunc_224_main() {
    let tests = new_tests!("sha512_224/test1", "sha512_224/test2", "sha512_224/test3");
    main_test(&mut Sha512Trunc224::new(), &tests);
}

#[test]
fn sha2_256_1million_a() {
    let output = include_bytes!("data/sha256/one_million_a.output");
    one_million_a(&mut Sha256::new(), output);
}


#[test]
fn sha2_512_1million_a() {
    let output = include_bytes!("data/sha512/one_million_a.output");
    one_million_a(&mut Sha512::new(), output);
}
