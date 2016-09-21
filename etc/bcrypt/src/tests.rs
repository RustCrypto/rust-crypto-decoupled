use super::bcrypt;

struct BcryptTest {
    pub name: &'static str,
    pub cost: u32,
    pub salt: &'static [u8],
    pub input: &'static [u8],
    pub output: &'static [u8],
}

macro_rules! get_tests {
    ( $( $name:expr ),*  ) => {
        [$(
            BcryptTest {
                name: $name,
                cost: 5,
                salt: include_bytes!(concat!("data/", $name, ".salt.bin")),
                input: include_bytes!(concat!("data/", $name, ".input.bin")),
                output: include_bytes!(concat!("data/", $name, ".output.bin")),
            },
        )*]
    };
}

// These are $2y$ versions of the test vectors. $2x$ is broken and $2a$ does
// weird bit-twiddling when it encounters a 0xFF byte.
const OPENWALL_TESTS: [BcryptTest; 13] = get_tests!(
    "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13");

#[test]
fn test_openwall_test_vectors() {
    let mut buf = [0u8; 24];
    for test in OPENWALL_TESTS.iter() {
        bcrypt(test.cost, &test.salt[..], &test.input[..], &mut buf[..]);
        assert!(&buf[..23] == test.output);
    }
}