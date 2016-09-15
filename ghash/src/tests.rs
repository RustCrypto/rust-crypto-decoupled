use super::Ghash;

struct Test {
    pub name: &'static str,
    pub h: &'static [u8],
    pub c: &'static [u8],
    pub a: &'static [u8],
    pub out: &'static [u8],
}

macro_rules! get_tests {
    ( $( $name:expr ),*  ) => {
        [$(
            Test{
                name: $name,
                h: include_bytes!(concat!("data/", $name, ".h.bin")),
                a: include_bytes!(concat!("data/", $name, ".a.bin")),
                c: include_bytes!(concat!("data/", $name, ".c.bin")),
                out: include_bytes!(concat!("data/", $name, ".out.bin")),
            },
        )*]
    };
}

// Test cases from:
// <http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf>
const TESTS: [Test; 18] = get_tests!(
    "1", "2", "3", "4", "5", "6", "7", "8", "9",
    "10", "11", "12", "13", "14", "15", "16", "17", "18");

#[test]
fn ghash() {
    for t in TESTS.iter() {
        let res = Ghash::new(t.h).input_a(t.a).input_c(t.c).result();
        assert_eq!(res, t.out);
    }
}

#[test]
fn ghash_split() {
    for t in TESTS.iter() {
        let ghash = Ghash::new(t.h);
        let (a1, a2) = t.a.split_at(t.a.len() / 2);
        let (c1, c2) = t.c.split_at(t.c.len() / 2);
        let res = ghash.input_a(a1).input_a(a2).input_c(c1).input_c(c2).result();
        assert_eq!(&res[..], t.out);
    }
}