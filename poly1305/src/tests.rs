use super::Poly1305;
use crypto_mac::Mac;

pub struct Test {
    pub name: &'static str,
    pub key: &'static [u8],
    pub msg: &'static [u8],
    pub out: &'static [u8],
}

macro_rules! get_test {
    ($name:expr) => {
            Test{
                name: $name,
                key: include_bytes!(concat!("data/", $name, ".key.bin")),
                msg: include_bytes!(concat!("data/", $name, ".msg.bin")),
                out: include_bytes!(concat!("data/", $name, ".out.bin")),
            }
    };
}

fn poly1305(key: &[u8], msg: &[u8], mac: &mut [u8]) {
    let mut poly = Poly1305::new(key);
    poly.input(msg);
    poly.raw_result(mac);
}

#[test]
fn poly1305_nacl_vector() {
    let test = get_test!("nacl_vector");

    let mut mac = [0u8; 16];
    poly1305(test.key, test.msg, &mut mac);
    assert_eq!(&mac[..], &test.out[..]);

    let mut poly = Poly1305::new(&test.key);
    poly.input(&test.msg[0..32]);
    poly.input(&test.msg[32..96]);
    poly.input(&test.msg[96..112]);
    poly.input(&test.msg[112..120]);
    poly.input(&test.msg[120..124]);
    poly.input(&test.msg[124..126]);
    poly.input(&test.msg[126..127]);
    poly.input(&test.msg[127..128]);
    poly.input(&test.msg[128..129]);
    poly.input(&test.msg[129..130]);
    poly.input(&test.msg[130..131]);
    poly.raw_result(&mut mac);
    assert_eq!(&mac[..], &test.out[..]);
}

#[test]
fn poly1305_donna_self_test() {
    let test = get_test!("wrap");

    let mut mac = [0u8; 16];
    poly1305(test.key, test.msg, &mut mac);
    assert_eq!(&mac[..], &test.out[..]);

    let total_key = include_bytes!("data/total.key.bin");

    let total_mac = include_bytes!("data/total.out.bin");;

    let mut tpoly = Poly1305::new(total_key);
    for i in 0..256 {
        let key = [i as u8; 32];
        let msg = [i as u8; 256];
        let mut mac = [0u8; 16];
        poly1305(&key[..], &msg[0..i], &mut mac);
        tpoly.input(&mac);
    }
    tpoly.raw_result(&mut mac);
    assert_eq!(&mac[..], &total_mac[..]);
}

#[test]
fn poly1305_tls_vectors() {
    // from http://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-04
    let test = get_test!("tls_vector_1");
    let mut mac = [0u8; 16];
    poly1305(test.key, test.msg, &mut mac);
    assert_eq!(&mac[..], &test.out[..]);

    let test = get_test!("tls_vector_2");
    poly1305(test.key, test.msg, &mut mac);
    assert_eq!(&mac[..], &test.out[..]);
}


