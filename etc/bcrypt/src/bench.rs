use test::Bencher;
use super::bcrypt;

#[bench]
pub fn bcrypt_16_5(bh: & mut Bencher) {
    let pass = [0u8; 16];
    let salt = [0u8; 16];
    let mut out  = [0u8; 24];
    bh.iter( || { bcrypt(5, &salt, &pass, &mut out); });
}