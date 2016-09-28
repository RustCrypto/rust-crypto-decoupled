use super::{Fe, curve25519_base};

fn gen_e(i: u32) -> [u8; 32] {
    let mut res = [0u8; 32];
    for idx in 0..32 {
        res[idx] = ((idx as u32)*(1289+i*761)) as u8 ;
    }
    res
}

#[test]
fn from_to_bytes_preserves() {
    for i in 0..50 {
        let mut e = gen_e(i);
        e[0] &= 248;
        e[31] &= 127;
        e[31] |= 64;
        let fe = Fe::from_bytes(e.as_ref());
        let e_preserved = fe.to_bytes();
        assert_eq!(e, e_preserved);
    }
}

#[test]
fn swap_test() {
    let mut f = Fe([10,20,30,40,50,60,70,80,90,100]);
    let mut g = Fe([11,21,31,41,51,61,71,81,91,101]);
    let f_initial = f;
    let g_initial = g;
    f.maybe_swap_with(&mut g, 0);
    assert!(f == f_initial);
    assert!(g == g_initial);

    f.maybe_swap_with(&mut g, 1);
    assert!(f == g_initial);
    assert!(g == f_initial);
}

struct CurveGen {
    which: u32
}
impl CurveGen {
    fn new(seed: u32) -> CurveGen {
        CurveGen{which: seed}
    }
}
impl Iterator for CurveGen {
    type Item = Fe;

    fn next(&mut self) -> Option<Fe> {
        let mut e = gen_e(self.which);
        e[0] &= 248;
        e[31] &= 127;
        e[31] |= 64;
        Some(Fe::from_bytes(e.as_ref()))
    }
}

#[test]
fn mul_commutes() {
   for (x,y) in CurveGen::new(1).zip(CurveGen::new(2)).take(40) {
      assert!(x*y == y*x);
   };
}

#[test]
fn mul_assoc() {
   for (x,(y,z)) in CurveGen::new(1).zip(CurveGen::new(2).zip(CurveGen::new(3))).take(40) {
      assert!((x*y)*z == x*(y*z));
   };
}

#[test]
fn invert_inverts() {
   for x in CurveGen::new(1).take(40) {
      assert!(x.invert().invert() == x);
   };
}

#[test]
fn square_by_mul() {
   for x in CurveGen::new(1).take(40) {
      assert!(x*x == x.square());
   };
}

#[test]
fn base_example() {
    let sk : [u8; 32] = [
        0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1,
        0x72, 0x51, 0xb2, 0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0,
        0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a ];
    let pk = curve25519_base(sk.as_ref());
    let correct : [u8; 32] = [
         0x85,0x20,0xf0,0x09,0x89,0x30,0xa7,0x54
        ,0x74,0x8b,0x7d,0xdc,0xb4,0x3e,0xf7,0x5a
        ,0x0d,0xbf,0x3a,0x0d,0x26,0x38,0x1a,0xf4
        ,0xeb,0xa4,0xa9,0x8e,0xaa,0x9b,0x4e,0x6a ];
    assert_eq!(pk, correct);
}
