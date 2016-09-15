#![cfg(feature = "std")]
// TODO: Wait for `core::io` and remove `std` constraint
use std::io;
use super::{write_u32_le, write_u32_be, write_u64_le, write_u64_be};

/// An extension trait to implement a few useful serialization
/// methods on types that implement Write
pub trait WriteExt {
    fn write_u8(&mut self, val: u8) -> io::Result<()>;
    fn write_u32_le(&mut self, val: u32) -> io::Result<()>;
    fn write_u32_be(&mut self, val: u32) -> io::Result<()>;
    fn write_u64_le(&mut self, val: u64) -> io::Result<()>;
    fn write_u64_be(&mut self, val: u64) -> io::Result<()>;
}

impl<T> WriteExt for T
    where T: io::Write
{
    fn write_u8(&mut self, val: u8) -> io::Result<()> {
        let buff = [val];
        self.write_all(&buff)
    }
    fn write_u32_le(&mut self, val: u32) -> io::Result<()> {
        let mut buff = [0u8; 4];
        write_u32_le(&mut buff, val);
        self.write_all(&buff)
    }
    fn write_u32_be(&mut self, val: u32) -> io::Result<()> {
        let mut buff = [0u8; 4];
        write_u32_be(&mut buff, val);
        self.write_all(&buff)
    }
    fn write_u64_le(&mut self, val: u64) -> io::Result<()> {
        let mut buff = [0u8; 8];
        write_u64_le(&mut buff, val);
        self.write_all(&buff)
    }
    fn write_u64_be(&mut self, val: u64) -> io::Result<()> {
        let mut buff = [0u8; 8];
        write_u64_be(&mut buff, val);
        self.write_all(&buff)
    }
}
