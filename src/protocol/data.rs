use bytes::{Buf, BufMut, Bytes, BytesMut};
use serde_derive::{Deserialize, Serialize};

use super::User;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Data<'d>(&'d [u8]);
impl<'d> Data<'d> {
    pub fn new(data: &'d [u8]) -> Self {
        Self(data)
    }
    pub fn as_slice(&self) -> &[u8] {
        self.0
    }
    pub fn copy_to_bytes(&self) -> Bytes {
        Bytes::copy_from_slice(self.0)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct DataUser {
    user: User,
}

impl DataUser {
    pub fn new(user: User) -> Self {
        Self { user }
    }

    fn key(&self) -> [u8; 32] {
        self.user.ticket("data")
    }
    fn key_recent<'s>(&'s self) -> impl Iterator<Item = [u8; 32]> + 's {
        self.user.ticket_recent("data")
    }
}

#[cfg(test)]
mod test {
    use std::iter::repeat;

    use rand::Rng;

    use super::*;
    #[test]
    fn test_crypt() {}
}
