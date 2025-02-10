use std::iter::repeat;

use bytes::{Buf, Bytes, BytesMut};
use chrono::{DateTime, Local, Timelike, Utc};
use hmac::{Mac, SimpleHmac};
use rand::{Rng, RngCore};
use serde_derive::{Deserialize, Serialize};
use serde_encrypt::encrypt;
use sha2::Sha256;

use super::Timecode;

#[derive(Debug, Clone, Copy)]
pub struct User {
    key: [u8; 32],
}
impl User {
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    pub fn hash_now(&self) -> [u8; 32] {
        self.hash_with_time(Timecode::now())
    }

    /// assert that encrypt_hash is 32 bytes in length
    pub fn hash_verify_recent(&self, encrypt_hash: Bytes) -> bool {
        Timecode::now()
            .iter_recent()
            .map(|t| self.hash_with_time(t))
            .any(|x| encrypt_hash.eq(x.as_ref()))
    }

    fn hash_with_time(&self, time: Timecode) -> [u8; 32] {
        let mut mac = SimpleHmac::<Sha256>::new_from_slice(&self.key).unwrap();
        mac.update(&time.into_bytes());
        let result = mac.finalize_reset().into_bytes();
        result.into()
    }
}

pub struct Auth {
    data: Bytes,
}
impl Into<Bytes> for Auth {
    fn into(self) -> Bytes {
        self.data
    }
}
impl Auth {
    pub fn new(data: Bytes) -> Self {
        Self { data }
    }

    pub fn from_hash(hash: [u8; 32]) -> Self {
        let mut rng = rand::rng();

        let mut buf = BytesMut::from_iter(rng.clone().random_iter::<u8>().take(u8::MAX as usize));

        let start_at = rng.random_range(1..u8::MAX - 32 - 1) as usize;

        buf[0] = start_at as u8;
        buf.iter_mut()
            .skip(start_at)
            .take(32)
            .enumerate()
            .for_each(|(i, b)| *b = hash[i]);

        let data = buf.freeze();
        Self { data }
    }
    pub fn get_hash(&self) -> Option<Bytes> {
        let start_at = *self.data.first()? as usize;
        let end_at = start_at + 32;
        let minimum_len = end_at + 1;
        if self.data.len() < minimum_len {
            return None;
        }
        Some(self.data.slice(start_at..end_at))
    }
}

mod test {

    #[test]
    fn test_auth_loop() {
        (0..100000).for_each(|_| {
            test_auth();
        });
    }

    #[test]
    fn test_auth() {
        use bytes::Bytes;

        use super::Auth;
        use super::User;

        let user = User::new([0; 32]);
        let data = user.hash_now();

        let auth = Auth::from_hash(data);
        let payload: Bytes = auth.into();

        let auth2 = Auth::new(payload.clone());

        // println!("{:?}", payload[0]);
        // println!("{:?}", payload);
        assert_eq!(auth2.get_hash(), Some(Bytes::copy_from_slice(&data)));
    }
}
