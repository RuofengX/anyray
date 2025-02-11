use hmac::{Mac, SimpleHmac};
use rand::{Rng, RngCore};
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
    pub fn hash_verify_recent(&self, hash: &[u8; 32]) -> bool {
        Timecode::now()
            .iter_recent()
            .map(|t| self.hash_with_time(t))
            .any(|x| hash.eq(x.as_ref()))
    }

    fn hash_with_time(&self, time: Timecode) -> [u8; 32] {
        let mut mac = SimpleHmac::<Sha256>::new_from_slice(&self.key).unwrap();
        mac.update(&time.into_bytes());
        let hash = mac.finalize_reset().into_bytes();
        hash.into()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Auth {
    data: [u8; 256],
}
impl Into<[u8; 256]> for Auth {
    fn into(self) -> [u8; 256] {
        self.data
    }
}
impl Auth {
    pub fn new(data: [u8; 256]) -> Self {
        Self { data }
    }

    pub fn from_hash(hash: &[u8; 32]) -> Self {
        let mut rng = rand::rng();

        let mut data = [0u8; 256];
        rng.fill_bytes(&mut data);

        let start_at = rng.random_range(1..u8::MAX - 32 - 1) as usize;

        data[0] = start_at as u8;
        data.iter_mut()
            .skip(start_at)
            .take(32)
            .enumerate()
            .for_each(|(i, b)| *b = hash[i]);

        Self { data }
    }
    pub fn get_hash(&self) -> Option<[u8; 32]> {
        let start_at = *self.data.first()? as usize;
        let end_at = start_at + 32;
        let minimum_len = end_at + 1;
        if self.data.len() < minimum_len {
            return None;
        }
        let ret = self.data[start_at..end_at].try_into().unwrap();
        Some(ret)
    }
    pub fn into_bytes(&self) -> [u8; 256] {
        self.data
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
        use std::array;

        use super::Auth;
        use super::User;

        let user = User::new(array::from_fn(|x| x as u8));

        let hash = user.hash_now();
        let auth = Auth::from_hash(&hash);

        // assert 1: test auth hash function
        assert_eq!(auth.get_hash(), Some(hash));

        let payload_on_wire = auth.into_bytes();

        let auth2 = Auth::new(payload_on_wire.clone());

        // assert 2: auth2 and auth are totally same
        assert_eq!(auth2, auth);

        // assert 3: test auth to bytes and from bytes function
        let hash2 = auth2.get_hash();
        assert_eq!(hash2, Some(hash));
        let hash2 = hash2.unwrap();

        // assert 4: test hash verify function
        user.hash_verify_recent(&hash);
        user.hash_verify_recent(&hash2);
    }

    #[test]
    fn test_timeout_failure() {
        use std::array;
        use std::time::Duration;

        use super::*;

        let user = User::new(array::from_fn(|x| x as u8));
        let hash = user.hash_now();

        // assert 5: test timeout failure function
        std::thread::sleep(Duration::from_secs(1));
        assert!(user.hash_verify_recent(&hash));
        std::thread::sleep(Duration::from_secs(1));
        assert!(user.hash_verify_recent(&hash));
        std::thread::sleep(Duration::from_secs(1));
        assert!(user.hash_verify_recent(&hash));
        std::thread::sleep(Duration::from_secs(1));
        assert!(user.hash_verify_recent(&hash));
        std::thread::sleep(Duration::from_secs(1));
        assert!(user.hash_verify_recent(&hash));

        std::thread::sleep(Duration::from_secs(1));
        assert!(!user.hash_verify_recent(&hash));
    }
}
