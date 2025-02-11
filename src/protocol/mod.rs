pub mod auth;
pub mod data;
pub mod proxy;

use chrono::Local;
use hmac::{Mac, SimpleHmac};
use rand::{Rng, RngCore};
use serde_derive::{Deserialize, Serialize};
use sha2::Sha256;
use std::array;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Timecode(i64);
impl Timecode {
    pub const RANGE: u8 = 5;
    pub fn now() -> Self {
        let now = Local::now().to_utc();
        Self(now.timestamp())
    }
    pub fn iter_recent(&self) -> impl Iterator<Item = Self> {
        (self.0 - Self::RANGE as i64..self.0 + Self::RANGE as i64).map(|t| Self(t))
    }
    pub fn into_bytes(&self) -> [u8; 8] {
        self.0.to_be_bytes()
    }
}
impl Into<[u8; 8]> for Timecode {
    fn into(self) -> [u8; 8] {
        self.0.to_be_bytes()
    }
}

#[derive(Debug, Clone, Copy)]
pub struct User {
    key: [u8; 32],
}
impl User {
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }
    pub fn random() -> Self {
        let mut rng = rand::rng();
        let key = array::from_fn(|_| rng.random());
        Self { key }
    }

    pub fn ticket(&self, channel: &'static str) -> [u8; 32] {
        self.ticket_with_time(Timecode::now(), channel)
    }

    pub fn verify_recent_ticket(&self, hash: &[u8; 32], channel: &'static str) -> bool {
        Timecode::now()
            .iter_recent()
            .map(|t| self.ticket_with_time(t, channel))
            .any(|x| hash.eq(x.as_ref()))
    }

    pub fn ticket_recent<'s>(
        &'s self,
        channel: &'static str,
    ) -> impl Iterator<Item = [u8; 32]> + 's {
        Timecode::now()
            .iter_recent()
            .map(move |t| self.ticket_with_time(t, channel))
    }

    fn ticket_with_time(&self, time: Timecode, channel: &'static str) -> [u8; 32] {
        let mut mac = SimpleHmac::<Sha256>::new_from_slice(&self.key).unwrap();
        mac.update(&time.into_bytes());
        mac.update(channel.as_bytes());
        let hash = mac.finalize_reset().into_bytes();
        hash.into()
    }


}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Remix {
    data: [u8; 256],
}
impl Into<[u8; 256]> for Remix {
    fn into(self) -> [u8; 256] {
        self.data
    }
}
impl Remix {
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
