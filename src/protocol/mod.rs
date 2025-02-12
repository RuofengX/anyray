pub mod auth;
pub mod command;
pub mod data;
pub mod remix;

use chrono::Local;
use hmac::{Mac, SimpleHmac};
use rand::Rng;
use serde_derive::{Deserialize, Serialize};
use sha2::Sha256;
use std::array;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
pub struct Officer {
    ticket: Ticket,
}
impl Officer {
    pub fn new(ticket: Ticket) -> Self {
        Self { ticket }
    }
    pub fn random() -> Self {
        let ticket = Ticket::random();
        Self { ticket }
    }

    pub fn ticket(&self, channel: &'static str) -> Ticket {
        self.ticket_with_time(Timecode::now(), channel)
    }

    pub fn verify_recent_ticket(&self, key: &Ticket, channel: &'static str) -> bool {
        Timecode::now()
            .iter_recent()
            .map(|t| self.ticket_with_time(t, channel))
            .any(|x| key.eq(&x))
    }

    pub fn ticket_recent<'s>(&'s self, channel: &'static str) -> impl Iterator<Item = Ticket> + 's {
        Timecode::now()
            .iter_recent()
            .map(move |t| self.ticket_with_time(t, channel))
    }

    fn ticket_with_time(&self, time: Timecode, channel: &'static str) -> Ticket {
        let mut mac = SimpleHmac::<Sha256>::new_from_slice(self.ticket.as_ref()).unwrap();
        mac.update(&time.into_bytes());
        mac.update(channel.as_bytes());
        let hash = mac.finalize_reset().into_bytes().into();
        Ticket::from_bytes(hash)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ticket([u8; 32]);
impl Ticket {
    pub fn from_bytes(value: [u8; 32]) -> Self {
        Self(value)
    }
    pub fn random() -> Self {
        let mut rng = rand::rng();
        let data = array::from_fn(|_| rng.random());
        Ticket(data)
    }
}
impl AsRef<[u8]> for Ticket {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
impl From<[u8; 32]> for Ticket {
    fn from(value: [u8; 32]) -> Self {
        Ticket(value)
    }
}
impl Into<[u8; 32]> for Ticket {
    fn into(self) -> [u8; 32] {
        self.0
    }
}

pub trait Certified: AsRef<Ticket> {
    fn verify_recent(&self, user: &Officer, channel: &'static str) -> bool {
        user.verify_recent_ticket(self.as_ref(), channel)
    }
}

impl<T: AsRef<Ticket>> Certified for T {}
