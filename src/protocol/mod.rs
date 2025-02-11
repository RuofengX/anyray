pub mod auth;
pub mod data;
pub mod proxy;

use chrono::Local;
use serde_derive::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Timecode(i64);
impl Timecode {
    pub const RANGE: u8 = 5;
    pub fn now() -> Self {
        let now = Local::now().to_utc();
        Self(now.timestamp())
    }
    pub fn iter_recent(&self) -> impl Iterator<Item = Self> {
        (self.0 - Self::RANGE as i64..=self.0 + Self::RANGE as i64).map(|t| Self(t))
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
