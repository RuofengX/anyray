use std::array;

use hmac::{Mac, SimpleHmac};
use rand::Rng;
use sha2::Sha256;

use super::{Timecode, Officer};

#[derive(Debug, Clone, Copy)]
pub struct AuthUser {
    user: Officer,
}
impl AuthUser {
    pub fn new(user: Officer) -> Self {
        Self { user }
    }

    pub fn auth(&self) -> [u8; 32] {
        self.user.ticket("auth")
    }
    pub fn verify_auth(&self, data: &[u8; 32]) -> bool {
        self.user
            .ticket_recent("auth")
            .any(|ticket| &ticket == data)
    }
}

#[cfg(test)]
mod test {
    use std::time::Duration;

    use chrono::Local;

    use crate::protocol::Officer;

    use super::super::Remix;
    use super::AuthUser;

    #[test]
    fn test_auth_loop() {
        (0..100000).for_each(|_| {
            test_auth();
        });
    }

    #[test]
    fn test_auth() {
        let user = AuthUser::new(Officer::random());

        let hash = user.auth();
        let mix = Remix::from_hash(&hash);

        // assert 1: test auth hash function
        assert_eq!(mix.get_hash(), Some(hash));

        let payload_on_wire = mix.into_bytes();

        let mix2 = Remix::new(payload_on_wire.clone());

        // assert 2: auth2 and auth are totally same
        assert_eq!(mix2, mix);

        // assert 3: test auth to bytes and from bytes function
        let hash2 = mix2.get_hash();
        assert_eq!(hash2, Some(hash));
        let hash2 = hash2.unwrap();

        // assert 4: test hash verify function
        user.verify_auth(&hash);
        user.verify_auth(&hash2);
    }

    #[test]
    fn test_timeout_failure() {
        let start_ts = Local::now().to_utc().timestamp();
        let user = AuthUser::new(Officer::random());
        let hash = user.auth();

        // assert: test timeout failure function
        loop {
            let ts = Local::now().to_utc().timestamp();
            if ts - start_ts < 10 {
                if ts - start_ts <= 5 {
                    assert!(user.verify_auth(&hash));
                } else {
                    assert!(!user.verify_auth(&hash));
                }
                std::thread::sleep(Duration::from_millis(1));
            } else {
                break;
            }
        }
    }
}
