use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

use super::Ticket;

pub struct RandomChunk<'s, const MIN_L: usize, const MAX_L: usize> {
    data: &'s [u8],
    cursor: usize,
}
impl<'s, const MIN_L: usize, const MAX_L: usize> RandomChunk<'s, MIN_L, MAX_L> {
    pub fn new(data: &'s [u8]) -> Self {
        Self { data, cursor: 0 }
    }
}

impl<'s, const MIN_L: usize, const MAX_L: usize> Iterator for RandomChunk<'s, MIN_L, MAX_L> {
    type Item = &'s [u8];

    fn next(&mut self) -> Option<Self::Item> {
        let byte_left = self.data.len() - self.cursor;
        if byte_left == 0 {
            return None;
        }

        let mut rng = rand::rng();
        let mut chunk_size: usize = rng.random_range(MIN_L..=MAX_L);
        if chunk_size > byte_left {
            chunk_size = byte_left;
        }

        let chunk_start = self.cursor;
        let chunk_end = self.cursor + chunk_size;

        self.cursor += chunk_size;
        Some(&self.data[chunk_start..chunk_end])
    }
}

pub struct Remix<'d> {
    chacha: ChaCha20Rng,
    data: std::slice::Iter<'d, u8>,
}
impl<'d> Remix<'d> {
    pub fn new(ticket: Ticket, data: &'d [u8]) -> Self {
        let chacha = ChaCha20Rng::from_seed(*ticket.as_ref());
        let data = data.iter();
        Remix { chacha, data }
    }
}
impl<'d> Iterator for Remix<'d> {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        let raw = self.data.next()?;
        let chacha_char: u8 = self.chacha.random();
        // if:
        //   a ^ b == c
        // then:
        //    a ^ c == b
        //    and b ^ c == a
        Some(raw ^ chacha_char)
    }
}

#[cfg(test)]
mod test {
    use crate::protocol::User;

    use super::*;
    use std::array;

    #[test]
    fn test_random_chunk() {
        let data: [u8; 256] = array::from_fn(|n| n as u8);
        println!("{:?}", data);
        let rc = RandomChunk::<254, 254>::new(&data);
        for i in rc {
            println!("{:?}", i);
        }
    }

    #[test]
    fn test_remix() {
        let mut rng = rand::rng();
        let data: [u8; 1024] = array::from_fn(|_| rng.random());
        let data = data.to_vec();

        let user = User::random();
        let ticket = user.ticket();

        let remix = Remix::new(ticket, &data);
        let remixed: Vec<u8> = remix.collect();
        assert_ne!(remixed, data);

        let remix_remix = Remix::new(ticket, &remixed);
        let remix_remixed: Vec<u8> = remix_remix.collect();

        assert_eq!(remix_remixed, data);
    }
}
