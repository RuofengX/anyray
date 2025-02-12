use rand::{rngs::ThreadRng, Rng};

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


#[cfg(test)]
mod test {
    use super::*;
    use std::array;

    #[test]
    fn test_random_chunk() {
        let data: [u8; 256] = array::from_fn(|n| n as u8);
        println!("{:?}", data);
        let rc = RandomChunk::<254, 254>::new(&data);
        for i in rc{
            println!("{:?}", i);
        }
    }
}
