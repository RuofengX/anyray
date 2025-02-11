pub struct Remix<T: Iterator<Item = u8>> {
    data: T,
    cursor: usize,
}
impl <T:Iterator<Item = u8>>Remix<T>{
    pub fn from_iter(data: T) -> Self{
        Remix { data, cursor: 0 }
    }
}

impl<T: Iterator<Item = u8>> Iterator for Remix<T> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        self.data.
    }
}
