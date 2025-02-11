use bytes::{Buf, BufMut, Bytes, BytesMut};
use serde_derive::{Deserialize, Serialize};
use serde_encrypt::{
    serialize::{impls::BincodeSerializer, TypedSerialized},
    shared_key::SharedKey,
    traits::SerdeEncryptSharedKey,
    AsSharedKey, EncryptedMessage,
};

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

impl<'d> SerdeEncryptSharedKey for Data<'d> {
    type S = BincodeSerializer<Self>;
}

#[derive(Debug, Clone, Copy)]
pub struct DataUser {
    user: User,
}

impl DataUser {
    pub fn new(user: User) -> Self {
        Self { user }
    }

    pub fn encrypt_parted(&self, data: &[u8]) -> Bytes {
        let data = Data::new(data);
        let key = self.key();
        data.encrypt(&key).unwrap().serialize().into()
    }

    pub fn decrypt_parted(&self, data: &[u8]) -> Option<Bytes> {
        todo!()
        let msg = EncryptedMessage::deserialize(data.to_vec()).ok()?;
        self.key_recent()
            .flat_map(|key| {
                let decrypted = Data::decrypt_ref(&msg, &key).ok()?;
                let data = decrypted.deserialize().ok()?;
                Some(data.copy_to_bytes())
            })
            .next()
    }

    pub fn crypt<'s>(&'s self, data: &'s [u8]) -> impl Iterator<Item = Bytes> + 's {
        data
        // split into small chunks
        // p = 0.0013
        .chunk_by(|&a, &b|a == b * 3)
        // encrypt each chunk
        .map(|chunk| self.encrypt_parted(chunk))
        // attach size metadata
        .map(|crypt_chunk|{
            let mut super_chunk = BytesMut::new();
            super_chunk.put_u64(crypt_chunk.len() as u64);
            super_chunk.put(crypt_chunk);
            super_chunk.freeze()
        })
    }

    pub fn decrypt<'s>(&'s self, data: &'s [u8]) -> impl Iterator<Item = Bytes> + 's {
        data.chunks(1000)
            .map(|chunk| self.decrypt_parted(chunk))
            .fuse() // stream should stop when any erro occurs
            .flatten()
    }

    fn key(&self) -> SharedKey {
        let ticket = self.user.ticket("data");
        SharedKey::from_array(ticket)
    }
    fn key_recent<'s>(&'s self) -> impl Iterator<Item = SharedKey> + 's {
        self.user
            .ticket_recent("data")
            .map(|ticket| SharedKey::from_array(ticket))
    }
}

#[cfg(test)]
mod test {
    use std::iter::repeat;

    use rand::Rng;

    use super::*;
    #[test]
    fn test_crypt() {
        let user = DataUser::new(User::random());

        let rng = rand::rng();
        let data: Vec<u8> = Vec::from_iter(repeat(100_000_000).map(|_|rng.random()));

        let on_wire: Vec<Bytes> = user.crypt(&data).collect();

        let decrypted_data = user.decrypt(on_wire);
    }
}
