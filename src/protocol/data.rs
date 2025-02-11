use bytes::{Buf, Bytes};
use serde_derive::{Deserialize, Serialize};
use serde_encrypt::{
    serialize::impls::BincodeSerializer, shared_key::SharedKey, traits::SerdeEncryptSharedKey,
    AsSharedKey, EncryptedMessage,
};

use super::User;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Data(Bytes);
impl Data {
    pub fn new(data: Bytes) -> Self {
        Self(data)
    }
    pub fn from_slice(data: &[u8]) -> Self {
        Self(Bytes::copy_from_slice(data))
    }
    pub fn into_bytes(self) -> Bytes {
        self.0
    }
}

impl SerdeEncryptSharedKey for Data {
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
        let data = Data::from_slice(data);
        let key = self.key();
        data.encrypt(&key).unwrap().serialize().into()
    }

    pub fn decrypt_parted(&self, data: &[u8]) -> Option<Bytes> {
        let msg = EncryptedMessage::deserialize(data.to_vec()).ok()?;
        self.key_recent()
            .flat_map(|key| Data::decrypt_owned(&msg, &key).ok())
            .map(|x| x.into_bytes())
            .next()
    }

    pub fn crypt<'s>(&'s self, data: &'s [u8]) -> impl Iterator<Item = Bytes> + 's {
        data.chunks(1000).map(|chunk| self.encrypt_parted(chunk))
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
