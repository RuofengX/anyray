use std::{
    array,
    net::{Ipv4Addr, Ipv6Addr},
};

use rand::Rng;
use serde_derive::{Deserialize, Serialize};
use serde_encrypt::{
    serialize::{impls::BincodeSerializer, TypedSerialized},
    shared_key::SharedKey,
    traits::SerdeEncryptSharedKey,
    AsSharedKey, EncryptedMessage,
};

use super::User;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Addr {
    IPv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    Domain(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Ty {
    TCP,
    UDP,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    ty: Ty,
    addr: Addr,
    port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Response {
    padding: [u8; 32],
}
impl Response {
    pub fn new() -> Self {
        let mut rng = rand::rng();
        let padding = array::from_fn(|_| rng.random());
        Self { padding }
    }
}

pub struct ProxyUser {
    user: User,
}

impl ProxyUser {
    pub fn new(user: User) -> Self {
        Self { user }
    }

    pub fn request(&self, ty: Ty, addr: Addr, port: u16) -> Vec<u8> {
        let req = Request { ty, addr, port };
        req.encrypt(&self.key()).unwrap().serialize()
    }

    pub fn verify_request(&self, data: Vec<u8>) -> Option<Request> {
        let msg = EncryptedMessage::deserialize(data).ok()?;
        self.key_recent()
            .flat_map(|key| Request::decrypt_owned(&msg, &key).ok())
            .next()
    }

    pub fn response(&self) -> Vec<u8> {
        let resp = Response::new();
        resp.encrypt(&self.key()).unwrap().serialize()
    }

    pub fn verify_response(&self, data: Vec<u8>) -> Option<()> {
        let msg = EncryptedMessage::deserialize(data).ok()?;
        self.key_recent()
            .flat_map(|key| Response::decrypt_ref(&msg, &key).ok())
            .flat_map(|i| i.deserialize().ok())
            .next()?;
        Some(())
    }

    fn key(&self) -> SharedKey {
        let ticket = self.user.ticket("command");
        SharedKey::from_array(ticket)
    }
    fn key_recent<'s>(&'s self) -> impl Iterator<Item = SharedKey> + 's {
        self.user
            .ticket_recent("command")
            .map(|ticket| SharedKey::from_array(ticket))
    }
}

/// from [`serde_encrypt`] doc:
///
/// Currently, the following serializers are built-in.
///
///     BincodeSerializer (only std feature)
///         Best choice for std to reduce message size in most cases.
///     PostcardSerializer
///         Best choice for no_std to reduce message size in most cases.
///     CborSerializer
///         Has large message size but deals with complex serde types. See Encrypts/Decrypts complex serde types example to check kind of serde types only CborSerializer can serialize.
///         Single available choice in serde-encrypt-sgx.
///             Both bincode and postcard crates cannot compile with Rust SGX SDK
impl SerdeEncryptSharedKey for Request {
    type S = BincodeSerializer<Self>; // you can specify serializer implementation (or implement it by yourself).
}

impl SerdeEncryptSharedKey for Response {
    type S = BincodeSerializer<Self>;
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_request() {
        let user = ProxyUser::new(User::random());
        let req = user.request(Ty::TCP, Addr::Domain("http://github.com".to_string()), 443);
        println!("{:?}", req);

        assert_eq!(
            user.verify_request(req),
            Some(Request {
                ty: Ty::TCP,
                addr: Addr::Domain("http://github.com".to_string()),
                port: 443,
            })
        );
    }
}
