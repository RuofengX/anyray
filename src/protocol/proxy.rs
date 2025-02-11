use std::net::{Ipv4Addr, Ipv6Addr};

use bytes::Bytes;
use serde::{Deserialize, Serialize};
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
    data: Bytes,
}

pub struct ProxyUser {
    user: User,
}

impl ProxyUser {
    pub fn new(user: User) -> Self {
        Self { user }
    }

    pub fn request(&self, ty: Ty, addr: Addr, port: u16, data: &Bytes) -> Vec<u8> {
        let req = Request {
            ty,
            addr,
            port,
            data: data.clone(),
        };
        req.encrypt(&self.key()).unwrap().serialize()
    }

    pub fn verify_request(&self, data: Vec<u8>) -> Option<Request> {
        let msg = EncryptedMessage::deserialize(data).ok()?;
        self.key_recent()
            .flat_map(|key| Request::decrypt_ref(&msg, &key).ok())
            .flat_map(|i| i.deserialize().ok())
            .next()
    }

    fn key(&self) -> SharedKey {
        let ticket = self.user.ticket("proxy");
        SharedKey::from_array(ticket)
    }
    fn key_recent<'s>(&'s self) -> impl Iterator<Item = SharedKey> + 's {
        self.user
            .ticket_recent("proxy")
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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_request() {
        let user = ProxyUser::new(User::random());
        let req = user.request(
            Ty::TCP,
            Addr::Domain("http://github.com".to_string()),
            443,
            &Bytes::from_static("GET".as_bytes()),
        );
        println!("{:?}", req);

        assert_eq!(
            user.verify_request(req),
            Some(Request {
                ty: Ty::TCP,
                addr: Addr::Domain("http://github.com".to_string()),
                port: 443,
                data: Bytes::from_static("GET".as_bytes()),
            })
        );
    }
}
