use std::{
    array,
    io::Read,
    net::{Ipv4Addr, Ipv6Addr},
};

use rand::Rng;
use rmp_serde::from_read;
use serde_derive::{Deserialize, Serialize};

use super::{Timecode, User};

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
    #[serde(with = "serde_bytes")]
    key: [u8; 32],
    ty: Ty,
    addr: Addr,
    port: u16,
    #[serde(with = "serde_bytes")]
    padding: [u8; 32],
}
impl Request {
    pub fn new(key: [u8; 32], ty: Ty, addr: Addr, port: u16) -> Self {
        let mut rng = rand::rng();
        let padding = array::from_fn(|_| rng.random());
        Self {
            key,
            ty,
            addr,
            port,
            padding,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Response {
    #[serde(with = "serde_bytes")]
    key: [u8; 32],
    #[serde(with = "serde_bytes")]
    padding: [u8; 32],
}
impl Response {
    pub fn new(key: [u8; 32]) -> Self {
        let mut rng = rand::rng();
        let padding = array::from_fn(|_| rng.random());
        Self { key, padding }
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
        let key = self.user.ticket("proxy request");
        let req = Request::new(key, ty, addr, port);
        rmp_serde::to_vec(&req).expect("encode function never fail")
    }

    pub fn verify_request<R: Read>(&self, rd: R) -> Option<Request> {
        self.user.ticket_recent("proxy request");
        rmp_serde::from_read(rd).ok()
    }

    pub fn response(&self) -> Vec<u8> {
        let key = self.user.ticket("proxy response");
        let req = Response::new(key);
        rmp_serde::to_vec(&req).expect("encode function never fail")
    }

    pub fn verify_response(&self, data: Vec<u8>) -> Option<()> {}

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
