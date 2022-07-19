use core::future::Future;

use crate::Vault;

struct MxId<'a>(&'a str, &'a str);

enum MxCredentials<'a> {
    IdAndPassword(MxId<'a>, &'a str),
    IdAndToken(MxId<'a>, &'a str),
}

struct MatrixS4 {
    storage: ssss::Storage,
}

impl<'a> Vault for &'a MatrixS4 {
    type Credentials = MxCredentials<'a>;
    type AuthDone = Foo;
    type Error = Error;

    fn unlock(&mut self, _c: impl Into<Self::Credentials>) -> Self::AuthDone {
        Foo
    }

    fn get_root(&self) -> Option<&crate::RootAccount> {
        None
    }
}

enum Error {}

struct Foo;

impl Future for Foo {
    type Output = Result<(), Error>;

    fn poll(
        self: core::pin::Pin<&mut Self>,
        _cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Self::Output> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn foo() {
        panic!("X");
    }
}

mod ssss {
    type AccessToken = [u8; 0];

    pub(super) struct Storage {
        token: AccessToken,
    }

    impl Storage {
        fn new(token: &str) -> Self {
            let token = token.as_bytes();
            Storage { token }
        }
    }
}
