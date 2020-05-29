use crate::error::{Error, ErrorKind};
use edgelet_core::{Authenticator, KeyStore, ModuleRuntime, Policy, WorkloadConfig};
use edgelet_http::authentication::Authentication;
use edgelet_http::authorization::Authorization;
use edgelet_http::route::{Builder, RegexRecognizer, Router, RouterService};
use edgelet_http::{router, Version};
use failure::{Compat, Fail, ResultExt};
use futures::{Future, future};
use hyper::service::{NewService, Service};

use self::sign::SignHandler;
use hyper::{Body, Request};

mod error;
mod sign;

#[derive(Clone)]
pub struct KeyService {
    inner: RouterService<RegexRecognizer>,
}

impl KeyService {
    pub fn new<M, W, K>(
        runtime: &M,
        config: W,
        key_store: &K,
    ) -> impl Future<Item = Self, Error = Error>
    where
        K: KeyStore + Clone + Send + Sync + 'static,
        M: ModuleRuntime + Authenticator<Request = Request<Body>> + Clone + Send + Sync + 'static,
        W: WorkloadConfig + Clone + Send + Sync + 'static,
        <M::AuthenticateFuture as Future>::Error: Fail,
    {
        let router = router!(
            get   Version2018_06_28 runtime Policy::Anonymous => "/sign" => SignHandler::new(key_store.clone()),
        );

        router.new_service().then(|inner| {
            let inner = inner.context(ErrorKind::StartService)?;
            Ok(KeyService { inner })
        })
    }
}

impl Service for KeyService {
    type ReqBody = <RouterService<RegexRecognizer> as Service>::ReqBody;
    type ResBody = <RouterService<RegexRecognizer> as Service>::ResBody;
    type Error = <RouterService<RegexRecognizer> as Service>::Error;
    type Future = <RouterService<RegexRecognizer> as Service>::Future;

    fn call(&mut self, req: Request<Self::ReqBody>) -> Self::Future { self.inner.call(req)}
}

impl NewService for KeyService {
    type ReqBody = <Self::Service as Service>::ReqBody;
    type ResBody = <Self::Service as Service>::ResBody;
    type Error = <Self::Service as Service>::Error;
    type Service = Self;
    type Future = future::FutureResult<Self::Service, Self::InitError>;
    type InitError = Compat<Error>;

    fn new_service(&self) -> Self::Future { future::ok(self.clone())}
}