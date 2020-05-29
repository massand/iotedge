use crate::error::{Error, ErrorKind};
use edgelet_core::{Authenticator, KeyStore, ModuleRuntime, Policy, WorkloadConfig};
use edgelet_http::authentication::Authentication;
use edgelet_http::authorization::Authorization;
use edgelet_http::route::{Builder, RegexRecognizer, Router, RouterService};
use edgelet_http::{router, Version};
use failure::{Compat, Fail, ResultExt};
use futures::{Future, future};
use hyper::service::{NewService, Service};

use self::identity::IdentityHandler;
use hyper::{Body, Request, Response};

mod error;
mod identity;

#[derive(Clone)]
pub struct IdentityService {
    inner: RouterService<RegexRecognizer>,
}

impl IdentityService {
    pub fn new<M, W>(runtime: &M, config: W) -> impl Future<Item = Self, Error = Error>
    where
        M: ModuleRuntime + Authenticator<Request = Request<Body>> + Clone + Send + Sync + 'static,
        W: WorkloadConfig + Clone + Send + Sync + 'static,
        <M::AuthenticateFuture as Future>::Error: Fail,
    {
        let router = router!(
            get   Version2018_06_28 runtime Policy::Anonymous => "/identities/identity" => IdentityHandler::new(config.clone()),
        );

        router.new_service().then(|inner| {
            let inner = inner.context(ErrorKind::StartService)?;
            Ok(IdentityService { inner })
        })
    }
}

impl Service for IdentityService {
    type ReqBody = <RouterService<RegexRecognizer> as Service>::ReqBody;
    type ResBody = <RouterService<RegexRecognizer> as Service>::ResBody;
    type Error = <RouterService<RegexRecognizer> as Service>::Error;
    type Future = <RouterService<RegexRecognizer> as Service>::Future;

    fn call(&mut self, req: Request<Self::ReqBody>) -> Self::Future { self.inner.call(req)}
}

impl NewService for IdentityService {
    type ReqBody = <Self::Service as Service>::ReqBody;
    type ResBody = <Self::Service as Service>::ResBody;
    type Error = <Self::Service as Service>::Error;
    type Service = Self;
    type Future = future::FutureResult<Self::Service, Self::InitError>;
    type InitError = Compat<Error>;

    fn new_service(&self) -> Self::Future { future::ok(self.clone())}
}