// Copyright (c) Microsoft. All rights reserved.
use crate::error::{Error, ErrorKind};
use edgelet_core::crypto::KeyStore;
use edgelet_core::{AuthId, WorkloadConfig};
use edgelet_http::route::{Handler, Parameters};
use edgelet_http::Error as HttpError;
use failure::ResultExt;
use futures::{future, Future};
use hyper::header::{CONTENT_LENGTH, CONTENT_TYPE};
use hyper::{Body, Request, Response, StatusCode};

pub struct SignHandler<K>
where
    K: 'static + KeyStore + Clone,
{
    key_store: K,
}

impl<K> SignHandler<K>
where
    K: 'static + KeyStore + Clone,
{
    pub fn new(key_store: K) -> Self {
        SignHandler { key_store }
    }
}

impl<K> Handler<Parameters> for SignHandler<K>
where
    K: 'static + KeyStore + Clone + Send,
{
    fn handle(
        &self,
        req: Request<Body>,
        params: Parameters,
    ) -> Box<dyn Future<Item = Response<Body>, Error = HttpError> + Send> {
        let key_store = self.key_store.clone();

        let body = req
            .extensions()
            .get::<AuthId>()
            .map_or_else(
                || "AuthId expected".to_string(),
                |auth_id| format!("auth = {}", auth_id),
            )
            .into();

        let response = Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "application/json")
            .header(CONTENT_LENGTH, "0")
            .body(body)
            .unwrap();

        Box::new(future::ok(response))
    }
}
