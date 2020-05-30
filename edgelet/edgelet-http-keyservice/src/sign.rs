// Copyright (c) Microsoft. All rights reserved.
use crate::error::{Error, ErrorKind};
use edgelet_core::crypto::{KeyStore, Sign, SignatureAlgorithm};
use edgelet_core::{AuthId, KeyIdentity, Signature};
use edgelet_http::route::{Handler, Parameters};
use edgelet_http::Error as HttpError;
use failure::ResultExt;
use futures::{future, Future};
use hyper::header::{CONTENT_LENGTH, CONTENT_TYPE};
use hyper::{Body, Request, Response, StatusCode};

use crate::IntoResponse;

pub struct SignHandler<K>
where
    K: 'static + KeyStore + Clone,
    K::Key: Sign,
{
    key_store: K,
}

impl<K> SignHandler<K>
where
    K: 'static + KeyStore + Clone,
    K::Key: Sign,
{
    pub fn new(key_store: K) -> Self {
        SignHandler { key_store }
    }
}

impl<K> Handler<Parameters> for SignHandler<K>
where
    K: 'static + KeyStore + Clone + Send,
    K::Key: Sign,
{
    fn handle(
        &self,
        req: Request<Body>,
        _params: Parameters,
    ) -> Box<dyn Future<Item = Response<Body>, Error = HttpError> + Send> {
        let _key_store = self.key_store.clone();
        let device_key = _key_store.get(
            &KeyIdentity::Device, "primary")
            .unwrap();

        let message = "primary";

        let signature = device_key.sign(
            SignatureAlgorithm::HMACSHA256, &message.as_bytes())
            .map(|s| base64::encode(s.as_bytes()))
            .context(ErrorKind::GetSignature)
            .unwrap();

        let body = serde_json::to_string(&signature.as_bytes())
            .context(ErrorKind::GetSignature)
            .unwrap();

        let response = Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "application/json")
            .header(CONTENT_LENGTH, body.len().to_string().as_str())
            .body(body.into())
            .context(ErrorKind::GetSignature)
            .unwrap();

        Box::new(future::ok(response))
    }
}
