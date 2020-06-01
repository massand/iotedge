// Copyright (c) Microsoft. All rights reserved.
use crate::error::{Error, ErrorKind};
use edgelet_core::crypto::{KeyStore, Sign, SignatureAlgorithm};
use edgelet_core::{KeyIdentity, Signature};
use edgelet_http::route::{Handler, Parameters};
use edgelet_http::Error as HttpError;
use failure::ResultExt;
use futures::{Future, Stream};
use hyper::header::{CONTENT_LENGTH, CONTENT_TYPE};
use hyper::{Body, Request, Response, StatusCode};

use crate::IntoResponse;
use keyservice::models::SignRequest;

pub struct SignHandler<K: KeyStore> {
    key_store: K,
}

impl<K: KeyStore> SignHandler<K> {
    pub fn new(key_store: K) -> Self {
        SignHandler { key_store }
    }
}

impl<K> Handler<Parameters> for SignHandler<K>
where
    K: 'static + KeyStore + Clone + Sync + Send,
    K::Key: Sign,
{
    fn handle(
        &self,
        req: Request<Body>,
        _params: Parameters,
    ) -> Box<dyn Future<Item = Response<Body>, Error = HttpError> + Send> {
        let key_store = self.key_store.clone();

        let response = req
            .into_body()
            .concat2()
            .then(move |b| {
                let b = b.context(ErrorKind::MalformedRequestBody)?;
                let request = serde_json::from_slice::<SignRequest>(&b)
                    .context(ErrorKind::MalformedRequestBody)?;
                let message = base64::decode(
                    request.parameters().message())
                    .context(ErrorKind::MalformedRequestBody)?;
                let key_handle = request.key_handle();
                let device_key = key_store.get(
                    &KeyIdentity::Device, key_handle)
                    .context(ErrorKind::DeviceKeyNotFound)?;
                let signature = device_key
                    .sign(SignatureAlgorithm::HMACSHA256, &message)
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
                    .with_context(|_| ErrorKind::GetSignature)?;

                Ok(response)
            })
            .or_else(|e: Error| Ok(e.into_response()));

        Box::new(response)
    }
}

#[cfg(tests)]
mod tests {
    use edgelet_core::crypto::MemoryKey;
    use crate::sign::SignHandler;
    use edgelet_http::route::{Parameters, Handler};
    use futures::{Stream, Future};
    use keyservice::models::ErrorResponse;
    use std::sync::{Arc, Mutex};
    use serde_json::ser::State;
    use edgelet_core::{KeyStore, KeyIdentity};
    use sha2::Digest;

    #[derive(Clone, Debug)]
    struct TestKeyStore {
        key: MemoryKey,
        state: Arc<Mutex<State>>,
    }

    impl TestKeyStore {
        pub fn new(key: MemoryKey) -> Self {
            TestKeyStore {
                key,
                state: Arc::new(Mutex::new(State::new())),
            }
        }
    }

    impl KeyStore for TestKeyStore {
        type Key = MemoryKey;

        fn get(&self, identity: &KeyIdentity, key_name: &str) -> Result<Self::Key, CoreError> {
            let mut state = self.state.lock().unwrap();
            {
                let state = &mut *state;
                state.last_id = match identity {
                    KeyIdentity::Device => "".to_string(),
                    KeyIdentity::Module(ref m) => m.to_string(),
                };
                state.last_key_name = key_name.to_string();
            }
            drop(state);
            Ok(self.key.clone())
        }
    }

    #[test]
    fn bad_body() {
        // arrange
        let key = MemoryKey::new("key");
        let store = TestKeyStore::new(key);
        let handler = SignHandler::new(store);

        let body = "invalid";

        let request = Request::post("http://localhost/sign")
            .body(body.into())
            .unwrap();

        // act
        let response = handler.handle(request, Parameters::new()).wait().unwrap();

        // assert
        assert_eq!(StatusCode::BAD_REQUEST, response.status());
        response
            .into_body()
            .concat2()
            .and_then(|b| {
                let error_response: ErrorResponse = serde_json::from_slice(&b).unwrap();
                let expected =
                    "Request body is malformed\n\tcaused by: expected value at line 1 column 1";
                assert_eq!(expected, error_response.message());
                Ok(())
            })
            .wait()
            .unwrap();
    }
}
