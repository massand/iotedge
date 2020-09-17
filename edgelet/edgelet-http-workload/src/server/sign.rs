// Copyright (c) Microsoft. All rights reserved.

use std::sync::{Arc, Mutex};

use failure::ResultExt;
use futures::{Future, IntoFuture, Stream};
use hyper::header::{CONTENT_LENGTH, CONTENT_TYPE};
use hyper::{Body, Request, Response, StatusCode};
use workload::models::{SignRequest, SignResponse};

use aziot_key_common::KeyHandle;
use edgelet_core::crypto::Signature;
use edgelet_http::route::{Handler, Parameters};
use edgelet_http::Error as HttpError;
use http_common::Connector;
use identity_client::client::IdentityClient;


use crate::error::{EncryptionOperation, Error, ErrorKind};
use crate::IntoResponse;

pub struct SignHandler
{
    key_store: Arc<Mutex<aziot_key_client::Client>>,
    identity_client: Arc<Mutex<IdentityClient>>,
}

impl SignHandler
{
    pub fn new(key_connector: Connector, identity_client: IdentityClient) -> Self {
        let key_store = Arc::new(Mutex::new(aziot_key_client::Client::new(key_connector)));
        
        SignHandler { key_store, identity_client: Arc::new(Mutex::new(identity_client)) }
    }
}

impl Handler<Parameters> for SignHandler
{
    fn handle(
        &self,
        req: Request<Body>,
        params: Parameters,
    ) -> Box<dyn Future<Item = Response<Body>, Error = HttpError> + Send> {
        let key_store = self.key_store.clone();
        let id_mgr = self.identity_client.clone();

        let response = params
            .name("name")
            .ok_or_else(|| Error::from(ErrorKind::MissingRequiredParameter("name")))
            .and_then(|name| {
                let genid = params
                    .name("genid")
                    .ok_or_else(|| Error::from(ErrorKind::MissingRequiredParameter("genid")))?;
                Ok((name, genid))
            })
            .map(|(name, genid)| {
                let id = name.to_string();
                let genid = genid.to_string();
                let key_store = self.key_store.clone();

                req.into_body().concat2().then(|body| {
                    let body =
                        body.context(ErrorKind::EncryptionOperation(EncryptionOperation::Encrypt))?;
                    let request: SignRequest =
                        serde_json::from_slice(&body).context(ErrorKind::MalformedRequestBody)?;
                    Ok((id, request))
                })
            })
            .into_future()
            .flatten()
            .and_then(|(id, request)| -> Result<_, Error> {
                let fut = get_key_handle(id_mgr.clone(),&id);
                let data: Vec<u8> = base64::decode(request.data()).context(ErrorKind::MalformedRequestBody)?;
                let sig = fut.and_then(|k| { get_signature(self.key_store.clone(), k, data) } )
                .and_then(|signature| -> Result<_, Error> {
                    let encoded = base64::encode(signature.as_bytes());
                    let response = SignResponse::new(encoded);
                    let body = serde_json::to_string(&response)
                        .context(ErrorKind::EncryptionOperation(EncryptionOperation::Sign))?;
                    let response = Response::builder()
                        .status(StatusCode::OK)
                        .header(CONTENT_TYPE, "application/json")
                        .header(CONTENT_LENGTH, body.len().to_string().as_str())
                        .body(body.into())
                        .context(ErrorKind::EncryptionOperation(EncryptionOperation::Sign))?;
                    Ok(response)
                });
                sig.map(Ok)
            })
            .or_else(|e| Ok(e.into_response()));

        Box::new(response)
    }
}

fn get_key_handle(identity_client: Arc<Mutex<IdentityClient>>, name: &str) -> impl Future<Item = KeyHandle, Error = Error> {
    let id_mgr = identity_client.lock().unwrap();
    id_mgr.get_module("2020-09-01", name)
    .map_err(|_| Error::from(ErrorKind::GetIdentity))
    .and_then(|identity| {
        match identity {
            aziot_identity_common::Identity::Aziot(spec) => {
                spec.auth.map(|authInfo| {
                    Ok(authInfo.key_handle)
                }).expect("keyhandle missing")
            }
        }   
    })
}

fn get_signature(key_client: Arc<Mutex<aziot_key_client::Client>>, key_handle: KeyHandle, data: Vec<u8> + 'static) -> impl Future<Item = Vec<u8>, Error = Error> {
    key_client
    .lock()
    .expect("lock error")
    .sign(
        &key_handle,
         aziot_key_common::SignMechanism::HmacSha256,
          data.as_bytes())
    .map_err(|_| Error::from(ErrorKind::GetIdentity))
}