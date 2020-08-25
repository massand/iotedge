// Copyright (c) Microsoft. All rights reserved.

use failure::{Fail, ResultExt};
use futures::future::Future;
use futures::prelude::*;
use hyper::client::{Client as HyperClient};
// use hyper::header::HeaderValue;
// use hyper::service::Service;
use hyper::{Body, Client};
// use hyper::{Body, Error as HyperError};
// use hyper::{Request, Uri};
// use log::{debug, trace};
use typed_headers::{self, http};

use edgelet_http::{UrlConnector};

use crate::error::{Error, ErrorKind, RequestType};
use url::Url;

pub struct IdentityClient {
    client: HyperClient<UrlConnector, Body>
}

impl IdentityClient {
    pub fn new() -> Result<Self, Error> {
        let url = Url::parse("http://localhost:8901").map_err(|err| Error::from(ErrorKind::Uri(err)))?;
        let client = Client::builder()
            .build(UrlConnector::new(
                &url).context(ErrorKind::Hyper)?);
        Ok(IdentityClient {
            client
        })
    }

    pub fn get_device(
        &self,
        _api_version: &str,
    ) -> Box<dyn Future<Item = aziot_identity_common::Identity, Error = Error> + Send>
    {
        let method = hyper::Method::GET;
        
        let uri = format!("/identities/device");

        let mut builder = hyper::Request::builder();
        builder.method(method).uri(uri);
        
        let req = builder
            .body(hyper::Body::empty())
            .expect("could not build hyper::Request");
        
        Box::new(
            self
            .client
            .request(req)
            .map_err(|e| Error::from(e.context(ErrorKind::Request(RequestType::GetDevice))))
            .and_then(|resp| {
                let (http::response::Parts { status, .. }, body) = resp.into_parts();
                body.concat2()
                    .and_then(move |body| Ok((status, body)))
                    .map_err(|e| Error::from(e.context(ErrorKind::Response(RequestType::GetDevice))))
            })
            .and_then(|(status, body)| {
                if status.is_success() {
                    Ok(body)
                } else {
                    Err(Error::from(ErrorKind::Response(RequestType::GetDevice)))
                    //Err(Error::from((status, &*body)))
                }
            })
            .and_then(|body| {
                let parsed: Result<aziot_identity_common::Identity, _> =
                    serde_json::from_slice(&body);
                parsed.map_err(|e| Error::from(e.context(ErrorKind::JsonParse(RequestType::GetDevice))))
            })
        )
    }
    
    // fn reprovision_device(
    //     &self,
    //     api_version: &str,
    // ) -> Box<dyn Future<Item = (), Error = Error<serde_json::Value>>> 
    // {
    //     Box::new()
    // }

    // fn create_module(
    //     &self,
    //     api_version: &str,
    //     module: crate::models::IdentitySpec,
    // ) -> Box<dyn Future<Item = crate::models::IdentityResult, Error = Error<serde_json::Value>>>
    // {
    //     Box::new()
    // }

    // fn delete_module(
    //     &self,
    //     api_version: &str,
    //     module_name: &str,
    // ) -> Box<dyn Future<Item = (), Error = Error<serde_json::Value>>> 
    // {
    //     Box::new()
    // }

    // fn get_module(
    //     &self,
    //     api_version: &str,
    //     module_name: &str,
    // ) -> Box<dyn Future<Item = crate::models::IdentityResult, Error = Error<serde_json::Value>>>
    // {
    //     Box::new()
    // }

    // fn get_modules(
    //     &self,
    //     api_version: &str,
    // ) -> Box<dyn Future<Item = crate::models::IdentityList, Error = Error<serde_json::Value>>> 
    // {
    //     Box::new()
    // }
}