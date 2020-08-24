// Copyright (c) Microsoft. All rights reserved.

use failure::{Fail, ResultExt};
use futures::future;
use futures::prelude::*;
use hyper::body::Payload;
use hyper::client::connect::Connect;
use hyper::client::{Client as HyperClient, HttpConnector, ResponseFuture};
// use hyper::header::HeaderValue;
use hyper::service::Service;
use hyper::{Body, Error as HyperError};
use hyper::{Request, Uri};
use log::{debug, trace};

use crate::error::{Error, ErrorKind, RequestType};

pub struct HttpClient<C, B>(pub HyperClient<C, B>);

impl<C, B> Service for HttpClient<C, B>
where
    C: Connect + Sync + 'static,
    B: Payload + Send,
{
    type ReqBody = B;
    type ResBody = Body;
    type Error = HyperError;
    type Future = ResponseFuture;

    fn call(&mut self, req: Request<B>) -> Self::Future {
        self.0.request(req)
    }
}

pub struct Client {
    client: HttpClient<HttpConnector, Body>
}

impl Client {
    pub fn new() -> Self {
        let mut connector = HttpConnector::new(4);

        Client {
            client: HttpClient(HyperClient::builder().build::<_, Body>(connector)),
        }
    }

    fn execute(
        &mut self,
        req: hyper::Request<Vec<u8>>,
    ) -> impl Future<Item = hyper::Response<Body>, Error = Error> {
        let path = req
            .uri()
            .path_and_query()
            .map_or("", |p| p.as_str())
            .to_string();
        debug!("HTTP request path: {}", path);
        self.config
            .host()
            .join(&path)
            .and_then(|base_url| {
                base_url.join(req.uri().path_and_query().map_or("", |pq| pq.as_str()))
            })
            .map_err(|err| {
                Error::from(err.context(ErrorKind::UrlJoin(self.config.host().clone(), path)))
            })
            .and_then(|url| {
                // req is an http 0.2 Request but hyper uses http 0.1, so destructure req and reassemble it.

                let (req_parts, body) = req.into_parts();

                let mut builder = hyper::Request::builder();

                builder.uri(url.as_str().parse::<Uri>().context(ErrorKind::Uri(url))?);

                builder.method(match req_parts.method {
                    hyper::Method::DELETE => hyper::Method::DELETE,
                    hyper::Method::GET => hyper::Method::GET,
                    hyper::Method::PATCH => hyper::Method::PATCH,
                    hyper::Method::POST => hyper::Method::POST,
                    hyper::Method::PUT => hyper::Method::PUT,
                    method => {
                        let err = failure::format_err!("unrecognized http method {}", method);
                        return Err(err.context(ErrorKind::Hyper).into());
                    }
                });

                for (name, value) in req_parts.headers {
                    if let Some(name) = name {
                        builder.header(name.as_str(), value.as_bytes());
                    }
                }

                let req = builder
                    .body(body.into())
                    .map_err(|err| Error::from(err.context(ErrorKind::Hyper)))?;

                let res = self
                    .client
                    .call(req)
                    .map_err(|err| Error::from(err.context(ErrorKind::Hyper)))
                    .map(|res| res.map(From::from));
                Ok(res)
            })
            .into_future()
            .flatten()
    }
}