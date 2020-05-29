/* 
 * Key Service API
 *
 * No description provided (generated by Swagger Codegen https://github.com/swagger-api/swagger-codegen)
 *
 * OpenAPI spec version: 2020-02-02
 * 
 * Generated by: https://github.com/swagger-api/swagger-codegen.git
 */

use std::borrow::Borrow;
use std::sync::Arc;

use futures::{Future, Stream};
use typed_headers::{self, mime, http, HeaderMapExt};

use super::{Error, configuration};

pub struct KeyOperationsApiClient<C: hyper::client::connect::Connect> {
    configuration: Arc<configuration::Configuration<C>>,
}

impl<C: hyper::client::connect::Connect> KeyOperationsApiClient<C> {
    pub fn new(configuration: Arc<configuration::Configuration<C>>) -> KeyOperationsApiClient<C> {
        KeyOperationsApiClient {
            configuration,
        }
    }
}

pub trait KeyOperationsApi {
    fn sign(&self, api_version: &str, sign_payload: crate::models::SignRequest) -> Box<dyn Future<Item = crate::models::SignResponse, Error = Error<serde_json::Value>>>;
}


impl<C: hyper::client::connect::Connect>KeyOperationsApi for KeyOperationsApiClient<C>
where
    C: hyper::client::connect::Connect + 'static,
    <C as hyper::client::connect::Connect>::Transport: 'static,
    <C as hyper::client::connect::Connect>::Future: 'static,
{
    fn sign(&self, api_version: &str, sign_payload: crate::models::SignRequest) -> Box<dyn Future<Item = crate::models::SignResponse, Error = Error<serde_json::Value>>> {
        let configuration: &configuration::Configuration<C> = self.configuration.borrow();

        let method = hyper::Method::POST;

        let query = ::url::form_urlencoded::Serializer::new(String::new())
            .append_pair("api-version", &api_version.to_string())
            .finish();
        let uri_str = format!("/sign?{}", query);

        let uri = (configuration.uri_composer)(&configuration.base_path, &uri_str);
        // TODO(farcaller): handle error
        // if let Err(e) = uri {
        //     return Box::new(futures::future::err(e));
        // }

        let serialized = serde_json::to_string(&sign_payload).unwrap();
        let serialized_len = serialized.len();

        let mut req = hyper::Request::builder();
        req.method(method).uri(uri.unwrap());
        if let Some(ref user_agent) = configuration.user_agent {
        req.header(http::header::USER_AGENT, &**user_agent);
        }
        let mut req = req
        .body(hyper::Body::from(serialized))
        .expect("could not build hyper::Request");
        req.headers_mut().
            typed_insert(&typed_headers::ContentType(mime::APPLICATION_JSON));
        req.headers_mut().
            typed_insert(&typed_headers::ContentLength(serialized_len as u64));

        // send request
        Box::new(
        configuration
            .client
                .request(req)
                .map_err(Error::from)
                .and_then(|resp| {
                    let (http::response::Parts { status, .. }, body) = resp.into_parts();
                        body.concat2()
                        .and_then(move |body| Ok((status, body)))
                        .map_err(Error::from)
                })
                .and_then(|(status, body)| {
                    if status.is_success() {
                    Ok(body)
                } else {
                    Err(Error::from((status, &*body)))
                }
                })
                .and_then(|body| {
                    let parsed: Result<crate::models::SignResponse, _> =
                        serde_json::from_slice(&body);
                    parsed.map_err(Error::from)
                }),
        )
    }

}
