// Copyright (c) Microsoft. All rights reserved.

use std::cmp;
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use failure::{Fail, ResultExt};
use futures::future::{Future, IntoFuture};
use hyper::header::{CONTENT_LENGTH, CONTENT_TYPE};
use hyper::{Body, Response, StatusCode};

use cert_client::client::CertificateClient;
use edgelet_core::{
    Certificate as CoreCertificate, CertificateProperties, KeyBytes, PrivateKey as CorePrivateKey,
};
use edgelet_http::Error as HttpError;
use edgelet_utils::ensure_not_empty_with_context;
use openssl::error::ErrorStack;
use workload::models::{CertificateResponse, PrivateKey as PrivateKeyResponse};

use crate::{
    error::{Error, ErrorKind, Result},
    IntoResponse,
};

mod identity;
mod server;

pub use self::identity::IdentityCertHandler;
pub use self::server::ServerCertHandler;

fn cert_to_response<T: CoreCertificate>(
    cert: &T,
    context: ErrorKind,
) -> Result<CertificateResponse> {
    let cert_buffer = match cert.pem() {
        Ok(cert_buffer) => cert_buffer,
        Err(err) => return Err(Error::from(err.context(context))),
    };

    let expiration = match cert.get_valid_to() {
        Ok(expiration) => expiration,
        Err(err) => return Err(Error::from(err.context(context))),
    };

    let private_key = match cert.get_private_key() {
        Ok(Some(CorePrivateKey::Ref(ref_))) => {
            PrivateKeyResponse::new("ref".to_string()).with_ref(ref_)
        }
        Ok(Some(CorePrivateKey::Key(KeyBytes::Pem(buffer)))) => {
            PrivateKeyResponse::new("key".to_string())
                .with_bytes(String::from_utf8_lossy(buffer.as_ref()).to_string())
        }
        Ok(None) => return Err(ErrorKind::BadPrivateKey.into()),
        Err(err) => return Err(Error::from(err.context(context))),
    };

    Ok(CertificateResponse::new(
        private_key,
        String::from_utf8_lossy(cert_buffer.as_ref()).to_string(),
        expiration.to_rfc3339(),
    ))
}

fn compute_validity(expiration: &str, max_duration_sec: i64, context: ErrorKind) -> Result<i64> {
    ensure_not_empty_with_context(expiration, || context.clone())?;

    let expiration = DateTime::parse_from_rfc3339(expiration).context(context)?;

    let secs = expiration
        .with_timezone(&Utc)
        .signed_duration_since(Utc::now())
        .num_seconds();

    Ok(cmp::min(secs, max_duration_sec))
}

fn refresh_cert(
    key_client: &Arc<aziot_key_client::Client>,
    cert_client: Arc<Mutex<CertificateClient>>,
    alias: String,
    props: &CertificateProperties,
    edge_ca_id: String,
    context: ErrorKind,
) -> Box<dyn Future<Item = Response<Body>, Error = HttpError> + Send> {
    let response = generate_key_and_csr(props)
        .map_err(|e| Error::from(e.context(context.clone())))
        .into_future()
        .and_then(|(privkey, csr)| {
            let response = get_workload_ca_key_pair(key_client.clone(), cert_client.clone(),edge_ca_id.clone(), context.clone())
                .map_err(|e| Error::from(e.context(context.clone())))
                .and_then(|aziot_edged_ca_key_pair_handle| {
                    Ok((privkey, csr, aziot_edged_ca_key_pair_handle))
                })
                .and_then(
                    move |(privkey, csr, aziot_edged_ca_key_pair_handle)| -> Result<_> {
                        let context_copy = context.clone();
                        let response = cert_client
                            .lock()
                            .expect("certificate client lock error")
                            .create_cert(
                                &alias,
                                &csr,
                                Some((edge_ca_id.as_str(), &aziot_edged_ca_key_pair_handle)),
                            )
                            .map_err(|e| Error::from(e.context(context_copy)))
                            .map(|cert| (privkey, cert))
                            .and_then(move |(privkey, cert)| {
                                let pk = privkey
                                    .private_key_to_pem_pkcs8()
                                    .context(context.clone())?;
                                let cert = Certificate::new(cert, pk);
                                let cert = cert_to_response(&cert, context.clone())?;
                                let body = match serde_json::to_string(&cert) {
                                    Ok(body) => body,
                                    Err(err) => return Err(Error::from(err.context(context))),
                                };

                                let response = Response::builder()
                                    .status(StatusCode::CREATED)
                                    .header(CONTENT_TYPE, "application/json")
                                    .header(CONTENT_LENGTH, body.len().to_string().as_str())
                                    .body(body.into())
                                    .context(context)?;

                                Ok(response)
                            });
                        Ok(response)
                    },
                );
            Ok(response)
        })
        .flatten()
        .or_else(|e| Ok(e.into_response()));

    Box::new(response)
}

fn generate_key_and_csr(
    props: &CertificateProperties,
) -> std::result::Result<(openssl::pkey::PKey<openssl::pkey::Private>, Vec<u8>), ErrorStack> {
    let rsa = openssl::rsa::Rsa::generate(2048)?;
    let privkey = openssl::pkey::PKey::from_rsa(rsa)?;
    let pubkey = privkey.public_key_to_pem()?;
    let pubkey: openssl::pkey::PKey<openssl::pkey::Public> =
        openssl::pkey::PKey::public_key_from_pem(&pubkey)?;

    let mut csr = openssl::x509::X509Req::builder()?;

    csr.set_version(2)?;

    let mut subject_name = openssl::x509::X509Name::builder()?;
    subject_name.append_entry_by_text("CN", props.common_name())?;
    let subject_name = subject_name.build();
    csr.set_subject_name(&subject_name)?;

    csr.set_pubkey(&pubkey)?;

    let mut extended_key_usage = openssl::x509::extension::ExtendedKeyUsage::new();

    if props.certificate_type() == &edgelet_core::CertificateType::Client {
        extended_key_usage.client_auth();
    } else if props.certificate_type() == &edgelet_core::CertificateType::Server {
        extended_key_usage.server_auth();
    }

    let extended_key_usage = extended_key_usage.build()?;

    let mut extensions = openssl::stack::Stack::new()?;
    extensions.push(extended_key_usage)?;

    if props.dns_san_entries().is_some() || props.ip_entries().is_some() {
        let mut subject_alt_name = openssl::x509::extension::SubjectAlternativeName::new();
        props.dns_san_entries().into_iter().flatten().for_each(|s| {
            subject_alt_name.dns(s);
        });
        props.ip_entries().into_iter().flatten().for_each(|s| {
            subject_alt_name.ip(s);
        });
        let san = subject_alt_name.build(&csr.x509v3_context(None))?;
        extensions.push(san)?;
    }

    csr.add_extensions(&extensions)?;

    csr.sign(&privkey, openssl::hash::MessageDigest::sha256())?;

    let csr = csr.build();
    let csr = csr.to_pem()?;

    Ok((privkey, csr))
}

fn get_workload_ca_key_pair(key_client: Arc<aziot_key_client::Client>, cert_client: Arc<Mutex<CertificateClient>>, ca_cert_id: String, context: ErrorKind) 
    -> Box<dyn Future<Item = aziot_key_common::KeyHandle, Error = Error> + Send>{
    //TODO: Fetch current workload CA cert and check expiration
    //      let workload_ca_cert = 
    let aziot_edged_ca_key_pair_handle = cert_client
        .lock()
        .expect("certificate client lock error")
        .get_cert(
            &ca_cert_id,
        )
        .map_err(|e| Error::from(e.context(context)))
        .map(|_| -> Result<_>{
            key_client
                .load_key_pair(ca_cert_id.as_str())
                .map_err(|e| Error::from(e.context(context.clone())))
        })
        .flatten();

    //TODO: If expired, fetch current key algorithm and produce new one. 
        //     let workload_ca_key_pair = load_key_pair("workload-ca");
        //      delete_key_pair(workload_ca_key_pair)

    // if not found {
    //     let workload_ca_key_pair = create_if_not_exists("workload-ca", algo);
    // }
    
    //TODO: Create new keypair if not exists?
    Box::new(aziot_edged_ca_key_pair_handle)
}

#[derive(Debug)]
pub struct Certificate {
    pem: Vec<u8>,
    private_key: Vec<u8>,
}

impl Certificate {
    pub fn new(pem: Vec<u8>, private_key: Vec<u8>) -> Certificate {
        Certificate { pem, private_key }
    }
}

impl CoreCertificate for Certificate {
    type Buffer = Vec<u8>;
    type KeyBuffer = Vec<u8>;

    fn pem(&self) -> std::result::Result<Self::Buffer, edgelet_core::Error> {
        Ok(self.pem.clone())
    }

    fn get_private_key(
        &self,
    ) -> std::result::Result<Option<CorePrivateKey<Self::KeyBuffer>>, edgelet_core::Error> {
        Ok(Some(CorePrivateKey::Key(KeyBytes::Pem(
            self.private_key.clone(),
        ))))
    }

    fn get_valid_to(&self) -> std::result::Result<DateTime<Utc>, edgelet_core::Error> {
        fn parse_openssl_time(
            time: &openssl::asn1::Asn1TimeRef,
        ) -> chrono::ParseResult<chrono::DateTime<chrono::Utc>> {
            // openssl::asn1::Asn1TimeRef does not expose any way to convert the ASN1_TIME to a Rust-friendly type
            //
            // Its Display impl uses ASN1_TIME_print, so we convert it into a String and parse it back
            // into a chrono::DateTime<chrono::Utc>
            let time = time.to_string();
            let time = chrono::NaiveDateTime::parse_from_str(&time, "%b %e %H:%M:%S %Y GMT")?;
            Ok(chrono::DateTime::<chrono::Utc>::from_utc(time, chrono::Utc))
        }

        let cert = openssl::x509::X509::from_pem(&self.pem)
            .map_err(|_| edgelet_core::Error::from(edgelet_core::ErrorKind::CertificateCreate))?;
        let not_after = parse_openssl_time(cert.not_after())
            .map_err(|_| edgelet_core::Error::from(edgelet_core::ErrorKind::ParseSince))?;
        Ok(not_after)
    }

    fn get_common_name(&self) -> std::result::Result<String, edgelet_core::Error> {
        unimplemented!()
    }
}
