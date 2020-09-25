// Copyright (c) Microsoft. All rights reserved.

#![deny(rust_2018_idioms, warnings)]
#![deny(clippy::all, clippy::pedantic)]
#![allow(
    clippy::doc_markdown, // clippy want the "IoT" of "IoT Hub" in a code fence
    clippy::missing_errors_doc,
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::shadow_unrelated,
    clippy::too_many_lines,
    clippy::type_complexity,
    clippy::use_self,
    dead_code,
    unused_imports,
    unused_macros,
    unused_variables,
)]

pub mod app;
mod error;
pub mod logging;
pub mod signal;
pub mod workload;

#[cfg(not(target_os = "windows"))]
pub mod unix;

#[cfg(target_os = "windows")]
pub mod windows;

use futures::sync::mpsc;
use identity_client::IdentityClient;
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::fs::{DirBuilder, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use failure::{Context, Fail, ResultExt};
use futures::future::{Either, IntoFuture};
use futures::sync::oneshot::{self, Receiver};
use futures::{future, Future, Stream};
use hyper::server::conn::Http;
use hyper::{Body, Request, Uri};
use log::{debug, info, Level};
use serde::de::DeserializeOwned;
use serde::Serialize;
use sha2::{Digest, Sha256};
use url::Url;

use edgelet_core::crypto::{
    Activate, CreateCertificate, Decrypt, DerivedKeyStore, Encrypt, GetDeviceIdentityCertificate,
    GetHsmVersion, GetIssuerAlias, GetTrustBundle, KeyIdentity, KeyStore, MakeRandom,
    MasterEncryptionKey, MemoryKey, MemoryKeyStore, Sign, Signature, SignatureAlgorithm,
    IOTEDGED_CA_ALIAS,
};
use edgelet_core::watchdog::Watchdog;
use edgelet_core::{
    AttestationMethod, Authenticator, Certificate, CertificateIssuer, CertificateProperties,
    CertificateType, Dps, MakeModuleRuntime, ManualAuthMethod, Module, ModuleRuntime,
    ModuleRuntimeErrorReason, ModuleSpec, ProvisioningResult as CoreProvisioningResult,
    ProvisioningType, RuntimeSettings, SymmetricKeyAttestationInfo, TpmAttestationInfo,
    WorkloadConfig, X509AttestationInfo,
};
use edgelet_http::certificate_manager::CertificateManager;
use edgelet_http::client::{Client as HttpClient, ClientImpl};
use edgelet_http::logging::LoggingService;
use edgelet_http::{HyperExt, MaybeProxyClient, PemCertificate, API_VERSION};
use edgelet_http_mgmt::ManagementService;
use edgelet_http_workload::WorkloadService;
use edgelet_utils::log_failure;
pub use error::{Error, ErrorKind, InitializeErrorReason};

use crate::error::ExternalProvisioningErrorReason;
use crate::workload::WorkloadData;

const EDGE_RUNTIME_MODULEID: &str = "$edgeAgent";
const EDGE_RUNTIME_MODULE_NAME: &str = "edgeAgent";
const AUTH_SCHEME: &str = "sasToken";

/// The following constants are all environment variables names injected into
/// the Edge Agent container.
///
/// This variable holds the host name of the IoT Hub instance that edge agent
/// is expected to work with.
const HOSTNAME_KEY: &str = "IOTEDGE_IOTHUBHOSTNAME";

/// This variable holds the host name for the parent edge device. This name is used
/// by the edge agent to connect to parent edge hub for identity and twin operations.
const GATEWAY_HOSTNAME_KEY: &str = "IOTEDGE_GATEWAYHOSTNAME";

/// This variable holds the host name for the edge device. This name is used
/// by the edge agent to provide the edge hub container an alias name in the
/// network so that TLS cert validation works.
const EDGEDEVICE_HOSTNAME_KEY: &str = "EdgeDeviceHostName";

/// This variable holds the IoT Hub device identifier.
const DEVICEID_KEY: &str = "IOTEDGE_DEVICEID";

/// This variable holds the IoT Hub module identifier.
const MODULEID_KEY: &str = "IOTEDGE_MODULEID";

/// This variable holds the URI to use for connecting to the workload endpoint
/// in iotedged. This is used by the edge agent to connect to the workload API
/// for its own needs and is also used for volume mounting into module
/// containers when the URI refers to a Unix domain socket.
const WORKLOAD_URI_KEY: &str = "IOTEDGE_WORKLOADURI";

/// This variable holds the URI to use for connecting to the management
/// endpoint in iotedged. This is used by the edge agent for managing module
/// lifetimes and module identities.
const MANAGEMENT_URI_KEY: &str = "IOTEDGE_MANAGEMENTURI";

/// This variable holds the authentication scheme that modules are to use when
/// connecting to other server modules (like Edge Hub). The authentication
/// scheme can mean either that we are to use SAS tokens or a TLS client cert.
const AUTHSCHEME_KEY: &str = "IOTEDGE_AUTHSCHEME";

/// This is the key for the edge runtime mode.
const EDGE_RUNTIME_MODE_KEY: &str = "Mode";

/// This is the edge runtime mode - it should be iotedged, when iotedged starts edge runtime in single node mode.
#[cfg(feature = "runtime-docker")]
const EDGE_RUNTIME_MODE: &str = "iotedged";

/// The HSM lib expects this variable to be set with home directory of the daemon.
const HOMEDIR_KEY: &str = "IOTEDGE_HOMEDIR";

/// The HSM lib expects these environment variables to be set if the Edge has to be operated as a gateway
const DEVICE_CA_CERT_KEY: &str = "IOTEDGE_DEVICE_CA_CERT";
const DEVICE_CA_PK_KEY: &str = "IOTEDGE_DEVICE_CA_PK";
const TRUSTED_CA_CERTS_KEY: &str = "IOTEDGE_TRUSTED_CA_CERTS";

/// The HSM lib expects this variable to be set to the endpoint of the external provisioning environment in the 'external'
/// provisioning mode.
const EXTERNAL_PROVISIONING_ENDPOINT_KEY: &str = "IOTEDGE_EXTERNAL_PROVISIONING_ENDPOINT";

/// This is the key for the largest API version that this edgelet supports
const API_VERSION_KEY: &str = "IOTEDGE_APIVERSION";

const IOTHUB_API_VERSION: &str = "2019-10-01";

/// This is the name of the provisioning backup file
const EDGE_PROVISIONING_BACKUP_FILENAME: &str = "provisioning_backup.json";

/// This is the name of the settings backup file
const EDGE_SETTINGS_STATE_FILENAME: &str = "settings_state";

/// This is the name of the hybrid id subdirectory that will
/// contain the hybrid key and other related files
const EDGE_HYBRID_IDENTITY_SUBDIR: &str = "hybrid_id";

/// This is the name of the hybrid X509-SAS key file
const EDGE_HYBRID_IDENTITY_MASTER_KEY_FILENAME: &str = "iotedge_hybrid_key";
/// This is the name of the hybrid X509-SAS initialization vector
const EDGE_HYBRID_IDENTITY_MASTER_KEY_IV_FILENAME: &str = "iotedge_hybrid_iv";

/// This is the name of the external provisioning subdirectory that will
/// contain the device's identity certificate, private key and other related files
const EDGE_EXTERNAL_PROVISIONING_SUBDIR: &str = "external_prov";

/// This is the name of the identity X509 certificate file
const EDGE_EXTERNAL_PROVISIONING_ID_CERT_FILENAME: &str = "id_cert";
/// This is the name of the identity X509 private key file
const EDGE_EXTERNAL_PROVISIONING_ID_KEY_FILENAME: &str = "id_key";

/// Size in bytes of the master identity key
/// The length has been chosen to be compliant with the underlying
/// default implementation of the HSM lib encryption algorithm. In the future
/// should this need to change, both IDENTITY_MASTER_KEY_LEN_BYTES and
/// IOTEDGED_CRYPTO_IV_LEN_BYTES lengths must be considered and modified appropriately.
const IDENTITY_MASTER_KEY_LEN_BYTES: usize = 32;
/// Size in bytes of the initialization vector
/// The length has been chosen to be compliant with the underlying
/// default implementation of the HSM lib encryption algorithm. In the future
/// should this need to change, both IDENTITY_MASTER_KEY_LEN_BYTES and
/// IOTEDGED_CRYPTO_IV_LEN_BYTES lengths must be considered and modified appropriately.
const IOTEDGED_CRYPTO_IV_LEN_BYTES: usize = 16;
/// Identity to be used for various crypto operations
const IOTEDGED_CRYPTO_ID: &str = "$iotedge";

/// This is the name of the cache subdirectory for settings state
const EDGE_SETTINGS_SUBDIR: &str = "cache";

/// This is the DPS registration ID env variable key
const DPS_REGISTRATION_ID_ENV_KEY: &str = "IOTEDGE_REGISTRATION_ID";

/// This is the edge device identity certificate file path env variable key.
/// This is used for both DPS attestation and manual authentication modes.
const DEVICE_IDENTITY_CERT_PATH_ENV_KEY: &str = "IOTEDGE_DEVICE_IDENTITY_CERT";
/// This is the edge device identity private key file path env variable key.
/// This is used for both DPS attestation and manual authentication modes.
const DEVICE_IDENTITY_KEY_PATH_ENV_KEY: &str = "IOTEDGE_DEVICE_IDENTITY_PK";

const IOTEDGED_COMMONNAME: &str = "iotedged workload ca";
const IOTEDGED_TLS_COMMONNAME: &str = "iotedged";
// 5 mins
const IOTEDGED_MIN_EXPIRATION_DURATION: i64 = 5 * 60;
// 2 hours
const IOTEDGE_ID_CERT_MAX_DURATION_SECS: i64 = 2 * 3600;
// 90 days
const IOTEDGE_SERVER_CERT_MAX_DURATION_SECS: i64 = 90 * 24 * 3600;

// HSM lib version that the iotedge runtime required
const IOTEDGE_COMPAT_HSM_VERSION: &str = "1.0.3";

#[derive(PartialEq)]
enum StartApiReturnStatus {
    Restart,
    Shutdown,
}

pub struct Main<M>
where
    M: MakeModuleRuntime,
{
    settings: M::Settings,
}

impl<M> Main<M>
where
    M: MakeModuleRuntime + Send + 'static,
    M::ModuleRuntime: 'static + Authenticator<Request = Request<Body>> + Clone + Send + Sync,
    <<M::ModuleRuntime as ModuleRuntime>::Module as Module>::Config:
        Clone + DeserializeOwned + Serialize,
    M::Settings: 'static + Clone + Serialize,
    <M::ModuleRuntime as ModuleRuntime>::Logs: Into<Body>,
    <M::ModuleRuntime as Authenticator>::Error: Fail + Sync,
    for<'r> &'r <M::ModuleRuntime as ModuleRuntime>::Error: Into<ModuleRuntimeErrorReason>,
{
    pub fn new(settings: M::Settings) -> Self {
        Main { settings }
    }

    // Allowing cognitive complexity errors for now. TODO: Refactor method later.
    #[allow(clippy::cognitive_complexity)]
    pub fn run_until<F, G>(self, make_shutdown_signal: G) -> Result<(), Error>
    where
        F: Future<Item = (), Error = ()> + Send + 'static,
        G: Fn() -> F,
    {
        let Main { settings } = self;

        let mut tokio_runtime = tokio::runtime::Runtime::new()
            .context(ErrorKind::Initialize(InitializeErrorReason::Tokio))?;

        let cache_subdir_path = Path::new(&settings.homedir()).join(EDGE_SETTINGS_SUBDIR);
        // make sure the cache directory exists
        DirBuilder::new()
            .recursive(true)
            .create(&cache_subdir_path)
            .context(ErrorKind::Initialize(
                InitializeErrorReason::CreateCacheDirectory,
            ))?;

        info!("Obtaining edge device provisioning data...");
        
        //TODO: Replace with factory method?
        let url = settings.endpoints().aziot_identityd_uri().clone();
        let client = Arc::new(Mutex::new(identity_client::IdentityClient::new()));

        let device_info = get_device_info(client)
        .map_err(|e| Error::from(e.context(ErrorKind::Initialize(InitializeErrorReason::DpsProvisioningClient))))
        .map(|(hub_name, device_id)| {
            debug!("{}:{}", hub_name, device_id);
            (hub_name, device_id)
        });

        // let device_id = "device-id-iotedged-test";

        // let _device_id_key_pair_handle =
        //     key_client.create_key_pair_if_not_exists(device_id, Some("ec-p256:rsa-2048:*")).unwrap();

        let (hub, device_id) = tokio_runtime
            .block_on(device_info)
            .context(ErrorKind::Initialize(
                InitializeErrorReason::DpsProvisioningClient,
            ))?;

        info!("Finished provisioning edge device.");

        let runtime = init_runtime::<M>(
            settings.clone(),
            &mut tokio_runtime,
        )?;

        // Normally iotedged will stop all modules when it shuts down. But if it crashed,
        // modules will continue to run. On Linux systems where iotedged is responsible for
        // creating/binding the socket (e.g., CentOS 7.5, which uses systemd but does not
        // support systemd socket activation), modules will be left holding stale file
        // descriptors for the workload and management APIs and calls on these APIs will
        // begin to fail. Resilient modules should be able to deal with this, but we'll
        // restart all modules to ensure a clean start.
        const STOP_TIME: Duration = Duration::from_secs(30);
        info!("Stopping all modules...");
        tokio_runtime
            .block_on(runtime.stop_all(Some(STOP_TIME)))
            .context(ErrorKind::Initialize(
                InitializeErrorReason::StopExistingModules
            ))?;
        info!("Finished stopping modules.");

        // if force_reprovision ||
        //     (provisioning_result.reconfigure() != ReprovisioningStatus::DeviceDataNotUpdated) {
        //     // If this device was re-provisioned and the device key was updated it causes
        //     // module keys to be obsoleted in IoTHub from the previous provisioning. We therefore
        //     // delete all containers after each DPS provisioning run so that IoTHub can be updated
        //     // with new module keys when the deployment is executed by EdgeAgent.
        //     info!(
        //         "Reprovisioning status {:?} will trigger reconfiguration of modules.",
        //         provisioning_result.reconfigure()
        //     );
        
        //TODO: Removing all modules on every restart for now.
        //      When should module runtime remove containers? Should it be based on some cached 
        //      provisioning result?
            tokio_runtime
                .block_on(runtime.remove_all())
                .context(ErrorKind::Initialize(
                    InitializeErrorReason::RemoveExistingModules,
                ))?;
        // }

        // Generate device and workload CA certs
        let keyd_url = settings.endpoints().aziot_keyd_uri().clone();

        tokio_runtime
            .block_on(generate_certs(keyd_url))
            .context(ErrorKind::Initialize(
                InitializeErrorReason::StopExistingModules
            ))?;

        let cfg = WorkloadData::new(
            hub,
            settings.parent_hostname().map(String::from),
            device_id,
            IOTEDGE_ID_CERT_MAX_DURATION_SECS,
            IOTEDGE_SERVER_CERT_MAX_DURATION_SECS,
        );
        // This "do-while" loop runs until a StartApiReturnStatus::Shutdown
        // is received. If the TLS cert needs a restart, we will loop again.
        loop {
            let (code, should_reprovision) = start_api::<_, _, M>(
                &settings,
                &runtime,
                cfg.clone(),
                make_shutdown_signal(),
                &mut tokio_runtime,
            )?;

            if should_reprovision {
                let url = settings.endpoints().aziot_identityd_uri().clone();
                let key_url = settings.endpoints().aziot_keyd_uri().clone();

                let client = identity_client::IdentityClient::new();
                let _device = client.get_device("api_version")
                .and_then(move |identity| {
                    debug!("{:?}", identity);
                    Ok(())
                });

                tokio_runtime
                    .block_on(_device)
                    .context(ErrorKind::Initialize(
                        InitializeErrorReason::DpsProvisioningClient,
                    ))?;

                // Return an error here to let the daemon exit with an error code.
                // This will make `systemd` restart the daemon which will re-execute the
                // provisioning flow and if the device has been re-provisioned, the daemon
                // will configure itself with the new provisioning information as part of
                // that flow.
                return Err(Error::from(ErrorKind::DeviceDeprovisioned))
            }

            if code != StartApiReturnStatus::Restart {
                break;
            }
        }

        info!("Shutdown complete.");
        Ok(())
    }
}

fn get_device_info(identity_client: Arc<Mutex<IdentityClient>>) -> impl Future<Item = (String, String), Error = Error> {
    let id_mgr = identity_client.lock().unwrap();
    id_mgr.get_device("2020-09-01")
    .map_err(|_| Error::from(ErrorKind::Initialize(
        InitializeErrorReason::DpsProvisioningClient,
    )))
    .and_then(|identity| {
        match identity {
            aziot_identity_common::Identity::Aziot(spec) => {
                Ok((spec.hub_name, spec.device_id.0))
            }
        }   
    })
}

fn generate_certs(key_url: Url) -> impl Future<Item = (), Error = Error> {
    // let cert_url = settings.endpoints().aziot_certd_uri().clone();
        // let key_connector = http_common::Connector::new(&key_url).map_err(|_| Error::from(ErrorKind::ReprovisionFailure))?;

        // let mut key_engine = {
        //     let key_client = aziot_key_client::Client::new(key_connector.clone());
        //     let key_client = std::sync::Arc::new(key_client);
    
        //     let key_engine = aziot_key_openssl_engine::load(key_client).map_err(|_| Error::from(ErrorKind::ReprovisionFailure))?;
        //     key_engine
        // };

        // let key_client = {
        //     let key_client = aziot_key_client::Client::new(key_connector);
    	// 	let key_client = std::sync::Arc::new(key_client);
        //     key_client
        // };
        
    //     //TODO: Pass in connector for cert client
    //     let cert_client = cert_client::CertificateClient::new();

    //     let device_ca_key_pair_handle =
    //         key_client.create_key_pair_if_not_exists("iotedged-device-ca", Some("ec-p256:rsa-4096:*")).map_err(|_| Error::from(ErrorKind::ReprovisionFailure))?;
    //     let (device_ca_public_key, device_ca_private_key) = {
    //         let device_ca_key_pair_handle = std::ffi::CString::new(device_ca_key_pair_handle.0.clone()).unwrap();
    //         let device_ca_public_key = key_engine.load_public_key(&device_ca_key_pair_handle).unwrap();
    //         let device_ca_private_key = key_engine.load_private_key(&device_ca_key_pair_handle).unwrap();
    //         (device_ca_public_key, device_ca_private_key)
    //     };
        
    //     //TODO: Check for existing cert
    //     // let device_ca_cert = cert_client.get_cert("iotedged-device-ca").map_err(|_| Error::from(ErrorKind::ReprovisionFailure));
    //     let device_ca_cert = {
    //         let csr =
    //             create_csr("iotedged-device-ca", &device_ca_public_key, &device_ca_private_key)
    //             .map_err(|_| Error::from(ErrorKind::ReprovisionFailure))?;
    //         let device_ca_cert =
    //             cert_client.create_cert("iotedged-device-ca", &csr, None)
    //             .map_err(|_| Error::from(ErrorKind::ReprovisionFailure))?;
    //         device_ca_cert
    //     };

    //     //TODO: Verify and recreate iotedged-device-ca cert if needed
    //     // let regenerate_device_ca_cert = match verify_device_ca_cert(&device_ca_cert[0], &device_ca_private_key)? {
    //     //     VerifyDeviceCaCertResult::Ok => false,
    
    //     //     VerifyDeviceCaCertResult::MismatchedKeys => {
    //     //         println!("Device CA cert does not match device CA private key.");
    //     //         true
    //     //     },
    //     // };
    //     // if regenerate_device_ca_cert {
    //     //     println!("Generating new device CA cert...");
    
    //     //     cert_client.delete_cert("iotedged-device-ca").await.map_err(|err| Error::CreateOrLoadDeviceCaCert(Box::new(err)))?;
    
    //     //     let csr =
    //     //         create_csr("iotedged-device-ca", &device_ca_public_key, &device_ca_private_key)
    //     //         .map_err(|err| Error::CreateOrLoadDeviceCaCert(Box::new(err)))?;
    //     //     let device_ca_cert =
    //     //         cert_client.create_cert("iotedged-device-ca", &csr, None)
    //     //         .await.map_err(|err| Error::CreateOrLoadDeviceCaCert(Box::new(err)))?;
    //     //     let device_ca_cert = openssl::x509::X509::stack_from_pem(&device_ca_cert).map_err(|err| Error::CreateOrLoadDeviceCaCert(Box::new(err)))?;
    
    //     //     println!("Loaded device CA cert with parameters: {}", Displayable(&*device_ca_cert));
    //     //     match verify_device_ca_cert(&device_ca_cert[0], &device_ca_private_key)? {
    //     //         VerifyDeviceCaCertResult::Ok => (),
    
    //     //         verify_result @ VerifyDeviceCaCertResult::MismatchedKeys =>
    //     //             panic!("new device CA cert still failed to validate: {:?}", verify_result),
    //     //     }
    //     // }

        // let workload_ca_key_pair_handle =
        //     key_client.create_key_pair_if_not_exists(IOTEDGED_CA_ALIAS, Some("ec-p256:rsa-4096:*")).map_err(|_| Error::from(ErrorKind::ReprovisionFailure))?;
    //     let (workload_ca_public_key, workload_ca_private_key) = {
    //         let workload_ca_key_pair_handle = std::ffi::CString::new(workload_ca_key_pair_handle.0.clone()).unwrap();
    //         let workload_ca_public_key = key_engine.load_public_key(&workload_ca_key_pair_handle).unwrap();
    //         let workload_ca_private_key = key_engine.load_private_key(&workload_ca_key_pair_handle).unwrap();
    //         (workload_ca_public_key, workload_ca_private_key)
    //     };

    //     //TODO: Check for existing cert
    //     // let workload_ca_cert = cert_client.get_cert(IOTEDGED_CA_ALIAS).map_err(|_| Error::from(ErrorKind::ReprovisionFailure));
    //     let workload_ca_cert = {
    //         let csr =
    //             create_csr(IOTEDGED_CA_ALIAS, &workload_ca_public_key, &workload_ca_private_key)
    //             .map_err(|_| Error::from(ErrorKind::ReprovisionFailure))?;
    //         let workload_ca_cert =
    //             cert_client.create_cert(IOTEDGED_CA_ALIAS, &csr, None)
    //             .map_err(|_| Error::from(ErrorKind::ReprovisionFailure))?;
    //         workload_ca_cert
    //     };

    //     //TODO: Verify and recreate iotedged-workload-ca cert if needed
    //     // let regenerate_workload_ca_cert = match verify_workload_ca_cert(&workload_ca_cert[0], &workload_ca_private_key, &device_ca_cert[0], &device_ca_public_key)? {
    //     //     VerifyWorkloadCaCertResult::Ok => false,
    
    //     //     VerifyWorkloadCaCertResult::MismatchedKeys => {
    //     //         println!("Workload CA cert does not match workload CA private key.");
    //     //         true
    //     //     },
    
    //     //     VerifyWorkloadCaCertResult::NotSignedByDeviceCa => {
    //     //         println!("Workload CA cert is not signed by device CA cert.");
    //     //         true
    //     //     },
    //     // };
    //     // if regenerate_workload_ca_cert {
    //     //     println!("Generating new workload CA cert...");
    
    //     //     cert_client.delete_cert(IOTEDGED_CA_ALIAS).await.map_err(|err| Error::CreateOrLoadWorkloadCaCert(Box::new(err)))?;
    
    //     //     let csr =
    //     //         create_csr(IOTEDGED_CA_ALIAS, &workload_ca_public_key, &workload_ca_private_key)
    //     //         .map_err(|err| Error::CreateOrLoadWorkloadCaCert(Box::new(err)))?;
    //     //     let workload_ca_cert =
    //     //         cert_client.create_cert(IOTEDGED_CA_ALIAS, &csr, None)
    //     //         .await.map_err(|err| Error::CreateOrLoadWorkloadCaCert(Box::new(err)))?;
    //     //     let workload_ca_cert = openssl::x509::X509::stack_from_pem(&*workload_ca_cert).map_err(|err| Error::CreateOrLoadWorkloadCaCert(Box::new(err)))?;
    
    //     //     println!("Loaded workload CA cert with parameters: {}", Displayable(&*workload_ca_cert));
    //     //     match verify_workload_ca_cert(&workload_ca_cert[0], &workload_ca_private_key, &device_ca_cert[0], &device_ca_public_key)? {
    //     //         VerifyWorkloadCaCertResult::Ok => (),
    
    //     //         verify_result => {
    //     //             // TODO: Handle properly
    //     //             panic!("new workload CA cert still failed to validate: {:?}", verify_result);
    //     //         },
    //     //     }
    //     // }

    future::ok(())
}

fn cert_public_key_matches_private_key(
	cert: &openssl::x509::X509Ref,
	private_key: &openssl::pkey::PKeyRef<openssl::pkey::Private>,
) -> bool {
	unsafe {
		openssl2::openssl_returns_1(openssl_sys2::X509_check_private_key(
			foreign_types_shared::ForeignTypeRef::as_ptr(cert),
			foreign_types_shared::ForeignTypeRef::as_ptr(private_key),
		)).is_ok()
	}
}

fn create_csr(
	subject: &str,
	public_key: &openssl::pkey::PKeyRef<openssl::pkey::Public>,
	private_key: &openssl::pkey::PKeyRef<openssl::pkey::Private>,
) -> Result<Vec<u8>, openssl::error::ErrorStack> {
	let mut csr = openssl::x509::X509Req::builder()?;

	csr.set_version(0)?;

	let mut subject_name = openssl::x509::X509Name::builder()?;
	subject_name.append_entry_by_text("CN", subject)?;
	let subject_name = subject_name.build();
	csr.set_subject_name(&subject_name)?;

	csr.set_pubkey(public_key)?;

	csr.sign(private_key, openssl::hash::MessageDigest::sha256())?;

	let csr = csr.build();
	let csr = csr.to_pem()?;
	Ok(csr)
}

fn verify_device_ca_cert(
	device_ca_cert: &openssl::x509::X509Ref,
	device_ca_private_key: &openssl::pkey::PKeyRef<openssl::pkey::Private>,
) -> Result<VerifyDeviceCaCertResult, Error> {
	if !cert_public_key_matches_private_key(device_ca_cert, device_ca_private_key) {
		return Ok(VerifyDeviceCaCertResult::MismatchedKeys);
	}

	Ok(VerifyDeviceCaCertResult::Ok)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum VerifyDeviceCaCertResult {
	Ok,
	MismatchedKeys,
}

fn verify_workload_ca_cert(
	workload_ca_cert: &openssl::x509::X509Ref,
	workload_ca_private_key: &openssl::pkey::PKeyRef<openssl::pkey::Private>,
	device_ca_cert: &openssl::x509::X509Ref,
	device_ca_public_key: &openssl::pkey::PKeyRef<openssl::pkey::Public>,
) -> Result<VerifyWorkloadCaCertResult, Error> {
	if !cert_public_key_matches_private_key(workload_ca_cert, workload_ca_private_key) {
		return Ok(VerifyWorkloadCaCertResult::MismatchedKeys);
	}

	if workload_ca_cert.signature().as_slice().is_empty() {
		return Ok(VerifyWorkloadCaCertResult::NotSignedByDeviceCa);
	}

	if !workload_ca_cert.verify(device_ca_public_key).map_err(|_|Error::from(ErrorKind::ReprovisionFailure))? {
		return Ok(VerifyWorkloadCaCertResult::NotSignedByDeviceCa);
	}

	let issued_result = device_ca_cert.issued(workload_ca_cert);
	if issued_result != openssl::x509::X509VerifyResult::OK {
		return Ok(VerifyWorkloadCaCertResult::NotSignedByDeviceCa);
	}

	Ok(VerifyWorkloadCaCertResult::Ok)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum VerifyWorkloadCaCertResult {
	Ok,
	MismatchedKeys,
	NotSignedByDeviceCa,
}

#[derive(Debug, Fail)]
#[fail(display = "Could not load settings")]
pub struct DiffError(#[cause] Context<Box<dyn std::fmt::Display + Send + Sync>>);

impl From<std::io::Error> for DiffError {
    fn from(err: std::io::Error) -> Self {
        DiffError(Context::new(Box::new(err)))
    }
}

impl From<serde_json::Error> for DiffError {
    fn from(err: serde_json::Error) -> Self {
        DiffError(Context::new(Box::new(err)))
    }
}

#[allow(clippy::too_many_arguments)]
fn start_api<F, W, M>(
    settings: &M::Settings,
    runtime: &M::ModuleRuntime,
    workload_config: W,
    shutdown_signal: F,
    tokio_runtime: &mut tokio::runtime::Runtime,
) -> Result<(StartApiReturnStatus, bool), Error>
where
    F: Future<Item = (), Error = ()> + Send + 'static,
    W: WorkloadConfig + Clone + Send + Sync + 'static,
    M::ModuleRuntime: Authenticator<Request = Request<Body>> + Send + Sync + Clone + 'static,
    M: MakeModuleRuntime + 'static,
    <<M::ModuleRuntime as ModuleRuntime>::Module as Module>::Config:
        Clone + DeserializeOwned + Serialize,
    M::Settings: 'static,
    <M::ModuleRuntime as ModuleRuntime>::Logs: Into<Body>,
    <M::ModuleRuntime as Authenticator>::Error: Fail + Sync,
    for<'r> &'r <M::ModuleRuntime as ModuleRuntime>::Error: Into<ModuleRuntimeErrorReason>,
{
    let iot_hub_name = workload_config.iot_hub_name().to_string();
    let device_id = workload_config.device_id().to_string();
    let upstream_gateway = format!(
        "https://{}",
        workload_config.parent_hostname().unwrap_or(&iot_hub_name)
    );

    let (mgmt_tx, mgmt_rx) = oneshot::channel();
    let (mgmt_stop_and_reprovision_tx, mgmt_stop_and_reprovision_rx) = mpsc::unbounded();
    let (work_tx, work_rx) = oneshot::channel();

    //TODO: Create CSR with props by getting device CA and using that CA as issuer for TLS cert
    let edgelet_cert_props = CertificateProperties::new(
        settings.certificates().auto_generated_ca_lifetime_seconds(),
        IOTEDGED_TLS_COMMONNAME.to_string(),
        CertificateType::Server,
        "iotedge-tls".to_string(),
    )
    .with_issuer(CertificateIssuer::DeviceCa);

    let id_mgr = identity_client::IdentityClient::new();

    // Create the certificate management timer and channel
    // let (restart_tx, restart_rx) = oneshot::channel();

    let expiration_timer = future::ok(());

    let mgmt = start_management::<M>(
        settings,
        runtime,
        id_mgr,
        mgmt_rx,
        mgmt_stop_and_reprovision_tx,
    );

    let workload = start_workload::<_, M>(
        settings,
        runtime,
        work_rx,
        workload_config,
    );

    let (runt_tx, runt_rx) = oneshot::channel();
    let edge_rt = start_runtime::<_, _, M>(
        runtime.clone(),
        &iot_hub_name,
        &device_id,
        &settings,
        runt_rx,
    )?;

    // This mpsc sender/receiver is used for getting notifications from the mgmt service
    // indicating that the daemon should shut down and attempt to reprovision the device.
    let mgmt_stop_and_reprovision_signaled = mgmt_stop_and_reprovision_rx
        .then(|res| match res {
            Ok(_) => Err(None),
            Err(_) => Err(Some(Error::from(ErrorKind::ManagementService))),
        })
        .for_each(move |_x: Option<Error>| Ok(()))
        .then(|res| match res {
            Ok(_) | Err(None) => Ok(None),
            Err(Some(e)) => Err(Some(e)),
        });

    let mgmt_stop_and_reprovision_signaled = if settings.provisioning().dynamic_reprovisioning() {
        futures::future::Either::B(mgmt_stop_and_reprovision_signaled)
    } else {
        futures::future::Either::A(future::empty())
    };

    let edge_rt_with_mgmt_signal = edge_rt.select2(mgmt_stop_and_reprovision_signaled).then(
        |res: Result<
            Either<((), _), (Option<Error>, _)>,
            Either<(Error, _), (Option<Error>, _)>,
        >| {
            // A -> EdgeRt Future
            // B -> Mgmt Stop and Reprovision Signal Future
            match res {
                Ok(Either::A((_x, _y))) => {
                    Ok((StartApiReturnStatus::Shutdown, false)).into_future()
                }
                Ok(Either::B((_x, _y))) => {
                    debug!("Shutdown with device reprovisioning.");
                    Ok((StartApiReturnStatus::Shutdown, true)).into_future()
                }
                Err(Either::A((err, _y))) => Err(err).into_future(),
                Err(Either::B((err, _y))) => {
                    debug!("The mgmt shutdown and reprovision signal failed.");
                    Err(err.unwrap()).into_future()
                }
            }
        },
    );

    // Wait for the watchdog to finish, and then send signal to the workload and management services.
    // This way the edgeAgent can finish shutting down all modules.
    let edge_rt_with_cleanup = edge_rt_with_mgmt_signal
        .select2(future::empty())
        .then(move |res| {
            mgmt_tx.send(()).unwrap_or(());
            work_tx.send(()).unwrap_or(());

            // A -> EdgeRt + Mgmt Stop and Reprovision Signal Future
            // B -> Restart Signal Future
            match res {
                Ok(Either::A((x, _))) => Ok((StartApiReturnStatus::Shutdown, x.1)).into_future(),
                Ok(Either::B(_)) => Ok((StartApiReturnStatus::Restart, false)).into_future(),
                Err(Either::A((err, _))) => Err(err).into_future(),
                Err(Either::B(_)) => {
                    debug!("The restart signal failed, shutting down.");
                    Ok((StartApiReturnStatus::Shutdown, false)).into_future()
                }
            }
        });

    let shutdown = shutdown_signal.map(move |_| {
        debug!("shutdown signaled");
        // Signal the watchdog to shutdown
        runt_tx.send(()).unwrap_or(());
    });
    tokio_runtime.spawn(shutdown);

    let services = mgmt
        .join4(workload, edge_rt_with_mgmt_signal, expiration_timer)
        .then(|result| match result {
            Ok(((), (), (code, should_reprovision), ())) => Ok((code, should_reprovision)),
            Err(err) => Err(err),
        });
    let (restart_code, should_reprovision) = tokio_runtime.block_on(services)?;
    Ok((restart_code, should_reprovision))
}

fn init_runtime<M>(
    settings: M::Settings,
    tokio_runtime: &mut tokio::runtime::Runtime,
) -> Result<M::ModuleRuntime, Error>
where
    M: MakeModuleRuntime + Send + 'static,
    M::ModuleRuntime: Send,
    M::Future: 'static,
{
    info!("Initializing the module runtime...");
    let runtime = tokio_runtime
        .block_on(M::make_runtime(settings))
        .context(ErrorKind::Initialize(InitializeErrorReason::ModuleRuntime))?;
    info!("Finished initializing the module runtime.");

    Ok(runtime)
}

fn start_runtime<K, HC, M>(
    runtime: M::ModuleRuntime,
    hostname: &str,
    device_id: &str,
    settings: &M::Settings,
    shutdown: Receiver<()>,
) -> Result<impl Future<Item = (), Error = Error>, Error>
where
    K: 'static + Sign + Clone + Send + Sync,
    HC: 'static + ClientImpl,
    M: MakeModuleRuntime,
    M::ModuleRuntime: Clone + 'static,
    <<M::ModuleRuntime as ModuleRuntime>::Module as Module>::Config:
        Clone + DeserializeOwned + Serialize,
    <M::ModuleRuntime as ModuleRuntime>::Logs: Into<Body>,
    for<'r> &'r <M::ModuleRuntime as ModuleRuntime>::Error: Into<ModuleRuntimeErrorReason>,
{
    let spec = settings.agent().clone();
    let env = build_env(spec.env(), hostname, device_id, settings);
    let spec = ModuleSpec::<<M::ModuleRuntime as ModuleRuntime>::Config>::new(
        EDGE_RUNTIME_MODULE_NAME.to_string(),
        spec.type_().to_string(),
        spec.config().clone(),
        env,
        spec.image_pull_policy(),
    )
    .context(ErrorKind::Initialize(InitializeErrorReason::EdgeRuntime))?;

    let watchdog = Watchdog::new(runtime, settings.watchdog().max_retries());
    let runtime_future = watchdog
        .run_until(spec, EDGE_RUNTIME_MODULEID, shutdown.map_err(|_| ()))
        .map_err(Error::from);

    Ok(runtime_future)
}

// Add the environment variables needed by the EdgeAgent.
fn build_env<S>(
    spec_env: &BTreeMap<String, String>,
    hostname: &str,
    device_id: &str,
    settings: &S,
) -> BTreeMap<String, String>
where
    S: RuntimeSettings,
{
    let mut env = BTreeMap::new();
    env.insert(HOSTNAME_KEY.to_string(), hostname.to_string());
    env.insert(
        EDGEDEVICE_HOSTNAME_KEY.to_string(),
        settings.hostname().to_string().to_lowercase(),
    );

    if let Some(parent_hostname) = settings.parent_hostname() {
        env.insert(
            GATEWAY_HOSTNAME_KEY.to_string(),
            parent_hostname.to_string().to_lowercase(),
        );
    }

    env.insert(DEVICEID_KEY.to_string(), device_id.to_string());
    env.insert(MODULEID_KEY.to_string(), EDGE_RUNTIME_MODULEID.to_string());

    #[cfg(feature = "runtime-docker")]
    let (workload_uri, management_uri) = (
        settings.connect().workload_uri().to_string(),
        settings.connect().management_uri().to_string(),
    );

    env.insert(WORKLOAD_URI_KEY.to_string(), workload_uri);
    env.insert(MANAGEMENT_URI_KEY.to_string(), management_uri);
    env.insert(AUTHSCHEME_KEY.to_string(), AUTH_SCHEME.to_string());
    env.insert(
        EDGE_RUNTIME_MODE_KEY.to_string(),
        EDGE_RUNTIME_MODE.to_string(),
    );
    for (key, val) in spec_env.iter() {
        env.insert(key.clone(), val.clone());
    }
    env.insert(API_VERSION_KEY.to_string(), API_VERSION.to_string());
    env
}

fn start_management<M>(
    settings: &M::Settings,
    runtime: &M::ModuleRuntime,
    identity_client: IdentityClient,
    shutdown: Receiver<()>,
    initiate_shutdown_and_reprovision: mpsc::UnboundedSender<()>,
) -> impl Future<Item = (), Error = Error>
where
    M: MakeModuleRuntime,
    M::ModuleRuntime: Authenticator<Request = Request<Body>> + Send + Sync + Clone + 'static,
    <<M::ModuleRuntime as Authenticator>::AuthenticateFuture as Future>::Error: Fail,
    for<'r> &'r <M::ModuleRuntime as ModuleRuntime>::Error: Into<ModuleRuntimeErrorReason>,
    <<M::ModuleRuntime as ModuleRuntime>::Module as Module>::Config: DeserializeOwned + Serialize,
    <M::ModuleRuntime as ModuleRuntime>::Logs: Into<Body>,
{
    info!("Starting management API...");

    let label = "mgmt".to_string();
    let url = settings.listen().management_uri().clone();
    let min_protocol_version = settings.listen().min_tls_version();
    let identity_client = Arc::new(Mutex::new(identity_client::IdentityClient::new()));

    ManagementService::new(runtime, identity_client, initiate_shutdown_and_reprovision)
        .then(move |service| -> Result<_, Error> {
            let service = service.context(ErrorKind::Initialize(
                InitializeErrorReason::ManagementService,
            ))?;
            let service = LoggingService::new(label, service);

            let run = Http::new()
                .bind_url(url.clone(), service)
                .map_err(|err| {
                    err.context(ErrorKind::Initialize(
                        InitializeErrorReason::ManagementService,
                    ))
                })?
                .run_until(shutdown.map_err(|_| ()))
                .map_err(|err| Error::from(err.context(ErrorKind::ManagementService)));
            info!("Listening on {} with 1 thread for management API.", url);
            Ok(run)
        })
        .flatten()
}

fn start_workload<W, M>(
    settings: &M::Settings,
    runtime: &M::ModuleRuntime,
    shutdown: Receiver<()>,
    config: W,
) -> impl Future<Item = (), Error = Error>
where
    W: WorkloadConfig + Clone + Send + Sync + 'static,
    M: MakeModuleRuntime + 'static,
    M::Settings: 'static,
    M::ModuleRuntime: 'static + Authenticator<Request = Request<Body>> + Clone + Send + Sync,
    <<M::ModuleRuntime as Authenticator>::AuthenticateFuture as Future>::Error: Fail,
    for<'r> &'r <M::ModuleRuntime as ModuleRuntime>::Error: Into<ModuleRuntimeErrorReason>,
    <<M::ModuleRuntime as ModuleRuntime>::Module as Module>::Config:
        Clone + DeserializeOwned + Serialize,
    <M::ModuleRuntime as ModuleRuntime>::Logs: Into<Body>,
{
    info!("Starting workload API...");

    let label = "work".to_string();
    let url = settings.listen().workload_uri().clone();
    let min_protocol_version = settings.listen().min_tls_version();

    let keyd_url = settings.endpoints().aziot_keyd_uri().clone();
    let _certd_url = settings.endpoints().aziot_certd_uri().clone();
    let _identityd_url = settings.endpoints().aziot_identityd_uri().clone();

    let key_connector = http_common::Connector::new(&keyd_url).expect("Connector");
    let key_client = Arc::new(Mutex::new(aziot_key_client::Client::new(key_connector)));

    let cert_client = Arc::new(Mutex::new(cert_client::CertificateClient::new()));
    let identity_client = Arc::new(Mutex::new(identity_client::IdentityClient::new()));

    WorkloadService::new(runtime, identity_client, cert_client, key_client, config)
        .then(move |service| -> Result<_, Error> {
            let service = service.context(ErrorKind::Initialize(
                InitializeErrorReason::WorkloadService,
            ))?;
            let service = LoggingService::new(label, service);

            let run = Http::new()
                .bind_url(url.clone(), service)
                .map_err(|err| {
                    err.context(ErrorKind::Initialize(
                        InitializeErrorReason::WorkloadService,
                    ))
                })?
                .run_until(shutdown.map_err(|_| ()))
                .map_err(|err| Error::from(err.context(ErrorKind::WorkloadService)));
            info!("Listening on {} with 1 thread for workload API.", url);
            Ok(run)
        })
        .flatten()
}

#[cfg(test)]
mod tests {
    use std::fmt;
    use std::io::Read;
    use std::path::Path;
    use std::sync::Mutex;

    use chrono::{Duration, Utc};
    use lazy_static::lazy_static;
    use rand::RngCore;
    use serde_json::json;
    use tempdir::TempDir;

    use edgelet_core::{
        KeyBytes, ModuleRuntimeState, PrivateKey, DEFAULT_AUTO_GENERATED_CA_LIFETIME_DAYS,
    };
    use edgelet_docker::{DockerConfig, DockerModuleRuntime, Settings};
    use edgelet_test_utils::cert::TestCert;
    use edgelet_test_utils::crypto::TestHsm;
    use edgelet_test_utils::module::{TestModule, TestProvisioningResult, TestRuntime};

    use provisioning::provisioning::{
        AuthType, CredentialSource, Credentials, ProvisioningResult, ReprovisioningStatus,
        SymmetricKeyCredential, X509Credential,
    };

    use super::{
        check_settings_state, compute_settings_digest, diff_with_cached, env,
        signal, CertificateIssuer, CertificateProperties, CreateCertificate, Decrypt, Digest, Encrypt,
        ErrorKind, ExternalProvisioningErrorReason, Fail, File, Future, GetIssuerAlias,
        InitializeErrorReason, Main, MakeModuleRuntime, MakeRandom, MasterEncryptionKey,
        RuntimeSettings, Sha256, Uri, Write,
        EDGE_HYBRID_IDENTITY_MASTER_KEY_FILENAME, EDGE_HYBRID_IDENTITY_MASTER_KEY_IV_FILENAME,
        IDENTITY_MASTER_KEY_LEN_BYTES, IOTEDGED_CRYPTO_IV_LEN_BYTES,
    };
    use docker::models::ContainerCreateBody;

    #[cfg(unix)]
    static GOOD_SETTINGS: &str = "../edgelet-docker/test/linux/sample_settings.yaml";
    #[cfg(unix)]
    static GOOD_SETTINGS1: &str = "test/linux/sample_settings1.yaml";
    #[cfg(unix)]
    static GOOD_SETTINGS2: &str = "test/linux/sample_settings2.yaml";
    #[cfg(unix)]
    static GOOD_SETTINGS_DPS_TPM1: &str = "test/linux/sample_settings.dps.tpm.1.yaml";
    #[cfg(unix)]
    static GOOD_SETTINGS_DPS_SYMM_KEY: &str = "test/linux/sample_settings.dps.symm.key.yaml";
    #[cfg(unix)]
    static GOOD_SETTINGS_NESTED_EDGE: &str = "test/linux/sample_settings.nested.edge.yaml";
    #[cfg(unix)]
    static GOOD_SETTINGS_DPS_DEFAULT: &str =
        "../edgelet-docker/test/linux/sample_settings.dps.default.yaml";
    #[cfg(unix)]
    static EMPTY_CONNECTION_STRING_SETTINGS: &str =
        "../edgelet-docker/test/linux/bad_sample_settings.cs.3.yaml";
    #[cfg(unix)]
    static DEFAULT_CONNECTION_STRING_SETTINGS: &str =
        "../edgelet-docker/test/linux/bad_sample_settings.cs.4.yaml";
    #[cfg(unix)]
    static GOOD_SETTINGS_EXTERNAL: &str =
        "../edgelet-docker/test/linux/sample_settings.external.1.yaml";
    #[cfg(unix)]
    static SETTINGS_DEFAULT_CERT: &str =
        "../edgelet-docker/test/linux/sample_settings_default_cert.yaml";

    #[cfg(windows)]
    static GOOD_SETTINGS: &str = "../edgelet-docker/test/windows/sample_settings.yaml";
    #[cfg(windows)]
    static GOOD_SETTINGS1: &str = "test/windows/sample_settings1.yaml";
    #[cfg(windows)]
    static GOOD_SETTINGS2: &str = "test/windows/sample_settings2.yaml";
    #[cfg(windows)]
    static GOOD_SETTINGS_DPS_TPM1: &str = "test/windows/sample_settings.dps.tpm.1.yaml";
    #[cfg(windows)]
    static GOOD_SETTINGS_DPS_SYMM_KEY: &str = "test/windows/sample_settings.dps.symm.key.yaml";
    #[cfg(windows)]
    static GOOD_SETTINGS_NESTED_EDGE: &str = "test/windows/sample_settings.nested.edge.yaml";
    #[cfg(windows)]
    static GOOD_SETTINGS_DPS_DEFAULT: &str =
        "../edgelet-docker/test/windows/sample_settings.dps.default.yaml";
    #[cfg(windows)]
    static EMPTY_CONNECTION_STRING_SETTINGS: &str =
        "../edgelet-docker/test/windows/bad_sample_settings.cs.3.yaml";
    #[cfg(windows)]
    static DEFAULT_CONNECTION_STRING_SETTINGS: &str =
        "../edgelet-docker/test/windows/bad_sample_settings.cs.4.yaml";
    #[cfg(windows)]
    static GOOD_SETTINGS_EXTERNAL: &str =
        "../edgelet-docker/test/windows/sample_settings.external.1.yaml";
    #[cfg(windows)]
    static SETTINGS_DEFAULT_CERT: &str =
        "../edgelet-docker/test/windows/sample_settings_default_cert.yaml";

    #[derive(Clone, Copy, Debug, Fail)]
    pub struct Error;

    impl fmt::Display for Error {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "Error")
        }
    }

    lazy_static! {
        // Tests that call Main::new cannot run in parallel because they initialize hsm-sys
        // (via hsm_client_crypto_init) which is not thread-safe.
        static ref LOCK: Mutex<()> = Mutex::new(());
    }

    #[test]
    fn default_settings_raise_load_error() {
        let _guard = LOCK.lock().unwrap();

        let settings = Settings::new(Path::new(DEFAULT_CONNECTION_STRING_SETTINGS)).unwrap();
        let main = Main::<DockerModuleRuntime>::new(settings);
        let result = main.run_until(signal::shutdown);
        match result.unwrap_err().kind() {
            ErrorKind::Initialize(InitializeErrorReason::LoadSettings) => (),
            kind => panic!("Expected `LoadSettings` but got {:?}", kind),
        }
    }

    #[test]
    fn empty_connection_string_raises_load_error() {
        let _guard = LOCK.lock().unwrap();

        let settings = Settings::new(Path::new(EMPTY_CONNECTION_STRING_SETTINGS)).unwrap();
        let main = Main::<DockerModuleRuntime>::new(settings);
        let result = main.run_until(signal::shutdown);
        match result.unwrap_err().kind() {
            ErrorKind::Initialize(InitializeErrorReason::LoadSettings) => (),
            kind => panic!("Expected `LoadSettings` but got {:?}", kind),
        }
    }

    #[test]
    fn settings_for_nested_edge() {
        let _guard = LOCK.lock().unwrap();

        let settings = Settings::new(Path::new(GOOD_SETTINGS_NESTED_EDGE)).unwrap();
        assert_eq!(settings.parent_hostname(), Some("parent_iotedge_device"));
    }
}
