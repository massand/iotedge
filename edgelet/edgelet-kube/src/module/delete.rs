// Copyright (c) Microsoft. All rights reserved.

use failure::Fail;
//use futures::prelude::*;
use futures::future::Either;
use futures::{future, Future, Stream};
use hyper::service::Service;
use hyper::Body;

use kube_client::TokenSource;

use crate::error::Error;
use crate::{ErrorKind, KubeModuleRuntime};

pub fn delete_module<T, S>(
    runtime: &KubeModuleRuntime<T, S>,
    module: &str,
) -> impl Future<Item = (), Error = Error>
where
    T: TokenSource + Send + 'static,
    S: Send + Service + 'static,
    S::ReqBody: From<Vec<u8>>,
    S::ResBody: Stream,
    Body: From<S::ResBody>,
    S::Error: Fail,
    S::Future: Send,
{
    let fut = runtime
        .client()
        .lock()
        .expect("Unexpected lock error")
        .borrow_mut()
        .delete_deployment(runtime.settings().namespace(), module)
        .map_err(|err| Error::from(err.context(ErrorKind::KubeClient)))
        .map(|_| ());

    Either::A(future::ok(()));

    Either::B(fut)
}

#[cfg(test)]
mod tests {
    use hyper::service::service_fn;
    use hyper::Method;
    use maplit::btreemap;
    use tokio::runtime::Runtime;

    use edgelet_test_utils::routes;
    use edgelet_test_utils::web::{make_req_dispatcher, HttpMethod, RequestHandler, RequestPath};

    use crate::module::delete_module;
    use crate::tests::{
        create_runtime, delete_handler, deployment_list_handler, make_settings, not_found_handler,
        replace_role_binding_handler, service_account_list_handler,
    };

    #[test]
    fn it_deletes_all_resources() {
        let settings = make_settings(None);

        let dispatch_table = routes!(
        //                    GET format!("/api/apps/v1/namespaces/{}/deployments", settings.namespace()) => deployment_list_handler(),
                            DELETE format!("/apis/apps/v1/namespaces/{}/deployments/edgeagent", settings.namespace()) => delete_handler(),
        //                    GET format!("/api/apps/v1/namespaces/{}/serviceaccounts", settings.namespace()) => service_account_list_handler(),
                //            DELETE format!("/apis/apps/v1/namespaces/{}/serviceaccounts/edgeagent", settings.namespace()) => delete_handler(),
        //                    GET format!("/apis/rbac.authorization.k8s.io/v1/namespaces/{}/rolebindings/edgeagent", settings.namespace()) => replace_role_binding_handler(),
                //            DELETE format!("/apis/rbac.authorization.k8s.io/v1/namespaces/{}/rolebindings/edgeagent", settings.namespace()) => delete_handler(),
                        );

        let name = "edgeagent";
        let handler = make_req_dispatcher(dispatch_table, Box::new(not_found_handler));
        let service = service_fn(handler);
        let runtime = create_runtime(settings, service);
        let task = delete_module(&runtime, name);

        let mut runtime = Runtime::new().unwrap();
        runtime.block_on(task).unwrap();
    }
}
