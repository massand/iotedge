// Copyright (c) Microsoft. All rights reserved.

//use failure::Fail;
//use futures::future::Either;
//use futures::prelude::*;
//use futures::{future, Future, Stream};
use futures::Future;

use crate::error::Error;
//use crate::{ErrorKind, KubeModuleRuntime};
use crate::KubeModuleRuntime;

//use edgelet_docker::DockerConfig;
//use edgelet_core::{ModuleSpec, RuntimeOperation};

pub fn delete_module<T, S>(
    _runtime: &KubeModuleRuntime<T, S>,
    _module: &str,
) -> impl Future<Item=(), Error=Error> {
    futures::future::empty()
}

#[cfg(test)]
mod tests {
    use edgelet_test_utils::routes;
    use edgelet_test_utils::web::{HttpMethod, make_req_dispatcher, RequestHandler, RequestPath};
    use hyper::Method;
    use hyper::service::service_fn;
    use maplit::btreemap;

    use crate::module::delete_module;
    use crate::tests::{
        create_runtime, create_service_account_handler, make_settings, not_found_handler,
    };

    #[test]
    fn it_deletes_all_resources() {
        let settings = make_settings(None);

        let dispatch_table = routes!(
            GET format!("/api/v1/namespaces/{}/serviceaccounts", settings.namespace()) => create_service_account_handler(),
        );

        let name = "edgeagent";
        let handler = make_req_dispatcher(dispatch_table, Box::new(not_found_handler));
        let service = service_fn(handler);
        let runtime = create_runtime(settings, service);
        let _task = delete_module(&runtime, name);
    }
}
