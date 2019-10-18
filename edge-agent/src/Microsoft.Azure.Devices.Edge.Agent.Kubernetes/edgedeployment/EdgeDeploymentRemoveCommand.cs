// Copyright (c) Microsoft. All rights reserved.
namespace Microsoft.Azure.Devices.Edge.Agent.Kubernetes.EdgeDeployment
{
    using System.Threading;
    using System.Threading.Tasks;
    using Microsoft.Azure.Devices.Edge.Agent.Core;
    using Microsoft.Azure.Devices.Edge.Util;
    using Microsoft.Extensions.Logging;
    using k8s;
    using k8s.Models;
    using Constants = Microsoft.Azure.Devices.Edge.Agent.Kubernetes.Constants;

    public class EdgeDeploymentRemoveCommand : ICommand
    {
        static readonly ILogger Logger = Util.Logger.Factory.CreateLogger<EdgeDeploymentRemoveCommand>();
        readonly IKubernetes client;
        readonly string deviceNamespace;
        readonly ResourceName resourceName;

        public EdgeDeploymentRemoveCommand(
            string deviceNamespace,
            ResourceName resourceName,
            IKubernetes client)
        {
            this.deviceNamespace = KubeUtils.SanitizeK8sValue(Preconditions.CheckNonWhiteSpace(deviceNamespace, nameof(deviceNamespace)));
            this.resourceName = Preconditions.CheckNotNull(resourceName, nameof(resourceName));
            this.client = Preconditions.CheckNotNull(client, nameof(client));
        }

        public string Id => $"Remove the EdgeDeployment";

        public async Task ExecuteAsync(CancellationToken token)
        {
            await this.client.DeleteNamespacedCustomObjectAsync(
                new V1DeleteOptions(),
                Constants.EdgeDeployment.Group,
                Constants.EdgeDeployment.Version,
                this.deviceNamespace,
                Constants.EdgeDeployment.Plural,
                this.resourceName,
                cancellationToken: token);
        }

        public Task UndoAsync(CancellationToken token) => Task.CompletedTask;

        public string Show() => $"Remove the EdgeDeployment";

        public override string ToString() => this.Show();

    }
}
