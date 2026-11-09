/* ========================================================================
 * Copyright (c) 2005-2026 The OPC Foundation, Inc. All rights reserved.
 *
 * OPC Foundation MIT License 1.00
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 * ======================================================================*/

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Moq;
using NUnit.Framework;
using Opc.Ua.Client;
using Opc.Ua.Client.TestFramework;
using Opc.Ua.Gds.Server.Onboarding;
using Opc.Ua.Security.Certificates;
using Opc.Ua.Server;
using Opc.Ua.Server.Network;
using Opc.Ua.Server.TestFramework;
using Opc.Ua.Tests;
using Quickstarts.ReferenceServer;
using ISession = Opc.Ua.Client.ISession;
using Ua = global::Opc.Ua;

namespace Opc.Ua.Gds.Tests.Onboarding
{
    /// <summary>
    /// Exercises the shared Part 21 and Part 22 Resources tree through a connected session.
    /// </summary>
    [TestFixture]
    [Category("Onboarding")]
    [Category("Server")]
    [NonParallelizable]
    public sealed class ProvisionableDeviceResourcesIntegrationTests
    {
        /// <summary>
        /// Browses the device and provider-backed interface with either node-manager registration order.
        /// </summary>
        [TestCase(true)]
        [TestCase(false)]
        [CancelAfter(60_000)]
        public async Task ProvisionableDeviceAndNetworkModelCoexistUnderResourcesAsync(
            bool networkFirst,
            CancellationToken cancellationToken)
        {
            string pkiRoot = Path.Combine(
                Path.GetTempPath(), "OpcUaResourcesTests", Guid.NewGuid().ToString("N"));
            byte[] password = Encoding.UTF8.GetBytes(Guid.NewGuid().ToString("N"));
            var runtime = new Mock<IProvisionableDeviceRuntime>(MockBehavior.Strict);
            runtime.SetupGet(device => device.IsSingleton).Returns(true);
            runtime.Setup(device => device.RequestTicketsAsync(It.IsAny<CancellationToken>()))
                .ReturnsAsync((ArrayOf<string>)["signed-ticket"]);
            var provider = new ReferenceNetworkModelProvider(new NetworkModelSnapshot
            {
                Timestamp = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc),
                StatusCode = StatusCodes.Good,
                Interfaces =
                [
                    new NetworkInterfaceSnapshot("physical", "eth0")
                    {
                        AdminStatus = InterfaceAdminStatus.Up,
                        OperStatus = InterfaceOperStatus.Up,
                        Speed = 1_000_000_000
                    }
                ],
                MappingTables = [],
                Streams = []
            });
            var server = new ServerFixture<ReferenceServer>(telemetry =>
            {
                var instance = new ReferenceServer(telemetry);
                // This account is already registered with the server's user-management metadata.
                Assert.That(
                    instance.UserDatabase.ResetPassword(
                        "user1", password, Ua.UserConfigurationMask.None, string.Empty),
                    Is.True);
                var network = new NetworkModelNodeManagerFactory(provider, _ => false);
                var device = new ProvisionableDeviceNodeManagerFactory(runtime.Object);
                if (networkFirst)
                {
                    instance.AddNodeManager(network);
                    instance.AddNodeManager(device);
                }
                else
                {
                    instance.AddNodeManager(device);
                    instance.AddNodeManager(network);
                }
                return instance;
            })
            {
                AutoAccept = true,
                SecurityNone = true
            };

            try
            {
                await server.LoadConfigurationAsync(pkiRoot).ConfigureAwait(false);
                server.Config.ServerConfiguration!.UserTokenPolicies =
                [
                    new UserTokenPolicy(UserTokenType.Anonymous),
                    new UserTokenPolicy(UserTokenType.UserName)
                ];
                await server.StartAsync(pkiRoot).ConfigureAwait(false);
                await using var client = new ClientFixture(NUnitTelemetryContext.Create());
                await client.LoadClientConfigurationAsync(pkiRoot).ConfigureAwait(false);
                var serverUrl = new Uri(
                    "opc.tcp://localhost:" + server.Port.ToString(CultureInfo.InvariantCulture));
                await using ISession session = await client.ConnectAsync(
                    serverUrl,
                    SecurityPolicies.Basic256Sha256,
                    default,
                    new UserIdentity("user1", password)).ConfigureAwait(false);

                int deviceIndex = session.NamespaceUris.GetIndex(ProvisionableDeviceNodeManagerFactory.NamespaceUri);
                int networkIndex = session.NamespaceUris.GetIndex(NetworkModelNodeManager.NamespaceUri);
                Assert.That(deviceIndex, Is.GreaterThan(0));
                Assert.That(networkIndex, Is.GreaterThan(0));
                var deviceId = new NodeId(29878u);
                var singletonId = new NodeId(29879u);
                var requestTicketsId = new NodeId(29880u);
                var interfaceId = new NodeId("interface/physical", checked((ushort)networkIndex));

                BrowseResponse response = await session.BrowseAsync(
                    null,
                    null,
                    0,
                    [
                        DescribeBrowse(Ua.ObjectIds.Resources, BrowseDirection.Forward),
                        DescribeBrowse(Ua.ObjectIds.Communication, BrowseDirection.Forward),
                        DescribeBrowse(Ua.ObjectIds.NetworkInterfaces, BrowseDirection.Forward),
                        DescribeBrowse(deviceId, BrowseDirection.Inverse),
                        new BrowseDescription
                        {
                            NodeId = deviceId,
                            BrowseDirection = BrowseDirection.Forward,
                            ReferenceTypeId = Ua.ReferenceTypeIds.HierarchicalReferences,
                            IncludeSubtypes = true,
                            ResultMask = (uint)BrowseResultMask.All
                        }
                    ],
                    cancellationToken).ConfigureAwait(false);
                Assert.That(response.Results.Count, Is.EqualTo(5));
                for (int i = 0; i < response.Results.Count; i++)
                {
                    Assert.That(response.Results[i].StatusCode, Is.EqualTo(StatusCodes.Good));
                    Assert.That(response.Results[i].ContinuationPoint.IsEmpty, Is.True);
                }

                List<ReferenceDescription> resources = response.Results[0].References.ToList();
                ReferenceDescription device = FindByName(resources, "ProvisionableDevice");
                Assert.Multiple(() =>
                {
                    Assert.That(device.BrowseName, Is.EqualTo(new QualifiedName("ProvisionableDevice", 0)));
                    Assert.That(device.NodeId, Is.EqualTo((ExpandedNodeId)deviceId));
                    Assert.That(device.NodeClass, Is.EqualTo(NodeClass.Object));
                    Assert.That(device.ReferenceTypeId, Is.EqualTo(Ua.ReferenceTypeIds.Organizes));
                    Assert.That(device.IsForward, Is.True);
                    Assert.That(device.TypeDefinition, Is.EqualTo(new ExpandedNodeId(26871u)));
                });

                ReferenceDescription communication = FindByName(resources, "Communication");
                Assert.Multiple(() =>
                {
                    Assert.That(communication.BrowseName, Is.EqualTo(new QualifiedName("Communication", 0)));
                    Assert.That(communication.NodeId, Is.EqualTo((ExpandedNodeId)Ua.ObjectIds.Communication));
                    Assert.That(communication.ReferenceTypeId, Is.EqualTo(Ua.ReferenceTypeIds.Organizes));
                    Assert.That(communication.IsForward, Is.True);
                });

                ReferenceDescription interfaces = FindByName(
                    response.Results[1].References.ToList(), "NetworkInterfaces");
                Assert.Multiple(() =>
                {
                    Assert.That(interfaces.BrowseName, Is.EqualTo(new QualifiedName("NetworkInterfaces", 0)));
                    Assert.That(interfaces.NodeId, Is.EqualTo((ExpandedNodeId)Ua.ObjectIds.NetworkInterfaces));
                    Assert.That(interfaces.ReferenceTypeId, Is.EqualTo(Ua.ReferenceTypeIds.Organizes));
                    Assert.That(interfaces.IsForward, Is.True);
                });

                ReferenceDescription networkInterface = FindByName(
                    response.Results[2].References.ToList(), "eth0");
                Assert.Multiple(() =>
                {
                    Assert.That(
                        networkInterface.BrowseName,
                        Is.EqualTo(new QualifiedName("eth0", checked((ushort)networkIndex))));
                    Assert.That(networkInterface.NodeId, Is.EqualTo((ExpandedNodeId)interfaceId));
                    Assert.That(networkInterface.NodeClass, Is.EqualTo(NodeClass.Object));
                    Assert.That(networkInterface.ReferenceTypeId, Is.EqualTo(Ua.ReferenceTypeIds.Organizes));
                    Assert.That(networkInterface.IsForward, Is.True);
                    Assert.That(
                        networkInterface.TypeDefinition,
                        Is.EqualTo((ExpandedNodeId)Ua.ObjectTypeIds.IetfBaseNetworkInterfaceType));
                });

                ReferenceDescription parent = FindByName(response.Results[3].References.ToList(), "Resources");
                Assert.Multiple(() =>
                {
                    Assert.That(parent.BrowseName, Is.EqualTo(new QualifiedName("Resources", 0)));
                    Assert.That(parent.NodeId, Is.EqualTo((ExpandedNodeId)Ua.ObjectIds.Resources));
                    Assert.That(parent.ReferenceTypeId, Is.EqualTo(Ua.ReferenceTypeIds.Organizes));
                    Assert.That(parent.IsForward, Is.False);
                });

                List<ReferenceDescription> children = response.Results[4].References.ToList();
                ReferenceDescription singleton = FindByName(children, "IsSingleton");
                ReferenceDescription requestTickets = FindByName(children, "RequestTickets");
                Assert.Multiple(() =>
                {
                    Assert.That(singleton.NodeId, Is.EqualTo((ExpandedNodeId)singletonId));
                    Assert.That(singleton.BrowseName, Is.EqualTo(new QualifiedName("IsSingleton", 0)));
                    Assert.That(singleton.NodeClass, Is.EqualTo(NodeClass.Variable));
                    Assert.That(singleton.ReferenceTypeId, Is.EqualTo(Ua.ReferenceTypeIds.HasProperty));
                    Assert.That(requestTickets.NodeId, Is.EqualTo((ExpandedNodeId)requestTicketsId));
                    Assert.That(requestTickets.BrowseName, Is.EqualTo(new QualifiedName("RequestTickets", 0)));
                    Assert.That(requestTickets.NodeClass, Is.EqualTo(NodeClass.Method));
                    Assert.That(requestTickets.ReferenceTypeId, Is.EqualTo(Ua.ReferenceTypeIds.HasComponent));
                });
                ReadResponse read = await session.ReadAsync(
                    null, 0, TimestampsToReturn.Neither,
                    [new ReadValueId { NodeId = singletonId, AttributeId = Attributes.Value }],
                    cancellationToken).ConfigureAwait(false);
                Assert.That(read.Results[0].StatusCode, Is.EqualTo(StatusCodes.Good));
                Assert.That(read.Results[0].WrappedValue.TryGetValue(out bool isSingleton), Is.True);
                Assert.That(isSingleton, Is.True);
                TranslateBrowsePathsToNodeIdsResponse translated = await session.TranslateBrowsePathsToNodeIdsAsync(
                    null,
                    [
                        new BrowsePath
                        {
                            StartingNode = Ua.ObjectIds.Resources,
                            RelativePath = new RelativePath
                            {
                                Elements =
                                [
                                    new RelativePathElement
                                    {
                                        ReferenceTypeId = Ua.ReferenceTypeIds.Organizes,
                                        TargetName = new QualifiedName("ProvisionableDevice", 0)
                                    },
                                    new RelativePathElement
                                    {
                                        ReferenceTypeId = Ua.ReferenceTypeIds.HasComponent,
                                        TargetName = new QualifiedName("RequestTickets", 0)
                                    }
                                ]
                            }
                        }
                    ],
                    cancellationToken).ConfigureAwait(false);
                Assert.That(translated.Results[0].StatusCode, Is.EqualTo(StatusCodes.Good));
                Assert.That(translated.Results[0].Targets.Count, Is.EqualTo(1));
                Assert.That(translated.Results[0].Targets[0].TargetId, Is.EqualTo((ExpandedNodeId)requestTicketsId));
                ArrayOf<Variant> outputs = await session.CallAsync(
                    deviceId, requestTicketsId, cancellationToken).ConfigureAwait(false);
                Assert.That(outputs.Count, Is.EqualTo(1));
                Assert.That(outputs[0].TryGetValue(out ArrayOf<string> tickets), Is.True);
                Assert.That(tickets.ToArray(), Is.EqualTo(new[] { "signed-ticket" }));
                runtime.Verify(device => device.RequestTicketsAsync(It.IsAny<CancellationToken>()), Times.Once);
            }
            finally
            {
                await server.StopAsync().ConfigureAwait(false);
                if (Directory.Exists(pkiRoot))
                {
                    Directory.Delete(pkiRoot, recursive: true);
                }
            }
        }

        /// <summary>
        /// Publishes, replaces, and retires the device through one authenticated server session.
        /// </summary>
        [Test]
        [Category("NodeManagerLifecycle")]
        [CancelAfter(60_000)]
        public async Task ConnectedSessionAddReplaceRemoveUpdatesResourcesAndRoutesCurrentRuntimeAsync(
            CancellationToken cancellationToken)
        {
            const string userNamePolicyId = "provisionable-device-user";
            string pkiRoot = Path.Combine(
                Path.GetTempPath(), "OpcUaResourcesLifecycleTests", Guid.NewGuid().ToString("N"));
            var fixture = new ServerFixture<NoListenerReferenceServer>(
                telemetry => new NoListenerReferenceServer(telemetry))
            {
                AutoAccept = true,
                SecurityNone = true
            };
            NoListenerReferenceServer? server = null;
            RequestHeader? requestHeader = null;
            SecureChannelContext? secureChannelContext = null;
            bool sessionActive = false;
            var retirements = new List<Task>();

            var runtime1 = new Mock<IProvisionableDeviceRuntime>(MockBehavior.Strict);
            runtime1.SetupGet(runtime => runtime.IsSingleton).Returns(true);
            runtime1.Setup(runtime => runtime.RequestTicketsAsync(It.IsAny<CancellationToken>()))
                .ReturnsAsync((ArrayOf<string>)["generation-1-ticket"]);

            var runtime2 = new Mock<IProvisionableDeviceRuntime>(MockBehavior.Strict);
            runtime2.SetupGet(runtime => runtime.IsSingleton).Returns(false);
            runtime2.Setup(runtime => runtime.RequestTicketsAsync(It.IsAny<CancellationToken>()))
                .ReturnsAsync((ArrayOf<string>)["generation-2-ticket"]);

            try
            {
                await fixture.LoadConfigurationAsync(pkiRoot).ConfigureAwait(false);
                fixture.Config.ServerConfiguration!.UserTokenPolicies =
                [
                    new UserTokenPolicy
                    {
                        PolicyId = userNamePolicyId,
                        TokenType = UserTokenType.UserName,
                        SecurityPolicyUri = SecurityPolicies.None
                    }
                ];
                Assert.That(
                    await fixture.Application.CheckApplicationInstanceCertificatesAsync(true).ConfigureAwait(false),
                    Is.True);

                server = new NoListenerReferenceServer(NUnitTelemetryContext.Create());
                await fixture.Application.StartAsync(server, cancellationToken).ConfigureAwait(false);

                (requestHeader, secureChannelContext) = await server.CreateAndActivateSessionAsync(
                    TestContext.CurrentContext.Test.Name,
                    useSecurity: false,
                    identityToken: new UserNameIdentityToken
                    {
                        PolicyId = userNamePolicyId,
                        UserName = "user1",
                        Password = Encoding.UTF8.GetBytes("password").ToByteString()
                    }).ConfigureAwait(false);
                sessionActive = true;

                await using IPreparedNodeManagerBatch preparedAdd = await server.NodeManagerLifecycle
                    .PrepareAsync(
                        [NodeManagerBatchChange.Add(
                            new ProvisionableDeviceNodeManagerFactory(runtime1.Object))],
                        cancellationToken)
                    .ConfigureAwait(false);
                NodeManagerBatchResult added = await preparedAdd
                    .CommitAsync(_ => default, cancellationToken)
                    .ConfigureAwait(false);
                Assert.That(added.CleanupFailure, Is.Null);
                Assert.That(added.Registrations, Has.Count.EqualTo(1));
                NodeManagerRegistration registration1 = added.Registrations.Single();
                retirements.Add(added.Retirement);

                await AssertResourcesBindingAsync(
                    server, requestHeader, secureChannelContext, expectedPresent: true, cancellationToken)
                    .ConfigureAwait(false);
                DataValue firstRead = await ReadSingletonAsync(
                    server, requestHeader, secureChannelContext, cancellationToken).ConfigureAwait(false);
                Assert.That(firstRead.StatusCode, Is.EqualTo(StatusCodes.Good));
                Assert.That(firstRead.WrappedValue.TryGetValue(out bool firstSingleton), Is.True);
                Assert.That(firstSingleton, Is.True);

                CallMethodResult firstCall = await RequestTicketsAsync(
                    server, requestHeader, secureChannelContext, cancellationToken).ConfigureAwait(false);
                Assert.That(firstCall.StatusCode, Is.EqualTo(StatusCodes.Good));
                Assert.That(firstCall.OutputArguments.Count, Is.EqualTo(1));
                Assert.That(firstCall.OutputArguments[0].TryGetValue(out ArrayOf<string> firstTickets), Is.True);
                Assert.That(firstTickets.ToArray(), Is.EqualTo(new[] { "generation-1-ticket" }));
                runtime1.Verify(
                    runtime => runtime.RequestTicketsAsync(It.IsAny<CancellationToken>()), Times.Once);

                await using IPreparedNodeManagerBatch preparedReplace = await server.NodeManagerLifecycle
                    .PrepareAsync(
                        [
                            NodeManagerBatchChange.Replace(
                                registration1,
                                new ProvisionableDeviceNodeManagerFactory(runtime2.Object))
                        ],
                        cancellationToken)
                    .ConfigureAwait(false);
                NodeManagerBatchResult replaced = await preparedReplace
                    .CommitAsync(_ => default, cancellationToken)
                    .ConfigureAwait(false);
                Assert.That(replaced.CleanupFailure, Is.Null);
                Assert.That(replaced.Registrations, Has.Count.EqualTo(1));
                NodeManagerRegistration replacementRegistration = replaced.Registrations.Single();
                retirements.Add(replaced.Retirement);
                await replaced.Retirement.WaitAsync(cancellationToken).ConfigureAwait(false);

                // Verify the retired generation's cleanup did not remove the replacement's Resources binding.
                await AssertResourcesBindingAsync(
                    server, requestHeader, secureChannelContext, expectedPresent: true, cancellationToken)
                    .ConfigureAwait(false);
                DataValue replacementRead = await ReadSingletonAsync(
                    server, requestHeader, secureChannelContext, cancellationToken).ConfigureAwait(false);
                Assert.That(replacementRead.StatusCode, Is.EqualTo(StatusCodes.Good));
                Assert.That(replacementRead.WrappedValue.TryGetValue(out bool replacementSingleton), Is.True);
                Assert.That(replacementSingleton, Is.False);

                requestHeader.Timestamp = DateTimeUtc.Now;
                ushort deviceNamespace = checked((ushort)server.CurrentInstance.NamespaceUris.GetIndex(
                    ProvisionableDeviceNodeManagerFactory.NamespaceUri));
                using var writeLifetime = new RequestLifetime(cancellationToken);
                WriteResponse overrideWrite = await server.WriteAsync(
                    secureChannelContext,
                    requestHeader,
                    [
                        new WriteValue
                        {
                            NodeId = new NodeId(29879u),
                            AttributeId = Attributes.Value,
                            Value = new DataValue(new Variant(true))
                        },
                        new WriteValue
                        {
                            NodeId = new NodeId("missing-device-node", deviceNamespace),
                            AttributeId = Attributes.Value,
                            Value = new DataValue(new Variant(true))
                        }
                    ],
                    writeLifetime).ConfigureAwait(false);
                Assert.That(overrideWrite.Results, Has.Count.EqualTo(2));
                Assert.That(overrideWrite.Results[0], Is.EqualTo(StatusCodes.BadUserAccessDenied));
                Assert.That(overrideWrite.Results[1], Is.EqualTo(StatusCodes.BadNodeIdUnknown));

                DataValue unchangedSingleton = await ReadSingletonAsync(
                    server, requestHeader, secureChannelContext, cancellationToken).ConfigureAwait(false);
                Assert.That(unchangedSingleton.StatusCode, Is.EqualTo(StatusCodes.Good));
                Assert.That(unchangedSingleton.WrappedValue.TryGetValue(out bool stillReplacementSingleton), Is.True);
                Assert.That(stillReplacementSingleton, Is.False);

                CallMethodResult replacementCall = await RequestTicketsAsync(
                    server, requestHeader, secureChannelContext, cancellationToken).ConfigureAwait(false);
                Assert.That(replacementCall.StatusCode, Is.EqualTo(StatusCodes.Good));
                Assert.That(replacementCall.OutputArguments.Count, Is.EqualTo(1));
                Assert.That(
                    replacementCall.OutputArguments[0].TryGetValue(out ArrayOf<string> replacementTickets),
                    Is.True);
                Assert.That(replacementTickets.ToArray(), Is.EqualTo(new[] { "generation-2-ticket" }));
                runtime1.Verify(
                    runtime => runtime.RequestTicketsAsync(It.IsAny<CancellationToken>()), Times.Once);
                runtime2.Verify(
                    runtime => runtime.RequestTicketsAsync(It.IsAny<CancellationToken>()), Times.Once);

                await using IPreparedNodeManagerBatch preparedRemove = await server.NodeManagerLifecycle
                    .PrepareAsync(
                        [NodeManagerBatchChange.Remove(replacementRegistration)],
                        cancellationToken)
                    .ConfigureAwait(false);
                NodeManagerBatchResult removed = await preparedRemove
                    .CommitAsync(_ => default, cancellationToken)
                    .ConfigureAwait(false);
                Assert.That(removed.CleanupFailure, Is.Null);
                retirements.Add(removed.Retirement);
                await removed.Retirement.WaitAsync(cancellationToken).ConfigureAwait(false);

                await AssertResourcesBindingAsync(
                    server, requestHeader, secureChannelContext, expectedPresent: false, cancellationToken)
                    .ConfigureAwait(false);
                NodeState resourcesNode = server.CurrentInstance.DiagnosticsNodeManager
                    .FindPredefinedNode<NodeState>(Ua.ObjectIds.Resources) ??
                    throw new AssertionException("The standard Resources node must remain available.");
                Assert.That(
                    resourcesNode.ReferenceExists(
                        Ua.ReferenceTypeIds.Organizes, false, new NodeId(29878u)),
                    Is.False);
                DataValue removedRead = await ReadSingletonAsync(
                    server, requestHeader, secureChannelContext, cancellationToken).ConfigureAwait(false);
                Assert.That(removedRead.StatusCode, Is.EqualTo(StatusCodes.BadNodeIdUnknown));
                CallMethodResult removedCall = await RequestTicketsAsync(
                    server, requestHeader, secureChannelContext, cancellationToken).ConfigureAwait(false);
                Assert.That(removedCall.StatusCode, Is.EqualTo(StatusCodes.BadNodeIdUnknown));
                Assert.That(removedCall.OutputArguments, Is.Empty);

                runtime1.Verify(
                    runtime => runtime.RequestTicketsAsync(It.IsAny<CancellationToken>()), Times.Once);
                runtime2.Verify(
                    runtime => runtime.RequestTicketsAsync(It.IsAny<CancellationToken>()), Times.Once);
            }
            finally
            {
                try
                {
                    if (sessionActive && server is not null && requestHeader is not null &&
                        secureChannelContext is not null)
                    {
                        requestHeader.Timestamp = DateTimeUtc.Now;
                        await server.CloseSessionAsync(
                            secureChannelContext, requestHeader, true, RequestLifetime.None).ConfigureAwait(false);
                    }
                }
                finally
                {
                    try
                    {
                        using (var cleanupTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(10)))
                        {
                            foreach (Task retirement in retirements)
                            {
                                await retirement.WaitAsync(cleanupTimeout.Token).ConfigureAwait(false);
                            }
                        }
                    }
                    finally
                    {
                        try
                        {
                            if (fixture.Application is not null)
                            {
                                await fixture.Application.DisposeAsync().ConfigureAwait(false);
                            }
                        }
                        finally
                        {
                            if (Directory.Exists(pkiRoot))
                            {
                                Directory.Delete(pkiRoot, recursive: true);
                            }
                        }
                    }
                }
            }
        }

        private static async Task AssertResourcesBindingAsync(
            NoListenerReferenceServer server,
            RequestHeader requestHeader,
            SecureChannelContext secureChannelContext,
            bool expectedPresent,
            CancellationToken cancellationToken)
        {
            const uint deviceId = 29878;
            requestHeader.Timestamp = DateTimeUtc.Now;
            using var requestLifetime = new RequestLifetime(cancellationToken);
            BrowseResponse response = await server.BrowseAsync(
                secureChannelContext,
                requestHeader,
                null,
                0,
                [DescribeBrowse(Ua.ObjectIds.Resources, BrowseDirection.Forward)],
                requestLifetime).ConfigureAwait(false);

            Assert.That(response.Results, Has.Count.EqualTo(1));
            BrowseResult result = response.Results[0];
            Assert.That(result.StatusCode, Is.EqualTo(StatusCodes.Good));
            Assert.That(result.ContinuationPoint.IsEmpty, Is.True);
            List<ReferenceDescription> references = result.References.ToList();
            QualifiedName expectedBrowseName = new("ProvisionableDevice", 0);
            ExpandedNodeId expectedTarget = new(deviceId);
            List<ReferenceDescription> byName = references
                .Where(reference => reference.BrowseName == expectedBrowseName)
                .ToList();
            List<ReferenceDescription> byTarget = references
                .Where(reference => reference.NodeId == expectedTarget)
                .ToList();

            Assert.That(byName, Has.Count.EqualTo(expectedPresent ? 1 : 0));
            Assert.That(byTarget, Has.Count.EqualTo(expectedPresent ? 1 : 0));
            if (!expectedPresent)
            {
                return;
            }

            ReferenceDescription device = byName[0];
            Assert.Multiple(() =>
            {
                Assert.That(device.NodeId, Is.EqualTo(expectedTarget));
                Assert.That(device.BrowseName, Is.EqualTo(expectedBrowseName));
                Assert.That(device.NodeClass, Is.EqualTo(NodeClass.Object));
                Assert.That(device.ReferenceTypeId, Is.EqualTo(Ua.ReferenceTypeIds.Organizes));
                Assert.That(device.IsForward, Is.True);
                Assert.That(device.TypeDefinition, Is.EqualTo(new ExpandedNodeId(26871u)));
            });
        }

        private static async Task<DataValue> ReadSingletonAsync(
            NoListenerReferenceServer server,
            RequestHeader requestHeader,
            SecureChannelContext secureChannelContext,
            CancellationToken cancellationToken)
        {
            requestHeader.Timestamp = DateTimeUtc.Now;
            using var requestLifetime = new RequestLifetime(cancellationToken);
            ReadResponse response = await server.ReadAsync(
                secureChannelContext,
                requestHeader,
                0,
                TimestampsToReturn.Neither,
                [
                    new ReadValueId
                    {
                        NodeId = new NodeId(29879u),
                        AttributeId = Attributes.Value
                    }
                ],
                requestLifetime).ConfigureAwait(false);
            Assert.That(response.Results, Has.Count.EqualTo(1));
            return response.Results[0];
        }

        private static async Task<CallMethodResult> RequestTicketsAsync(
            NoListenerReferenceServer server,
            RequestHeader requestHeader,
            SecureChannelContext secureChannelContext,
            CancellationToken cancellationToken)
        {
            requestHeader.Timestamp = DateTimeUtc.Now;
            using var requestLifetime = new RequestLifetime(cancellationToken);
            CallResponse response = await server.CallAsync(
                secureChannelContext,
                requestHeader,
                [
                    new CallMethodRequest
                    {
                        ObjectId = new NodeId(29878u),
                        MethodId = new NodeId(29880u),
                        InputArguments = []
                    }
                ],
                requestLifetime).ConfigureAwait(false);
            Assert.That(response.Results, Has.Count.EqualTo(1));
            return response.Results[0];
        }

        /// <summary>
        /// Uses real StandardServer internals while deliberately creating no listening service hosts.
        /// </summary>
        private sealed class NoListenerReferenceServer : ReferenceServer
        {
            public NoListenerReferenceServer(ITelemetryContext telemetry)
                : base(telemetry)
            {
            }

            protected override ValueTask<ServiceHostInitializationResult> InitializeServiceHostsAsync(
                ApplicationConfiguration configuration,
                ITransportBindingRegistry bindingFactory,
                CancellationToken cancellationToken = default)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var serverDescription = new ApplicationDescription
                {
                    ApplicationUri = configuration.ApplicationUri,
                    ProductUri = configuration.ProductUri,
                    ApplicationName = new LocalizedText(configuration.ApplicationName),
                    ApplicationType = ApplicationType.Server
                };
                var endpoint = new EndpointDescription
                {
                    EndpointUrl = configuration.ServerConfiguration!.BaseAddresses[0],
                    Server = serverDescription,
                    SecurityMode = MessageSecurityMode.None,
                    SecurityPolicyUri = SecurityPolicies.None,
                    TransportProfileUri = Profiles.UaTcpTransport,
                    UserIdentityTokens =
                    [
                        new UserTokenPolicy
                        {
                            PolicyId = "provisionable-device-user",
                            TokenType = UserTokenType.UserName,
                            SecurityPolicyUri = SecurityPolicies.None
                        }
                    ]
                };
                return new ValueTask<ServiceHostInitializationResult>(
                    new ServiceHostInitializationResult([], serverDescription, [endpoint]));
            }
        }

        /// <summary>
        /// Requests complete Organizes references in the specified direction.
        /// </summary>
        private static BrowseDescription DescribeBrowse(NodeId nodeId, BrowseDirection direction)
        {
            return new BrowseDescription
            {
                NodeId = nodeId,
                BrowseDirection = direction,
                ReferenceTypeId = Ua.ReferenceTypeIds.Organizes,
                IncludeSubtypes = false,
                ResultMask = (uint)BrowseResultMask.All
            };
        }

        /// <summary>
        /// Requires exactly one reference with the requested browse-name text.
        /// </summary>
        private static ReferenceDescription FindByName(List<ReferenceDescription> references, string name)
        {
            List<ReferenceDescription> matches = references
                .Where(reference => reference.BrowseName.Name == name)
                .ToList();
            Assert.That(
                matches,
                Has.Count.EqualTo(1),
                $"Expected one {name} reference; found " +
                    string.Join(", ", matches.Select(reference => reference.NodeId)));
            return matches[0];
        }
    }
}
