/* ========================================================================
 * Copyright (c) 2005-2025 The OPC Foundation, Inc. All rights reserved.
 *
 * OPC Foundation MIT License 1.00
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * The complete license agreement can be found here:
 * http://opcfoundation.org/License/MIT/1.00/
 * ======================================================================*/

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using NUnit.Framework;
using Opc.Ua.Client;
using Opc.Ua.OpenUsd;

namespace Opc.Ua.Di.Tests
{
    /// <summary>
    /// End-to-end validation of the draft OPC UA — OpenUSD Bindings companion
    /// specification against the PumpDeviceIntegrationServer. Starts the pump
    /// server via the generic host, connects a real client session, discovers the
    /// OpenUsdRepresentation AddIn + live bindings on Pump #1, subscribes to the
    /// bound source Variables, and drives an <see cref="OpenUsdConnector"/> that
    /// converts values and writes them into a <see cref="MockUsdSink"/> — the
    /// CI-friendly stand-in for a USD/Omniverse sink.
    /// </summary>
    [TestFixture]
    [Category("Pumps")]
    [Category("OpenUsd")]
    [Category("Integration")]
    [NonParallelizable]
    public sealed class PumpOpenUsdE2eTests
    {
        private ITelemetryContext m_telemetry = null!;
        private IHost? m_host;
        private ISession? m_session;
        private ApplicationConfiguration m_clientConfig = null!;

        private static int GetFreeTcpPort()
        {
            var listener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
            listener.Start();
            int port = ((System.Net.IPEndPoint)listener.LocalEndpoint).Port;
            listener.Stop();
            return port;
        }

        [OneTimeSetUp]
        public async Task OneTimeSetUpAsync()
        {
            m_telemetry = DefaultTelemetry.Create(b => b.SetMinimumLevel(LogLevel.Warning));

            int port = GetFreeTcpPort();
            string serverUrl = $"opc.tcp://localhost:{port}/PumpDeviceIntegrationServer";

            HostApplicationBuilder hostBuilder = Host.CreateApplicationBuilder();
            hostBuilder.Logging.ClearProviders();
            hostBuilder.Logging.SetMinimumLevel(LogLevel.Warning);
            hostBuilder.Services
                .AddOpcUa()
                .AddServer(o =>
                {
                    o.ApplicationName = "PumpOpenUsdE2eServer";
                    o.ApplicationUri = "urn:localhost:OPCFoundation:PumpOpenUsdE2eServer";
                    o.AutoAcceptUntrustedCertificates = true;
                    o.EndpointUrls.Add(serverUrl);
                })
                .AddNodeManager<global::Pumps.PumpNodeManagerFactory>();
            m_host = hostBuilder.Build();
            await m_host.StartAsync().ConfigureAwait(false);

            string pkiRoot = System.IO.Path.Combine(
                System.IO.Path.GetTempPath(), "PumpOpenUsdE2e", System.IO.Path.GetRandomFileName());
            m_clientConfig = new ApplicationConfiguration(m_telemetry)
            {
                ApplicationName = "PumpOpenUsdE2eClient",
                ApplicationUri = "urn:localhost:OPCFoundation:PumpOpenUsdE2eClient",
                ApplicationType = ApplicationType.Client,
                SecurityConfiguration = new SecurityConfiguration
                {
                    ApplicationCertificate = new CertificateIdentifier
                    {
                        StoreType = CertificateStoreType.Directory,
                        StorePath = System.IO.Path.Combine(pkiRoot, "own"),
                        SubjectName = "CN=PumpOpenUsdE2eClient, O=OPC Foundation"
                    },
                    TrustedIssuerCertificates = new CertificateTrustList
                    {
                        StoreType = CertificateStoreType.Directory,
                        StorePath = System.IO.Path.Combine(pkiRoot, "issuer")
                    },
                    TrustedPeerCertificates = new CertificateTrustList
                    {
                        StoreType = CertificateStoreType.Directory,
                        StorePath = System.IO.Path.Combine(pkiRoot, "trusted")
                    },
                    RejectedCertificateStore = new CertificateTrustList
                    {
                        StoreType = CertificateStoreType.Directory,
                        StorePath = System.IO.Path.Combine(pkiRoot, "rejected")
                    },
                    AutoAcceptUntrustedCertificates = true
                },
                TransportQuotas = new TransportQuotas { MaxMessageSize = 4 * 1024 * 1024 },
                ClientConfiguration = new ClientConfiguration(),
                ServerConfiguration = new ServerConfiguration()
            };
            await m_clientConfig.ValidateAsync(ApplicationType.Client).ConfigureAwait(false);

            var appInstance = new Opc.Ua.Configuration.ApplicationInstance(m_clientConfig, m_telemetry);
            await appInstance.CheckApplicationInstanceCertificatesAsync(true).ConfigureAwait(false);

            m_clientConfig.CertificateManager ??= CertificateManagerFactory.Create(
                m_clientConfig.SecurityConfiguration, m_telemetry);
            m_clientConfig.CertificateManager.AcceptError = static (cert, err) => true;

            // The hosted endpoint opens asynchronously after the host starts.
            EndpointDescription? endpointDescription = null;
            for (int attempt = 0; attempt < 40; attempt++)
            {
                try
                {
                    endpointDescription = await CoreClientUtils.SelectEndpointAsync(
                        m_clientConfig, serverUrl, useSecurity: false, m_telemetry, CancellationToken.None)
                        .ConfigureAwait(false);
                    if (endpointDescription != null)
                    {
                        break;
                    }
                }
                catch (Exception)
                {
                    // not ready yet
                }
                await Task.Delay(500).ConfigureAwait(false);
            }
            Assert.That(endpointDescription, Is.Not.Null, "Server endpoint did not become available.");

            var endpoint = new ConfiguredEndpoint(
                null, endpointDescription!, EndpointConfiguration.Create(m_clientConfig));
            var sessionFactory = new DefaultSessionFactory(m_telemetry);
            m_session = await sessionFactory.CreateAsync(
                m_clientConfig, endpoint, updateBeforeConnect: false,
                sessionName: "PumpOpenUsdE2e", sessionTimeout: 60000,
                identity: new UserIdentity(new AnonymousIdentityToken()),
                preferredLocales: default, ct: CancellationToken.None).ConfigureAwait(false);
        }

        [OneTimeTearDown]
        public async Task OneTimeTearDownAsync()
        {
            if (m_session != null)
            {
                await m_session.CloseAsync(CancellationToken.None).ConfigureAwait(false);
                await m_session.DisposeAsync().ConfigureAwait(false);
                m_session = null;
            }
            if (m_clientConfig?.CertificateManager is IDisposable manager)
            {
                manager.Dispose();
            }
            if (m_host != null)
            {
                await m_host.StopAsync().ConfigureAwait(false);
                m_host.Dispose();
                m_host = null;
            }
        }

        [Test]
        public void OpenUsdCompanionModelIsDeployedAndServed()
        {
            // The running server advertises the OpenUSD namespace ...
            int ns = m_session!.NamespaceUris.GetIndex("http://opcfoundation.org/UA/OpenUSD/");
            Assert.That(ns, Is.GreaterThan(0), "OpenUSD namespace not advertised by the server.");

            // ... and serves the companion type nodes (proves the NodeSet loaded).
            var repType = new NodeId(1003u, (ushort)ns);
            var connector = new OpenUsdConnector(m_session!, new MockUsdSink());
            string bn = connector.ReadBrowseNameAsync(repType, CancellationToken.None)
                .GetAwaiter().GetResult();
            Assert.That(bn, Is.EqualTo("OpenUsdRepresentationType"));
        }

        [Test]
        public async Task RepresentationAndBindingsAreDiscoverableAsync()
        {
            var connector = new OpenUsdConnector(m_session!, new MockUsdSink());
            OpenUsdConnector.RepresentationInfo? rep = await connector
                .DiscoverRepresentationAsync(CancellationToken.None).ConfigureAwait(false);

            Assert.That(rep, Is.Not.Null, "OpenUsdRepresentation not discovered on Pump #1.");
            Assert.That(rep!.PrimPath, Is.EqualTo("/Plant/Pumps/P101"));
            Assert.That(rep.StageNodeId, Is.Not.Null);
            Assert.That(rep.RootLayerIdentifier, Is.EqualTo("asset-repo/Plant.usd"));
            Assert.That(rep.Bindings, Has.Count.EqualTo(3));
        }

        [Test]
        public async Task LiveValuesFlowThroughConnectorToUsdSinkAsync()
        {
            var sink = new MockUsdSink();
            var connector = new OpenUsdConnector(m_session!, sink);

            await connector.StartAsync(CancellationToken.None).ConfigureAwait(false);
            await Task.Delay(4000, CancellationToken.None).ConfigureAwait(false);
            await connector.StopAsync().ConfigureAwait(false);

            Assert.Multiple(() =>
            {
                Assert.That(sink.WasWritten("/Plant/Pumps/P101", "xformOp:rotateZ"), Is.True,
                    "Rotation binding produced no value.");
                Assert.That(sink.WasWritten("/Plant/Pumps/P101/Body", "primvars:displayColor"), Is.True,
                    "DisplayColor binding produced no value.");
                Assert.That(sink.WasWritten("/Plant/Pumps/P101", "inputs:emissiveColor"), Is.True,
                    "EmissiveColor binding produced no value.");
                Assert.That(sink.TotalWrites, Is.GreaterThan(0));
            });
        }
    }

    /// <summary>USD-side sink abstraction for the connector.</summary>
    public interface IUsdSink
    {
        void SetAttribute(string primPath, string propertyName, object value);
    }

    /// <summary>In-memory, thread-safe sink for tests.</summary>
    public sealed class MockUsdSink : IUsdSink
    {
        private readonly ConcurrentDictionary<string, (object Value, int Count)> m_state = new();
        private int m_total;
        public int TotalWrites => Volatile.Read(ref m_total);
        public void SetAttribute(string primPath, string propertyName, object value)
        {
            m_state.AddOrUpdate(primPath + "." + propertyName, (value, 1),
                (_, prev) => (value, prev.Count + 1));
            Interlocked.Increment(ref m_total);
        }
        public bool WasWritten(string primPath, string propertyName)
            => m_state.TryGetValue(primPath + "." + propertyName, out (object Value, int Count) v)
               && v.Count > 0;
    }

    /// <summary>
    /// Generic connector: discovers an OpenUsdRepresentation and its live bindings
    /// by Browse/Read, subscribes to the bound source Variables, applies the
    /// declared conversion, and writes the target USD attributes into an
    /// <see cref="IUsdSink"/>. Domain-agnostic — it knows only the OpenUSD model.
    /// </summary>
    public sealed class OpenUsdConnector
    {
        private readonly ISession m_session;
        private readonly IUsdSink m_sink;
        private readonly ushort m_ns;
        private readonly NodeId m_representationTypeId;
        private readonly NodeId m_bindingTypeId;
        private Subscription? m_subscription;

        public OpenUsdConnector(ISession session, IUsdSink sink)
        {
            m_session = session;
            m_sink = sink;
            m_ns = (ushort)m_session.NamespaceUris.GetIndex(Opc.Ua.OpenUsd.Namespaces.OpenUSD);
            m_representationTypeId = new NodeId(1003u, m_ns);
            m_bindingTypeId = new NodeId(1004u, m_ns);
        }

        public sealed class BindingInfo
        {
            public NodeId? SourceNodeId { get; set; }
            public string? PrimPath { get; set; }
            public string? PropertyName { get; set; }
            public OpenUsdRenderTargetKindEnum Kind { get; set; }
            public double Scale { get; set; } = 1.0;
        }

        public sealed class RepresentationInfo
        {
            public NodeId? NodeId { get; set; }
            public NodeId? StageNodeId { get; set; }
            public string? PrimPath { get; set; }
            public string? RootLayerIdentifier { get; set; }
            public List<BindingInfo> Bindings { get; } = new();
        }

        // Part 1 discovery: the well-known OpenUSD facility exposes a
        // Representations registry (Organizes) that lists every
        // OpenUsdRepresentation in the address space, independent of the
        // represented object's own hierarchy.
        private async Task<NodeId?> FindFirstRepresentationAsync(CancellationToken ct)
        {
            var rootId = new NodeId("OpenUSD", m_ns);
            Dictionary<string, NodeId> rootChildren =
                await ChildrenByNameAsync(rootId, ct).ConfigureAwait(false);
            if (!rootChildren.TryGetValue("Representations", out NodeId registry))
            {
                return null;
            }
            foreach ((NodeId? childId, NodeId? typeDef) in
                await ChildrenWithTypeAsync(registry, ct).ConfigureAwait(false))
            {
                if (childId != null && typeDef == m_representationTypeId)
                {
                    return childId;
                }
            }
            return null;
        }

        public async Task<RepresentationInfo?> DiscoverRepresentationAsync(CancellationToken ct)
        {
            NodeId? repNodeId = await FindFirstRepresentationAsync(ct).ConfigureAwait(false);
            if (repNodeId == null)
            {
                return null;
            }

            var info = new RepresentationInfo { NodeId = repNodeId };
            Dictionary<string, NodeId> repProps = await ChildrenByNameAsync(repNodeId.Value, ct)
                .ConfigureAwait(false);
            info.PrimPath = await ReadStringAsync(repProps, "PrimPath", ct).ConfigureAwait(false);
            info.StageNodeId = await ReadNodeIdAsync(repProps, "Stage", ct).ConfigureAwait(false);
            if (info.StageNodeId != null)
            {
                Dictionary<string, NodeId> stageProps =
                    await ChildrenByNameAsync(info.StageNodeId.Value, ct).ConfigureAwait(false);
                info.RootLayerIdentifier =
                    await ReadStringAsync(stageProps, "RootLayerIdentifier", ct).ConfigureAwait(false);
            }

            foreach ((NodeId? childId, NodeId? typeDef) in await ChildrenWithTypeAsync(repNodeId.Value, ct)
                .ConfigureAwait(false))
            {
                if (childId == null || typeDef != m_bindingTypeId)
                {
                    continue;
                }
                Dictionary<string, NodeId> bp = await ChildrenByNameAsync(childId.Value, ct)
                    .ConfigureAwait(false);
                var b = new BindingInfo
                {
                    SourceNodeId = await ReadNodeIdAsync(bp, "SourceNodeId", ct).ConfigureAwait(false),
                    PrimPath = await ReadStringAsync(bp, "TargetPrimPath", ct).ConfigureAwait(false),
                    PropertyName = await ReadStringAsync(bp, "TargetPropertyName", ct).ConfigureAwait(false),
                    Kind = (OpenUsdRenderTargetKindEnum)await ReadInt32Async(bp, "RenderTargetKind", ct)
                        .ConfigureAwait(false),
                    Scale = await ReadDoubleAsync(bp, "Scale", 1.0, ct).ConfigureAwait(false)
                };
                if (string.IsNullOrEmpty(b.PrimPath))
                {
                    b.PrimPath = info.PrimPath;
                }
                info.Bindings.Add(b);
            }
            return info;
        }

        public async Task StartAsync(CancellationToken ct)
        {
            RepresentationInfo? rep = await DiscoverRepresentationAsync(ct).ConfigureAwait(false);
            if (rep == null)
            {
                throw new InvalidOperationException("No OpenUSD representation discovered.");
            }

            var subscription = new Subscription(m_session.DefaultSubscription)
            {
                DisplayName = "OpenUsdConnector",
                PublishingInterval = 250,
                KeepAliveCount = 10,
                LifetimeCount = 100,
                PublishingEnabled = true
            };
            m_subscription = subscription;
            m_session.AddSubscription(subscription);
            await subscription.CreateAsync(ct).ConfigureAwait(false);

            foreach (BindingInfo b in rep.Bindings)
            {
                if (b.SourceNodeId == null)
                {
                    continue;
                }
                var item = new MonitoredItem(subscription.DefaultItem)
                {
                    DisplayName = b.PropertyName ?? "binding",
                    StartNodeId = b.SourceNodeId.Value,
                    AttributeId = Attributes.Value,
                    SamplingInterval = 250,
                    QueueSize = 5,
                    Handle = b
                };
                item.Notification += OnNotification;
                subscription.AddItem(item);
            }
            await subscription.ApplyChangesAsync(ct).ConfigureAwait(false);
        }

        public async Task StopAsync()
        {
            if (m_subscription != null)
            {
                await m_subscription.DeleteAsync(true, CancellationToken.None).ConfigureAwait(false);
                m_subscription = null;
            }
        }

        private void OnNotification(MonitoredItem item, MonitoredItemNotificationEventArgs e)
        {
            if (item.Handle is not BindingInfo b)
            {
                return;
            }
            foreach (DataValue dv in item.DequeueValues())
            {
                object? raw = dv.WrappedValue.AsBoxedObject();
                if (StatusCode.IsNotGood(dv.StatusCode) || raw == null)
                {
                    continue;
                }
                object? usdValue = Convert(b, raw);
                if (usdValue != null)
                {
                    m_sink.SetAttribute(b.PrimPath!, b.PropertyName!, usdValue);
                }
            }
        }

        public static object? Convert(BindingInfo b, object raw)
        {
            double d = ToDouble(raw);
            switch (b.Kind)
            {
                case OpenUsdRenderTargetKindEnum.Rotation:
                case OpenUsdRenderTargetKindEnum.Translation:
                case OpenUsdRenderTargetKindEnum.Scale:
                case OpenUsdRenderTargetKindEnum.Opacity:
                    return d * b.Scale;
                case OpenUsdRenderTargetKindEnum.DisplayColor:
                case OpenUsdRenderTargetKindEnum.EmissiveColor:
                    double t = System.Math.Max(0.0, System.Math.Min(1.0, (d - 20.0) / 80.0));
                    return new[] { (float)t, 0f, (float)(1.0 - t) };
                case OpenUsdRenderTargetKindEnum.Visibility:
                    return d != 0.0 ? "inherited" : "invisible";
                default:
                    return d * b.Scale;
            }
        }

        private static double ToDouble(object v)
        {
            try
            {
                return System.Convert.ToDouble(v, System.Globalization.CultureInfo.InvariantCulture);
            }
            catch (Exception)
            {
                return 0.0;
            }
        }

        public async Task<string> ReadBrowseNameAsync(NodeId nodeId, CancellationToken ct)
        {
            var toRead = new ReadValueId[]
            {
                new ReadValueId { NodeId = nodeId, AttributeId = Attributes.BrowseName }
            };
            ReadResponse response = await m_session.ReadAsync(
                null!, 0, TimestampsToReturn.Neither, toRead, ct).ConfigureAwait(false);
            return response.Results[0].WrappedValue.AsBoxedObject() is QualifiedName qn ? qn.Name ?? string.Empty : string.Empty;
        }

        private async Task<List<ReferenceDescription>> BrowseAsync(NodeId node, CancellationToken ct)
        {
            var desc = new BrowseDescription
            {
                NodeId = node,
                BrowseDirection = BrowseDirection.Forward,
                ReferenceTypeId = Opc.Ua.ReferenceTypeIds.HierarchicalReferences,
                IncludeSubtypes = true,
                NodeClassMask = 0,
                ResultMask = (uint)BrowseResultMask.All
            };
            BrowseResponse response = await m_session.BrowseAsync(
                null!, null!, 0, new BrowseDescription[] { desc }, ct).ConfigureAwait(false);
            var list = new List<ReferenceDescription>();
            ArrayOf<ReferenceDescription> refs = response.Results[0].References;
            for (int i = 0; i < refs.Count; i++)
            {
                list.Add(refs[i]);
            }
            return list;
        }

        private async Task<Dictionary<string, NodeId>> ChildrenByNameAsync(NodeId parent, CancellationToken ct)
        {
            var map = new Dictionary<string, NodeId>();
            foreach (ReferenceDescription r in await BrowseAsync(parent, ct).ConfigureAwait(false))
            {
                if (r.BrowseName.Name is { Length: > 0 } n && !map.ContainsKey(n))
                {
                    map[n] = ExpandedNodeId.ToNodeId(r.NodeId, m_session.NamespaceUris);
                }
            }
            return map;
        }

        private async Task<List<(NodeId?, NodeId?)>> ChildrenWithTypeAsync(NodeId parent, CancellationToken ct)
        {
            var list = new List<(NodeId?, NodeId?)>();
            foreach (ReferenceDescription r in await BrowseAsync(parent, ct).ConfigureAwait(false))
            {
                list.Add((ExpandedNodeId.ToNodeId(r.NodeId, m_session.NamespaceUris),
                          ExpandedNodeId.ToNodeId(r.TypeDefinition, m_session.NamespaceUris)));
            }
            return list;
        }

        private async Task<DataValue> ReadAsync(NodeId nodeId, CancellationToken ct)
        {
            var toRead = new ReadValueId[]
            {
                new ReadValueId { NodeId = nodeId, AttributeId = Attributes.Value }
            };
            ReadResponse response = await m_session.ReadAsync(
                null!, 0, TimestampsToReturn.Neither, toRead, ct).ConfigureAwait(false);
            return response.Results[0];
        }

        private async Task<string?> ReadStringAsync(
            Dictionary<string, NodeId> props, string name, CancellationToken ct)
        {
            if (!props.TryGetValue(name, out NodeId id))
            {
                return null;
            }
            DataValue dv = await ReadAsync(id, ct).ConfigureAwait(false);
            return dv.WrappedValue.AsBoxedObject() as string;
        }

        private async Task<NodeId?> ReadNodeIdAsync(
            Dictionary<string, NodeId> props, string name, CancellationToken ct)
        {
            if (!props.TryGetValue(name, out NodeId id))
            {
                return null;
            }
            DataValue dv = await ReadAsync(id, ct).ConfigureAwait(false);
            return dv.WrappedValue.AsBoxedObject() is NodeId n ? n : null;
        }

        private async Task<int> ReadInt32Async(
            Dictionary<string, NodeId> props, string name, CancellationToken ct)
        {
            if (!props.TryGetValue(name, out NodeId id))
            {
                return 0;
            }
            DataValue dv = await ReadAsync(id, ct).ConfigureAwait(false);
            object? v = dv.WrappedValue.AsBoxedObject();
            return v == null ? 0
                : System.Convert.ToInt32(v, System.Globalization.CultureInfo.InvariantCulture);
        }

        private async Task<double> ReadDoubleAsync(
            Dictionary<string, NodeId> props, string name, double fallback, CancellationToken ct)
        {
            if (!props.TryGetValue(name, out NodeId id))
            {
                return fallback;
            }
            DataValue dv = await ReadAsync(id, ct).ConfigureAwait(false);
            object? v = dv.WrappedValue.AsBoxedObject();
            return v == null ? fallback
                : System.Convert.ToDouble(v, System.Globalization.CultureInfo.InvariantCulture);
        }
    }
}
