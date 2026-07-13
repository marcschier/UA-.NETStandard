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
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using NUnit.Framework;
using Opc.Ua.Client;
using PumpDeviceIntegrationBridge;

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
                Assert.That(sink.WasWritten("/Plant/Pumps/P101/Impeller", "xformOp:rotateZ"), Is.True,
                    "Rotation binding produced no value.");
                Assert.That(sink.WasWritten("/Plant/Pumps/P101/Body", "primvars:displayColor"), Is.True,
                    "DisplayColor binding produced no value.");
                Assert.That(sink.WasWritten("/Plant/Pumps/P101/StatusLight/Mat/Surface", "inputs:emissiveColor"), Is.True,
                    "EmissiveColor binding produced no value.");
                Assert.That(sink.TotalWrites, Is.GreaterThan(0));
            });
        }
    }
}
