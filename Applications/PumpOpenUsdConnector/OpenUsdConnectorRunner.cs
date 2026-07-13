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
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Opc.Ua;
using Opc.Ua.Client;

namespace PumpOpenUsdConnector
{
    /// <summary>
    /// Runs the generic <see cref="OpenUsdConnector"/>: connects to a running OPC UA
    /// server (e.g. PumpDeviceIntegrationServer), discovers the OpenUSD representation
    /// and bindings via <c>Server/OpenUSD/Representations</c>, and streams live values
    /// into a <see cref="UsdFileSink"/> (an override <c>live.usda</c>). Invoked as
    /// <c>PumpOpenUsdConnector [--server &lt;url&gt;] [--out &lt;live.usda&gt;] [--seconds N]</c>.
    /// </summary>
    public static class OpenUsdConnectorRunner
    {
        public static async Task<int> RunAsync(string[] args)
        {
            string server = GetOption(args, "--server")
                ?? "opc.tcp://localhost:62542/PumpDeviceIntegrationServer";
            string outPath = GetOption(args, "--out") ?? Path.Combine(Environment.CurrentDirectory, "live.usda");
            int seconds = int.TryParse(GetOption(args, "--seconds"), out int s) ? s : 0;

            ITelemetryContext telemetry = DefaultTelemetry.Create(b => b.SetMinimumLevel(LogLevel.Warning));

            string pkiRoot = Path.Combine(Path.GetTempPath(), "PumpOpenUsdConnector", Path.GetRandomFileName());
            var config = new ApplicationConfiguration(telemetry)
            {
                ApplicationName = "PumpOpenUsdConnector",
                ApplicationUri = "urn:localhost:OPCFoundation:PumpOpenUsdConnector",
                ApplicationType = ApplicationType.Client,
                SecurityConfiguration = new SecurityConfiguration
                {
                    ApplicationCertificate = new CertificateIdentifier
                    {
                        StoreType = CertificateStoreType.Directory,
                        StorePath = Path.Combine(pkiRoot, "own"),
                        SubjectName = "CN=PumpOpenUsdConnector, O=OPC Foundation"
                    },
                    TrustedIssuerCertificates = new CertificateTrustList
                    {
                        StoreType = CertificateStoreType.Directory,
                        StorePath = Path.Combine(pkiRoot, "issuer")
                    },
                    TrustedPeerCertificates = new CertificateTrustList
                    {
                        StoreType = CertificateStoreType.Directory,
                        StorePath = Path.Combine(pkiRoot, "trusted")
                    },
                    RejectedCertificateStore = new CertificateTrustList
                    {
                        StoreType = CertificateStoreType.Directory,
                        StorePath = Path.Combine(pkiRoot, "rejected")
                    },
                    AutoAcceptUntrustedCertificates = true
                },
                TransportQuotas = new TransportQuotas { MaxMessageSize = 4 * 1024 * 1024 },
                ClientConfiguration = new ClientConfiguration(),
                ServerConfiguration = new ServerConfiguration()
            };
            await config.ValidateAsync(ApplicationType.Client).ConfigureAwait(false);

            var appInstance = new Opc.Ua.Configuration.ApplicationInstance(config, telemetry);
            await appInstance.CheckApplicationInstanceCertificatesAsync(true).ConfigureAwait(false);
            await appInstance.DisposeAsync().ConfigureAwait(false);
            config.CertificateManager ??= CertificateManagerFactory.Create(config.SecurityConfiguration, telemetry);
            config.CertificateManager.AcceptError = static (cert, err) => true;

            Console.WriteLine($"Connecting to {server} ...");
            EndpointDescription? endpointDescription = null;
            for (int attempt = 0; attempt < 40 && endpointDescription == null; attempt++)
            {
                try
                {
                    endpointDescription = await CoreClientUtils.SelectEndpointAsync(
                        config, server, useSecurity: false, telemetry, CancellationToken.None)
                        .ConfigureAwait(false);
                }
                catch (Exception)
                {
                    await Task.Delay(500).ConfigureAwait(false);
                }
            }
            if (endpointDescription == null)
            {
                Console.Error.WriteLine("ERROR: could not reach the server endpoint. Is the server running?");
                return 2;
            }

            var endpoint = new ConfiguredEndpoint(null, endpointDescription, EndpointConfiguration.Create(config));
            var sessionFactory = new DefaultSessionFactory(telemetry);
            ISession session = await sessionFactory.CreateAsync(
                config, endpoint, updateBeforeConnect: false,
                sessionName: "PumpOpenUsdConnector", sessionTimeout: 60000,
                identity: new UserIdentity(new AnonymousIdentityToken()),
                preferredLocales: default, ct: CancellationToken.None).ConfigureAwait(false);

            var sink = new UsdFileSink(outPath);
            var connector = new OpenUsdConnector(session, sink);
            await connector.StartAsync(CancellationToken.None).ConfigureAwait(false);
            Console.WriteLine($"Streaming live OPC UA values into {outPath}. Press Ctrl+C to stop.");

            using var stop = new SemaphoreSlim(0, 1);
            ConsoleCancelEventHandler handler = (_, e) => { e.Cancel = true; stop.Release(); };
            Console.CancelKeyPress += handler;
            try
            {
                if (seconds > 0)
                {
                    await Task.Delay(TimeSpan.FromSeconds(seconds)).ConfigureAwait(false);
                }
                else
                {
                    await stop.WaitAsync().ConfigureAwait(false);
                }
            }
            finally
            {
                Console.CancelKeyPress -= handler;
            }

            await connector.StopAsync().ConfigureAwait(false);
            await session.CloseAsync(CancellationToken.None).ConfigureAwait(false);
            await session.DisposeAsync().ConfigureAwait(false);
            (config.CertificateManager as IDisposable)?.Dispose();
            Console.WriteLine($"Stopped. Final override layer: {outPath}");
            return 0;
        }

        private static string? GetOption(string[] args, string name)
        {
            for (int i = 0; i < args.Length - 1; i++)
            {
                if (string.Equals(args[i], name, StringComparison.OrdinalIgnoreCase))
                {
                    return args[i + 1];
                }
            }
            return null;
        }
    }
}
