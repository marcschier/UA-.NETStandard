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
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Opc.Ua;
using Opc.Ua.Client;

namespace PumpDeviceIntegrationBridge
{
    /// <summary>
    /// Generic OPC UA — OpenUSD connector. It discovers an
    /// <c>OpenUsdRepresentation</c> and its live bindings through the Part 1
    /// <c>Server/OpenUSD/Representations</c> registry, subscribes to the bound
    /// source Variables, applies the declared conversion, and writes the target
    /// USD attributes into an <see cref="IUsdSink"/>. It is domain-agnostic — it
    /// knows only the OpenUSD binding model, never "pump".
    /// </summary>
    public sealed class OpenUsdConnector
    {
        private readonly ISession m_session;
        private readonly IUsdSink m_sink;
        private readonly bool m_enableCommands;
        private readonly ushort m_ns;
        private readonly NodeId m_representationTypeId;
        private readonly NodeId m_bindingTypeId;
        private Subscription? m_subscription;

        public OpenUsdConnector(ISession session, IUsdSink sink)
            : this(session, sink, enableCommands: false)
        {
        }

        // enableCommands is the opt-in gate for UsdToUaCommand bindings. Command
        // bindings are always DISCOVERED, but the connector refuses to actuate one
        // unless explicitly enabled (fail-closed); read-only telemetry/alarm/history
        // bindings are unaffected.
        public OpenUsdConnector(ISession session, IUsdSink sink, bool enableCommands)
        {
            m_session = session;
            m_sink = sink;
            m_enableCommands = enableCommands;
            m_ns = (ushort)m_session.NamespaceUris.GetIndex(OpenUsdModel.NamespaceUri);
            m_representationTypeId = new NodeId(1003u, m_ns);
            m_bindingTypeId = new NodeId(1004u, m_ns);
        }

        public sealed class BindingInfo
        {
            public NodeId? SourceNodeId { get; set; }
            public string? PrimPath { get; set; }
            public string? PropertyName { get; set; }
            public OpenUsdRenderTargetKind Kind { get; set; }
            public double Scale { get; set; } = 1.0;
            public OpenUsdIntentProfile Intent { get; set; } = OpenUsdIntentProfile.UaToUsdTelemetry;
            public OpenUsdSignalRole SignalRole { get; set; } = OpenUsdSignalRole.Observable;
            public string? SourceSemanticId { get; set; }
            public OpenUsdAlarmAspect? AlarmAspect { get; set; }
            public bool TimeSampled { get; set; }
            public NodeId? CommandTargetNodeId { get; set; }
            public string? CommandTriggerPropertyName { get; set; }
        }

        public sealed class RepresentationInfo
        {
            public NodeId? NodeId { get; set; }
            public NodeId? StageNodeId { get; set; }
            public string? PrimPath { get; set; }
            public string? RootLayerIdentifier { get; set; }
            public byte[]? RootLayerDigest { get; set; }
            public OpenUsdDigestAlgorithm DigestAlgorithm { get; set; } = OpenUsdDigestAlgorithm.None;
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
                info.RootLayerDigest =
                    await ReadByteStringAsync(stageProps, "RootLayerDigest", ct).ConfigureAwait(false);
                info.DigestAlgorithm = (OpenUsdDigestAlgorithm)await ReadInt32Async(
                    stageProps, "RootLayerDigestAlgorithm", ct).ConfigureAwait(false);
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
                    Kind = (OpenUsdRenderTargetKind)await ReadInt32Async(bp, "RenderTargetKind", ct)
                        .ConfigureAwait(false),
                    Scale = await ReadDoubleAsync(bp, "Scale", 1.0, ct).ConfigureAwait(false),
                    Intent = (OpenUsdIntentProfile)await ReadInt32Async(bp, "IntentProfile", ct)
                        .ConfigureAwait(false),
                    SignalRole = (OpenUsdSignalRole)await ReadInt32Async(bp, "SignalRole", ct)
                        .ConfigureAwait(false),
                    SourceSemanticId = await ReadStringAsync(bp, "SourceSemanticId", ct)
                        .ConfigureAwait(false),
                    TimeSampled = await ReadBoolAsync(bp, "TimeSampled", ct).ConfigureAwait(false),
                    CommandTargetNodeId = await ReadNodeIdAsync(bp, "CommandTargetNodeId", ct)
                        .ConfigureAwait(false),
                    CommandTriggerPropertyName = await ReadStringAsync(bp, "CommandTriggerPropertyName", ct)
                        .ConfigureAwait(false)
                };
                if (bp.ContainsKey("AlarmAspect"))
                {
                    b.AlarmAspect = (OpenUsdAlarmAspect)await ReadInt32Async(bp, "AlarmAspect", ct)
                        .ConfigureAwait(false);
                }
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

            // Twin-BOM integrity (0.2): if the stage advertises a content digest,
            // verify it before authoring any opinions into the stage. A mismatch is
            // fail-closed — we do not compose an unverified stage.
            if (rep.RootLayerDigest is { Length: > 0 }
                && rep.DigestAlgorithm != OpenUsdDigestAlgorithm.None
                && !VerifyStageDigest(rep))
            {
                throw new InvalidOperationException(
                    "OpenUSD stage RootLayerDigest verification failed — refusing to compose.");
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
                // Command bindings are actuated on demand (IssueCommandAsync), and
                // history bindings are replayed via ReplayHistoryAsync — neither is a
                // live MonitoredItem. Telemetry and alarm bindings subscribe here.
                if (b.SourceNodeId == null
                    || b.Intent == OpenUsdIntentProfile.UsdToUaCommand
                    || b.Intent == OpenUsdIntentProfile.UaHistoryToUsd)
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

        /// <summary>
        /// Applies the binding's declared <see cref="OpenUsdRenderTargetKind"/> to a
        /// raw source value, returning the USD-side value (double for scalars, a
        /// three-float array for colours, a token for visibility).
        /// </summary>
        public static object? Convert(BindingInfo b, object raw)
        {
            double d = ToDouble(raw);
            switch (b.Kind)
            {
                case OpenUsdRenderTargetKind.Rotation:
                case OpenUsdRenderTargetKind.Translation:
                case OpenUsdRenderTargetKind.Scale:
                case OpenUsdRenderTargetKind.Opacity:
                    return d * b.Scale;
                case OpenUsdRenderTargetKind.DisplayColor:
                    // Temperature: blue (cool) -> red (hot).
                    double t = System.Math.Max(0.0, System.Math.Min(1.0, (d - 20.0) / 80.0));
                    return new[] { (float)t, 0f, (float)(1.0 - t) };
                case OpenUsdRenderTargetKind.EmissiveColor:
                    // Pressure: dark -> bright green-white glow.
                    double e = System.Math.Max(0.0, System.Math.Min(1.0, d / 6.0));
                    return new[] { (float)(0.1 * e), (float)e, (float)(0.2 * e) };
                case OpenUsdRenderTargetKind.Visibility:
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

        /// <summary>
        /// Verifies the stage's advertised RootLayerDigest (Twin-BOM integrity).
        /// The demo server digests the RootLayerIdentifier as a deterministic
        /// stand-in; a production connector digests the resolved root-layer bytes.
        /// </summary>
        public bool VerifyStageDigest(RepresentationInfo rep)
        {
            if (rep.RootLayerDigest == null || rep.RootLayerDigest.Length == 0
                || rep.DigestAlgorithm == OpenUsdDigestAlgorithm.None
                || string.IsNullOrEmpty(rep.RootLayerIdentifier))
            {
                return false;
            }
            byte[] computed = ComputeDigest(rep.DigestAlgorithm, rep.RootLayerIdentifier!);
            return FixedTimeEquals(computed, rep.RootLayerDigest);
        }

        /// <summary>
        /// Actuates the single opt-in UsdToUaCommand binding by writing the supplied
        /// value to its CommandTargetNodeId. Fail-closed: throws when commands were
        /// not explicitly enabled. Single-writer: uses the first controllable command
        /// binding found. Returns true when the UA write succeeds.
        /// </summary>
        public async Task<bool> IssueCommandAsync(double value, CancellationToken ct)
        {
            if (!m_enableCommands)
            {
                throw new InvalidOperationException(
                    "Command bindings are disabled. Construct the connector with enableCommands: true.");
            }
            RepresentationInfo? rep = await DiscoverRepresentationAsync(ct).ConfigureAwait(false);
            BindingInfo? cmd = null;
            if (rep != null)
            {
                foreach (BindingInfo b in rep.Bindings)
                {
                    if (b.Intent == OpenUsdIntentProfile.UsdToUaCommand
                        && b.SignalRole == OpenUsdSignalRole.Controllable
                        && b.CommandTargetNodeId != null)
                    {
                        cmd = b;
                        break;
                    }
                }
            }
            if (cmd?.CommandTargetNodeId == null)
            {
                return false;
            }
            StatusCode sc = await WriteAsync(cmd.CommandTargetNodeId.Value, value, ct)
                .ConfigureAwait(false);
            return StatusCode.IsGood(sc);
        }

        /// <summary>
        /// Replays history (Part 11 HistoryRead) for every UaHistoryToUsd binding,
        /// authoring returned values as USD time samples through the sink. Returns the
        /// number of samples authored. Sources that do not historize yield 0 without
        /// throwing (a documented degrade — history binding requires a historizing source).
        /// </summary>
        public async Task<int> ReplayHistoryAsync(DateTime startTime, DateTime endTime, CancellationToken ct)
        {
            RepresentationInfo? rep = await DiscoverRepresentationAsync(ct).ConfigureAwait(false);
            if (rep == null)
            {
                return 0;
            }
            int authored = 0;
            foreach (BindingInfo b in rep.Bindings)
            {
                if (b.Intent != OpenUsdIntentProfile.UaHistoryToUsd || b.SourceNodeId == null)
                {
                    continue;
                }
                var details = new ReadRawModifiedDetails
                {
                    IsReadModified = false,
                    StartTime = startTime,
                    EndTime = endTime,
                    NumValuesPerNode = 0,
                    ReturnBounds = false
                };
                var toRead = new HistoryReadValueId[]
                {
                    new HistoryReadValueId { NodeId = b.SourceNodeId.Value }
                };
                HistoryReadResponse resp;
                try
                {
                    resp = await m_session.HistoryReadAsync(
                        null!, new ExtensionObject(details), TimestampsToReturn.Source,
                        false, toRead, ct).ConfigureAwait(false);
                }
                catch (ServiceResultException)
                {
                    continue; // Source does not support history — graceful degrade.
                }
                HistoryReadResult r = resp.Results[0];
                if (StatusCode.IsNotGood(r.StatusCode))
                {
                    continue;
                }
                if (ExtensionObject.ToEncodeable(r.HistoryData) is HistoryData hd)
                {
                    foreach (DataValue dv in hd.DataValues)
                    {
                        object? raw = dv.WrappedValue.AsBoxedObject();
                        if (raw == null || StatusCode.IsNotGood(dv.StatusCode))
                        {
                            continue;
                        }
                        object? usd = Convert(b, raw);
                        if (usd != null && b.TimeSampled)
                        {
                            m_sink.SetTimeSample(b.PrimPath!, b.PropertyName!,
                                dv.SourceTimestamp.ToDateTime(), usd);
                            authored++;
                        }
                    }
                }
            }
            return authored;
        }

        private static byte[] ComputeDigest(OpenUsdDigestAlgorithm algorithm, string identifier)
        {
            byte[] bytes = System.Text.Encoding.UTF8.GetBytes(identifier);
            // ComputeHash (not the static HashData) is used for netstandard2.0/net48
            // compatibility where the static overloads do not exist.
#pragma warning disable CA1850 // Prefer static HashData
            switch (algorithm)
            {
                case OpenUsdDigestAlgorithm.Sha256:
                    using (var h = System.Security.Cryptography.SHA256.Create())
                    {
                        return h.ComputeHash(bytes);
                    }
                case OpenUsdDigestAlgorithm.Sha384:
                    using (var h = System.Security.Cryptography.SHA384.Create())
                    {
                        return h.ComputeHash(bytes);
                    }
                case OpenUsdDigestAlgorithm.Sha512:
                    using (var h = System.Security.Cryptography.SHA512.Create())
                    {
                        return h.ComputeHash(bytes);
                    }
                default:
                    return System.Array.Empty<byte>();
            }
#pragma warning restore CA1850
        }

        private static bool FixedTimeEquals(byte[] a, byte[] b)
        {
            if (a.Length != b.Length)
            {
                return false;
            }
            int diff = 0;
            for (int i = 0; i < a.Length; i++)
            {
                diff |= a[i] ^ b[i];
            }
            return diff == 0;
        }

        private async Task<StatusCode> WriteAsync(NodeId nodeId, double value, CancellationToken ct)
        {
            var toWrite = new WriteValue[]
            {
                new WriteValue
                {
                    NodeId = nodeId,
                    AttributeId = Attributes.Value,
                    Value = new DataValue(new Variant(value))
                }
            };
            WriteResponse resp = await m_session.WriteAsync(null!, toWrite, ct).ConfigureAwait(false);
            return resp.Results.Count > 0
                ? resp.Results[0]
                : (StatusCode)StatusCodes.BadUnexpectedError;
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

        private async Task<bool> ReadBoolAsync(
            Dictionary<string, NodeId> props, string name, CancellationToken ct)
        {
            if (!props.TryGetValue(name, out NodeId id))
            {
                return false;
            }
            DataValue dv = await ReadAsync(id, ct).ConfigureAwait(false);
            object? v = dv.WrappedValue.AsBoxedObject();
            return v != null
                && System.Convert.ToBoolean(v, System.Globalization.CultureInfo.InvariantCulture);
        }

        private async Task<byte[]?> ReadByteStringAsync(
            Dictionary<string, NodeId> props, string name, CancellationToken ct)
        {
            if (!props.TryGetValue(name, out NodeId id))
            {
                return null;
            }
            DataValue dv = await ReadAsync(id, ct).ConfigureAwait(false);
            object? v = dv.WrappedValue.AsBoxedObject();
            return v switch
            {
                byte[] ba => ba,
                ByteString bs => bs.ToArray(),
                _ => null
            };
        }
    }
}
