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

namespace PumpOpenUsdConnector
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
        private readonly ushort m_ns;
        private readonly NodeId m_representationTypeId;
        private readonly NodeId m_bindingTypeId;
        private Subscription? m_subscription;

        public OpenUsdConnector(ISession session, IUsdSink sink)
        {
            m_session = session;
            m_sink = sink;
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
                    Kind = (OpenUsdRenderTargetKind)await ReadInt32Async(bp, "RenderTargetKind", ct)
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
