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
using Microsoft.Extensions.Logging;
using Opc.Ua;
using Opc.Ua.OpenUsd;
using Opc.Ua.Pumps;
using Opc.Ua.Server;
using Opc.Ua.Server.NodeManager;

namespace Pumps
{
    /// <summary>
    /// Wires the draft OPC UA — OpenUSD Bindings composition/aggregation model
    /// (spec §5.12–5.14) onto the server: the pump composed 1:1 of Impeller and
    /// Bearing component Objects (child prims), and a ProductionLine aggregating
    /// 1..n pumps (Many, instanceable) with a dynamically added/removed pump
    /// (model-change events) and a cross-server component (federation).
    /// </summary>
    public partial class PumpNodeManager
    {
        private BaseObjectState? m_productionLine;
        private FolderState? m_linePumps;
        private NodeId? m_dynamicPumpNodeId;
        private const string LinePrimPath = "/Plant/Line1";

        // 1:1 (Child): create Impeller + Bearing component Objects on the pump, each
        // with its own representation, and declare One <Component> bindings.
        private void AttachPumpComponents(PumpState pump, OpenUsdRepresentationState pumpRep, ushort ns)
        {
            (BaseObjectState _, OpenUsdRepresentationState impellerRep) = CreateRepresentedComponent(
                pump, "Impeller", pump.BrowseName.NamespaceIndex, "/Plant/Pumps/P101/Impeller", ns);
            (BaseObjectState _, OpenUsdRepresentationState bearingRep) = CreateRepresentedComponent(
                pump, "Bearing", pump.BrowseName.NamespaceIndex, "/Plant/Pumps/P101/Bearing", ns);

            CreateComponentBinding(pumpRep, ns, "ImpellerComponent",
                new Guid("a1b2c3d4-0001-4000-8000-000000000001"),
                OpenUsdCardinalityEnum.One, OpenUsdCompositionArcEnum.Child,
                "/Plant/Pumps/P101/Impeller", componentRepresentation: impellerRep.NodeId);
            CreateComponentBinding(pumpRep, ns, "BearingComponent",
                new Guid("a1b2c3d4-0001-4000-8000-000000000002"),
                OpenUsdCardinalityEnum.One, OpenUsdCompositionArcEnum.Child,
                "/Plant/Pumps/P101/Bearing", componentRepresentation: bearingRep.NodeId);
        }

        // 1..n + dynamic + cross-server: a ProductionLine aggregating pumps.
        private async ValueTask MaterialiseProductionLineAsync(CancellationToken cancellationToken)
        {
            if (m_plantStage == null)
            {
                return;
            }
            try
            {
                ushort ns = (ushort)Server.NamespaceUris.GetIndex(Opc.Ua.OpenUsd.Namespaces.OpenUSD);
                NodeState? deviceSet = PredefinedNodes.FindById(NodeId.Create(
                    Opc.Ua.Di.Objects.DeviceSet, DiNamespaceUri, Server.NamespaceUris));
                if (deviceSet == null)
                {
                    return;
                }

                var line = new BaseObjectState(deviceSet)
                {
                    SymbolicName = "ProductionLine",
                    BrowseName = new QualifiedName("ProductionLine", ns),
                    DisplayName = new LocalizedText("ProductionLine"),
                    ReferenceTypeId = ReferenceTypeIds.HasComponent,
                    TypeDefinitionId = Opc.Ua.ObjectTypeIds.BaseObjectType
                };
                deviceSet.AddChild(line);
                line.NodeId = SystemContext.NodeIdFactory.New(SystemContext, line);

                OpenUsdRepresentationState lineRep = SystemContext.CreateInstanceOfOpenUsdRepresentationType(
                    line, new QualifiedName("OpenUsdRepresentation", ns));
                lineRep.ReferenceTypeId = ReferenceTypeIds.HasComponent;
                line.AddChild(lineRep);
                lineRep.NodeId = SystemContext.NodeIdFactory.New(SystemContext, lineRep);
                lineRep.CreateOrReplaceStage(SystemContext, null!).Value = m_plantStage.NodeId;
                lineRep.CreateOrReplacePrimPath(SystemContext, null!).Value = LinePrimPath;

                var pumps = new FolderState(line)
                {
                    SymbolicName = "Pumps",
                    BrowseName = new QualifiedName("Pumps", ns),
                    DisplayName = new LocalizedText("Pumps"),
                    ReferenceTypeId = ReferenceTypeIds.Organizes,
                    TypeDefinitionId = Opc.Ua.ObjectTypeIds.FolderType
                };
                line.AddChild(pumps);
                pumps.NodeId = SystemContext.NodeIdFactory.New(SystemContext, pumps);
                m_linePumps = pumps;

                // Two static aggregated pumps (1..n baseline).
                CreateRepresentedComponent(pumps, "P-201", ns,
                    LinePrimPath + "/Pumps/P_201", ns, ReferenceTypeIds.Organizes);
                CreateRepresentedComponent(pumps, "P-202", ns,
                    LinePrimPath + "/Pumps/P_202", ns, ReferenceTypeIds.Organizes);

                // Many <Component>: aggregate the Pumps as instanceable references, dynamic.
                CreateComponentBinding(lineRep, ns, "PumpsAggregation",
                    new Guid("a1b2c3d4-0002-4000-8000-000000000001"),
                    OpenUsdCardinalityEnum.Many, OpenUsdCompositionArcEnum.Instance,
                    LinePrimPath + "/Pumps",
                    assetReference: "@pump.usda@</Pump>", dynamic: true,
                    changeEventSource: Opc.Ua.ObjectIds.Server);

                // Cross-server <Component>: an OEM pump on another server (federation).
                CreateComponentBinding(lineRep, ns, "RemotePumpComponent",
                    new Guid("a1b2c3d4-0003-4000-8000-000000000001"),
                    OpenUsdCardinalityEnum.One, OpenUsdCompositionArcEnum.Reference,
                    LinePrimPath + "/RemotePump",
                    assetReference: "@remote-pump.usda@</Pump>",
                    componentServerUri: RemoteServerUri, componentEndpointUrl: RemoteEndpointUrl);

                AssignChildNodeIds(line);
                await AddPredefinedNodeAsync(SystemContext, line, cancellationToken).ConfigureAwait(false);

                // Register the line representation in the discovery registry.
                FolderState? registry = m_openUsdRoot?.Representations;
                if (registry != null)
                {
                    registry.AddReference(ReferenceTypeIds.Organizes, false, lineRep.NodeId);
                    lineRep.AddReference(ReferenceTypeIds.Organizes, true, registry.NodeId);
                }

                // Dynamic composition: emit model-change events on runtime add/remove.
                ModelChangeEmissionEnabled = true;
                _ = RunDynamicCompositionAsync(ns);

                m_productionLine = line;
                m_logger.LogInformation("Materialised ProductionLine (aggregates 1..n pumps).");
            }
            catch (Exception ex)
            {
                m_logger.LogError(ex, "Failed to materialise the ProductionLine.");
            }
        }

        // The cross-server component points at this same server process (a loopback
        // stand-in for an OEM sub-asset server); a test overrides RemoteEndpointUrl.
        private static string RemoteServerUri => "urn:localhost:OPCFoundation:PumpDeviceIntegrationServer";
        private string RemoteEndpointUrl { get; set; } =
            "opc.tcp://localhost:62810/PumpDeviceIntegrationServer";

        // Dynamic demo (§5.13): repeatedly add a pump (emits a GeneralModelChange),
        // hold, then remove it (emits again), so a connector observes both the add and
        // the remove regardless of when it connects. Bounded so the server quiesces.
        private async Task RunDynamicCompositionAsync(ushort ns)
        {
            try
            {
                for (int i = 0; i < 40; i++)
                {
                    await Task.Delay(3000).ConfigureAwait(false);
                    m_dynamicPumpNodeId = await AddLinePumpAsync("P-203",
                        LinePrimPath + "/Pumps/P_203", ns).ConfigureAwait(false);
                    await Task.Delay(3000).ConfigureAwait(false);
                    if (m_dynamicPumpNodeId != null)
                    {
                        await DeleteNodeAsync(SystemContext, (NodeId)m_dynamicPumpNodeId, CancellationToken.None)
                            .ConfigureAwait(false);
                        m_dynamicPumpNodeId = null;
                    }
                }
            }
            catch (Exception ex)
            {
                m_logger.LogWarning(ex, "Dynamic composition demo failed.");
            }
        }

        private async Task<NodeId?> AddLinePumpAsync(string name, string primPath, ushort ns)
        {
            if (m_linePumps == null)
            {
                return null;
            }
            var pump = new BaseObjectState(null)
            {
                SymbolicName = name,
                BrowseName = new QualifiedName(name, ns),
                DisplayName = new LocalizedText(name),
                TypeDefinitionId = Opc.Ua.ObjectTypeIds.BaseObjectType
            };
            OpenUsdRepresentationState rep = SystemContext.CreateInstanceOfOpenUsdRepresentationType(
                pump, new QualifiedName("OpenUsdRepresentation", ns));
            rep.ReferenceTypeId = ReferenceTypeIds.HasComponent;
            pump.AddChild(rep);
            rep.CreateOrReplaceStage(SystemContext, null!).Value = m_plantStage!.NodeId;
            rep.CreateOrReplacePrimPath(SystemContext, null!).Value = primPath;

            NodeId newId = await CreateNodeAsync(SystemContext, m_linePumps.NodeId,
                ReferenceTypeIds.Organizes, new QualifiedName(name, ns), pump, CancellationToken.None)
                .ConfigureAwait(false);
            return newId;
        }

        private (BaseObjectState, OpenUsdRepresentationState) CreateRepresentedComponent(
            NodeState parent, string name, ushort objNs, string primPath, ushort openUsdNs,
            NodeId? refType = null)
        {
            var obj = new BaseObjectState(parent)
            {
                SymbolicName = name,
                BrowseName = new QualifiedName(name, objNs),
                DisplayName = new LocalizedText(name),
                ReferenceTypeId = refType ?? ReferenceTypeIds.HasComponent,
                TypeDefinitionId = Opc.Ua.ObjectTypeIds.BaseObjectType
            };
            parent.AddChild(obj);
            obj.NodeId = SystemContext.NodeIdFactory.New(SystemContext, obj);

            OpenUsdRepresentationState rep = SystemContext.CreateInstanceOfOpenUsdRepresentationType(
                obj, new QualifiedName("OpenUsdRepresentation", openUsdNs));
            rep.ReferenceTypeId = ReferenceTypeIds.HasComponent;
            obj.AddChild(rep);
            rep.NodeId = SystemContext.NodeIdFactory.New(SystemContext, rep);
            rep.CreateOrReplaceStage(SystemContext, null!).Value = m_plantStage!.NodeId;
            rep.CreateOrReplacePrimPath(SystemContext, null!).Value = primPath;
            AssignChildNodeIds(obj);
            return (obj, rep);
        }

        private void CreateComponentBinding(
            OpenUsdRepresentationState rep, ushort ns, string name, Guid bindingDefinitionId,
            OpenUsdCardinalityEnum cardinality, OpenUsdCompositionArcEnum arc, string targetPrimPath,
            NodeId? componentRepresentation = null, string? assetReference = null,
            bool dynamic = false, NodeId? changeEventSource = null,
            string? componentServerUri = null, string? componentEndpointUrl = null,
            NodeId? componentTypeDefinition = null)
        {
            OpenUsdComponentBindingState b = rep.AddxComponent_(SystemContext, new QualifiedName(name, ns));
            b.CreateOrReplaceBindingDefinitionId(SystemContext, null!).Value = new Uuid(bindingDefinitionId);
            b.CreateOrReplaceEnabled(SystemContext, null!).Value = true;
            b.CreateOrReplaceCardinality(SystemContext, null!).Value = cardinality;
            b.CreateOrReplaceCompositionArc(SystemContext, null!).Value = arc;
            b.CreateOrReplaceTargetPrimPath(SystemContext, null!).Value = targetPrimPath;

            if (componentRepresentation != null)
            {
                b.CreateOrReplaceComponentRepresentation(SystemContext,
                    SystemContext.CreateOpenUsdComponentBindingType_ComponentRepresentation(b, forInstance: true))
                    .Value = (NodeId)componentRepresentation;
            }
            if (!string.IsNullOrEmpty(assetReference))
            {
                b.CreateOrReplaceComponentAssetReference(SystemContext,
                    SystemContext.CreateOpenUsdComponentBindingType_ComponentAssetReference(b, forInstance: true))
                    .Value = assetReference;
            }
            if (dynamic)
            {
                b.CreateOrReplaceDynamic(SystemContext,
                    SystemContext.CreateOpenUsdComponentBindingType_Dynamic(b, forInstance: true))
                    .Value = true;
            }
            if (changeEventSource != null)
            {
                b.CreateOrReplaceChangeEventSource(SystemContext,
                    SystemContext.CreateOpenUsdComponentBindingType_ChangeEventSource(b, forInstance: true))
                    .Value = (NodeId)changeEventSource;
            }
            if (!string.IsNullOrEmpty(componentServerUri))
            {
                b.CreateOrReplaceComponentServerUri(SystemContext,
                    SystemContext.CreateOpenUsdComponentBindingType_ComponentServerUri(b, forInstance: true))
                    .Value = componentServerUri;
            }
            if (!string.IsNullOrEmpty(componentEndpointUrl))
            {
                b.CreateOrReplaceComponentEndpointUrl(SystemContext,
                    SystemContext.CreateOpenUsdComponentBindingType_ComponentEndpointUrl(b, forInstance: true))
                    .Value = componentEndpointUrl;
            }
            if (componentTypeDefinition != null)
            {
                b.CreateOrReplaceComponentTypeDefinition(SystemContext,
                    SystemContext.CreateOpenUsdComponentBindingType_ComponentTypeDefinition(b, forInstance: true))
                    .Value = (NodeId)componentTypeDefinition;
            }
        }
    }
}
