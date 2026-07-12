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

namespace Pumps
{
    /// <summary>
    /// Wires the draft OPC UA — OpenUSD Bindings companion model onto the Pumps
    /// server: the well-known OpenUSD facility (stage + representation registries),
    /// a PlantStage descriptor, and an OpenUsdRepresentation AddIn on Pump #1 with
    /// three read-only live bindings (Part 2, UaToUsdTelemetry).
    /// </summary>
    public partial class PumpNodeManager
    {
        private OpenUsdRootState? m_openUsdRoot;
        private OpenUsdStageState? m_plantStage;

        private const string PlantRootLayerIdentifier = "asset-repo/Plant.usd";
        private const string PumpPrimPath = "/Plant/Pumps/P101";

        private async ValueTask MaterialiseOpenUsdFacilityAsync(
            CancellationToken cancellationToken)
        {
            try
            {
                ushort ns = (ushort)Server.NamespaceUris.GetIndex(Opc.Ua.OpenUsd.Namespaces.OpenUSD);

                OpenUsdRootState root = SystemContext.CreateInstanceOfOpenUsdRootType(
                    null!, new QualifiedName("OpenUSD", ns));
                root.NodeId = new NodeId("OpenUSD", ns);

                FolderState stages = root.Stages
                    ?? root.CreateOrReplaceStages(SystemContext, null!);
                _ = root.Representations
                    ?? root.CreateOrReplaceRepresentations(SystemContext, null!);

                m_plantStage = SystemContext.CreateInstanceOfOpenUsdStageType(
                    stages, new QualifiedName("PlantStage", ns));
                stages.AddChild(m_plantStage);
                m_plantStage.CreateOrReplaceRootLayerIdentifier(SystemContext, null!)
                    .Value = PlantRootLayerIdentifier;

                AssignChildNodeIds(root);
                await AddPredefinedNodeAsync(SystemContext, root, cancellationToken)
                    .ConfigureAwait(false);

                m_openUsdRoot = root;
                m_logger.LogInformation(
                    "Materialised OpenUSD facility (root {RootId}, PlantStage {StageId}).",
                    root.NodeId, m_plantStage.NodeId);
            }
            catch (Exception ex)
            {
                m_plantStage = null;
                m_openUsdRoot = null;
                m_logger.LogError(ex, "Failed to materialise the OpenUSD facility.");
            }
        }

        // Call between AssignChildNodeIds(pump) and AddPredefinedNodeAsync(pump).
        private void AttachOpenUsdRepresentation(PumpState pump)
        {
            if (m_plantStage == null)
            {
                return;
            }
            ushort ns = (ushort)Server.NamespaceUris.GetIndex(Opc.Ua.OpenUsd.Namespaces.OpenUSD);

            OpenUsdRepresentationState rep = SystemContext
                .CreateInstanceOfOpenUsdRepresentationType(
                    pump, new QualifiedName("OpenUsdRepresentation", ns));
            // The instance factory leaves ReferenceTypeId = Null; set HasComponent
            // so the AddIn is browsable from the represented object.
            rep.ReferenceTypeId = ReferenceTypeIds.HasComponent;
            pump.AddChild(rep);
            rep.NodeId = SystemContext.NodeIdFactory.New(SystemContext, rep);

            rep.CreateOrReplaceStage(SystemContext, null!).Value = m_plantStage.NodeId;
            rep.CreateOrReplacePrimPath(SystemContext, null!).Value = PumpPrimPath;

            MeasurementsState? m = pump.Operational?.Measurements;
            NodeId? massFlow = m?.MassFlow?.NodeId;
            NodeId? bearingTemp = m?.BearingTemperature?.NodeId;
            NodeId? diffPressure = m?.DifferentialPressure?.NodeId;

            CreateBinding(rep, ns, "MassFlowSpin",
                new Guid("6e63cf2c-f2de-4f78-a8f8-f0ccdbb7647a"),
                massFlow, "/Plant/Pumps/P101/Impeller", "xformOp:rotateZ", "double",
                OpenUsdRenderTargetKindEnum.Rotation, 1.0);
            CreateBinding(rep, ns, "BearingTempColor",
                new Guid("b1a1f6f0-5c2b-5a1e-9f3a-2b7c4d8e0011"),
                bearingTemp, "/Plant/Pumps/P101/Body", "primvars:displayColor", "color3f",
                OpenUsdRenderTargetKindEnum.DisplayColor, 1.0);
            CreateBinding(rep, ns, "DiffPressureEmissive",
                new Guid("c2b2a7e1-6d3c-5b2f-a04b-3c8d5e9f1122"),
                diffPressure, "/Plant/Pumps/P101/StatusLight/Mat/Surface", "inputs:emissiveColor", "color3f",
                OpenUsdRenderTargetKindEnum.EmissiveColor, 1.0);

            AssignChildNodeIds(rep);
        }

        private void OrganiseRepresentation(PumpState pump)
        {
            FolderState? registry = m_openUsdRoot?.Representations;
            if (registry == null)
            {
                return;
            }
            foreach (BaseInstanceState child in EnumerateChildren(pump))
            {
                if (child is OpenUsdRepresentationState rep)
                {
                    registry.AddReference(ReferenceTypeIds.Organizes, false, rep.NodeId);
                    rep.AddReference(ReferenceTypeIds.Organizes, true, registry.NodeId);
                }
            }
        }

        private System.Collections.Generic.List<BaseInstanceState> EnumerateChildren(NodeState parent)
        {
            var children = new System.Collections.Generic.List<BaseInstanceState>();
            parent.GetChildren(SystemContext, children);
            return children;
        }

        private void CreateBinding(
            OpenUsdRepresentationState rep, ushort ns, string name,
            Guid bindingDefinitionId, NodeId? sourceNodeId, string targetPrimPath,
            string targetPropertyName, string targetUsdTypeName,
            OpenUsdRenderTargetKindEnum kind, double scale)
        {
            // AddxBinding_ instantiates the <Binding> placeholder as a concrete
            // HasComponent child (browsable) and creates its mandatory members.
            OpenUsdLiveBindingState b = rep.AddxBinding_(SystemContext, new QualifiedName(name, ns));

            // Mandatory members already exist on the instance; set their values.
            b.CreateOrReplaceBindingDefinitionId(SystemContext, null!).Value = new Uuid(bindingDefinitionId);
            b.CreateOrReplaceEnabled(SystemContext, null!).Value = true;
            b.CreateOrReplaceIntentProfile(SystemContext, null!).Value = OpenUsdIntentProfileEnum.UaToUsdTelemetry;
            b.CreateOrReplaceTargetStage(SystemContext, null!).Value = m_plantStage!.NodeId;
            b.CreateOrReplaceTargetPrimPath(SystemContext, null!).Value = targetPrimPath;
            b.CreateOrReplaceTargetPropertyName(SystemContext, null!).Value = targetPropertyName;
            b.CreateOrReplaceTargetUsdTypeName(SystemContext, null!).Value = targetUsdTypeName;

            // Optional members are not auto-created; supply a generated node so the
            // member carries a valid BrowseName/ReferenceType and is browsable.
            if (sourceNodeId != null)
            {
                b.CreateOrReplaceSourceNodeId(
                    SystemContext,
                    SystemContext.CreateOpenUsdLiveBindingType_SourceNodeId(b, forInstance: true))
                    .Value = (NodeId)sourceNodeId;
            }
            b.CreateOrReplaceRenderTargetKind(
                SystemContext,
                SystemContext.CreateOpenUsdLiveBindingType_RenderTargetKind(b, forInstance: true))
                .Value = kind;
            b.CreateOrReplaceScale(
                SystemContext,
                SystemContext.CreateOpenUsdLiveBindingType_Scale(b, forInstance: true))
                .Value = scale;
            b.CreateOrReplaceBadQualityAction(
                SystemContext,
                SystemContext.CreateOpenUsdLiveBindingType_BadQualityAction(b, forInstance: true))
                .Value = OpenUsdBadQualityActionEnum.Skip;
        }
    }
}
