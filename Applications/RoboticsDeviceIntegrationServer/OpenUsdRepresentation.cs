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
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Opc.Ua;
using Opc.Ua.OpenUsd;
using OpenUsdShared;

namespace Robotics
{
    /// <summary>
    /// Wires the draft OPC UA — OpenUSD Bindings companion model onto the Robotics
    /// server: the well-known OpenUSD facility (stage + representation registries),
    /// a RobotCellStage descriptor, and the generic representation/binding helpers
    /// used by RobotCell.cs.
    /// </summary>
    public partial class RoboticsNodeManager
    {
        private OpenUsdRootState? m_openUsdRoot;
        private OpenUsdStageState? m_cellStage;

        private const string CellRootLayerIdentifier = "asset-repo/Cell.usd";

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

                m_cellStage = SystemContext.CreateInstanceOfOpenUsdStageType(
                    stages, new QualifiedName("RobotCellStage", ns));
                stages.AddChild(m_cellStage);
                m_cellStage.CreateOrReplaceRootLayerIdentifier(SystemContext, null!)
                    .Value = CellRootLayerIdentifier;

                // 0.2 Twin-BOM content integrity: publish a deterministic digest of the
                // resolved root layer identity so a connector can verify the stage
                // before composing it. A production server digests the actual resolved
                // bytes; here we digest the identifier as a testable stand-in.
                byte[] digest;
#pragma warning disable CA1850 // Prefer static HashData (net48/netstandard2.0 compatibility)
                using (var sha = System.Security.Cryptography.SHA256.Create())
                {
                    digest = sha.ComputeHash(
                        System.Text.Encoding.UTF8.GetBytes(CellRootLayerIdentifier));
                }
#pragma warning restore CA1850
                m_cellStage.CreateOrReplaceRootLayerDigest(
                    SystemContext,
                    SystemContext.CreateOpenUsdStageType_RootLayerDigest(m_cellStage, forInstance: true))
                    .Value = (ByteString)digest;
                m_cellStage.CreateOrReplaceRootLayerDigestAlgorithm(
                    SystemContext,
                    SystemContext.CreateOpenUsdStageType_RootLayerDigestAlgorithm(m_cellStage, forInstance: true))
                    .Value = OpenUsdDigestAlgorithmEnum.Sha256;

                // Per the companion spec §4.2 the OpenUSD facility SHALL be a component
                // of the Server Object (i=2253) so any conformant connector can Browse
                // Server -> OpenUSD -> Representations. Record the inverse reference
                // here; the matching forward reference from the Server Object is added
                // via the externalReferences dictionary in LinkOpenUsdRootToServer.
                root.AddReference(ReferenceTypeIds.HasComponent, true, Opc.Ua.ObjectIds.Server);

                // §5.15 asset content delivery (OU-AssetDelivery): serve this stage's
                // artist-authored USD layer closure so a connector can render the twin
                // with no external asset resolver.
                UsdAssetDelivery.AttachStageAssets(SystemContext, m_cellStage, ns, LoadServedAssets());

                AssignChildNodeIds(root);
                await AddPredefinedNodeAsync(SystemContext, root, cancellationToken)
                    .ConfigureAwait(false);

                m_openUsdRoot = root;
                m_logger.LogInformation(
                    "Materialised OpenUSD facility (root {RootId}, RobotCellStage {StageId}).",
                    root.NodeId, m_cellStage.NodeId);
            }
            catch (Exception ex)
            {
                m_cellStage = null;
                m_openUsdRoot = null;
                m_logger.LogError(ex, "Failed to materialise the OpenUSD facility.");
            }
        }

        // Loads the embedded artist-authored USD layers this server serves (spec §5.15).
        private static List<ServedAsset> LoadServedAssets()
        {
            return new List<ServedAsset>
            {
                new ServedAsset("Cell.usda", OpenUsdAssetKindEnum.RootLayer, ReadEmbeddedAsset("Cell.usda")),
                new ServedAsset("robot.usda", OpenUsdAssetKindEnum.Reference, ReadEmbeddedAsset("robot.usda")),
                new ServedAsset("tool.usda", OpenUsdAssetKindEnum.Reference, ReadEmbeddedAsset("tool.usda")),
            };
        }

        private static byte[] ReadEmbeddedAsset(string resourceName)
        {
            using Stream? s = typeof(RoboticsNodeManager).Assembly.GetManifestResourceStream(resourceName);
            if (s == null)
            {
                return Array.Empty<byte>();
            }
            using var ms = new MemoryStream();
            s.CopyTo(ms);
            return ms.ToArray();
        }

        /// <inheritdoc/>
        public override async ValueTask CreateAddressSpaceAsync(
            IDictionary<NodeId, IList<IReference>> externalReferences,
            CancellationToken cancellationToken = default)
        {
            // base.CreateAddressSpaceAsync loads predefined nodes and runs
            // OnAddressSpaceReadyAsync, which materialises the OpenUSD facility.
            await base.CreateAddressSpaceAsync(externalReferences, cancellationToken)
                .ConfigureAwait(false);

            // Now that the root exists, add the forward HasComponent reference from the
            // Server Object (i=2253, owned by the core node manager) to it.
            LinkOpenUsdRootToServer(externalReferences);
        }

        private void LinkOpenUsdRootToServer(
            IDictionary<NodeId, IList<IReference>> externalReferences)
        {
            if (m_openUsdRoot == null)
            {
                return;
            }
            if (!externalReferences.TryGetValue(Opc.Ua.ObjectIds.Server, out IList<IReference>? references)
                || references == null)
            {
                externalReferences[Opc.Ua.ObjectIds.Server] = references = new List<IReference>();
            }
            references.Add(new NodeStateReference(
                ReferenceTypeIds.HasComponent, false, m_openUsdRoot.NodeId));
            m_logger.LogInformation(
                "Linked OpenUSD facility under the Server Object (i=2253).");
        }

        // Attaches an OpenUsdRepresentation AddIn to an Object and registers it in the
        // discovery registry (Server/OpenUSD/Representations, Organizes). Returns the
        // representation so the caller can add live/component bindings to it.
        private OpenUsdRepresentationState AttachRepresentation(
            NodeState owner, string primPath, ushort ns)
        {
            OpenUsdRepresentationState rep = SystemContext
                .CreateInstanceOfOpenUsdRepresentationType(
                    owner, new QualifiedName("OpenUsdRepresentation", ns));
            // The instance factory leaves ReferenceTypeId = Null; set HasComponent so
            // the AddIn is browsable from the represented object.
            rep.ReferenceTypeId = ReferenceTypeIds.HasComponent;
            owner.AddChild(rep);
            rep.NodeId = SystemContext.NodeIdFactory.New(SystemContext, rep);
            rep.CreateOrReplaceStage(SystemContext, null!).Value = m_cellStage!.NodeId;
            rep.CreateOrReplacePrimPath(SystemContext, null!).Value = primPath;
            return rep;
        }

        // Adds the Organizes reference pair between the discovery registry and a
        // representation, so a generic connector discovers it without domain knowledge.
        private void OrganiseRepresentation(OpenUsdRepresentationState rep)
        {
            FolderState? registry = m_openUsdRoot?.Representations;
            if (registry == null)
            {
                return;
            }
            registry.AddReference(ReferenceTypeIds.Organizes, false, rep.NodeId);
            rep.AddReference(ReferenceTypeIds.Organizes, true, registry.NodeId);
        }

        // Creates a simple Variable child on any Object, assigning a per-instance
        // NodeId immediately (callers assign parent NodeIds first).
        private BaseDataVariableState CreateVariable(
            NodeState parent, string name, NodeId dataType, Variant initialValue, bool writable, ushort ns)
        {
            byte access = writable
                ? AccessLevels.CurrentReadOrWrite
                : AccessLevels.CurrentRead;
            var v = new BaseDataVariableState(parent)
            {
                SymbolicName = name,
                BrowseName = new QualifiedName(name, ns),
                DisplayName = new LocalizedText(name),
                ReferenceTypeId = ReferenceTypeIds.HasComponent,
                TypeDefinitionId = VariableTypeIds.BaseDataVariableType,
                DataType = dataType,
                ValueRank = ValueRanks.Scalar,
                AccessLevel = access,
                UserAccessLevel = access,
                Value = initialValue,
            };
            parent.AddChild(v);
            v.NodeId = SystemContext.NodeIdFactory.New(SystemContext, v);
            return v;
        }

        // Creates a FolderState child on any Object.
        private FolderState CreateFolder(NodeState parent, string name, ushort ns)
        {
            var folder = new FolderState(parent)
            {
                SymbolicName = name,
                BrowseName = new QualifiedName(name, ns),
                DisplayName = new LocalizedText(name),
                ReferenceTypeId = ReferenceTypeIds.HasComponent,
                TypeDefinitionId = Opc.Ua.ObjectTypeIds.FolderType
            };
            parent.AddChild(folder);
            folder.NodeId = SystemContext.NodeIdFactory.New(SystemContext, folder);
            return folder;
        }

        // Instantiates the OpenUsdLiveBinding <Binding> placeholder as a concrete
        // browsable child of a representation and sets its members (spec §5.4/§5.10/§5.11).
        private void CreateBinding(
            OpenUsdRepresentationState rep, ushort ns, string name,
            Guid bindingDefinitionId, NodeId? sourceNodeId, string targetPrimPath,
            string targetPropertyName, string targetUsdTypeName,
            OpenUsdRenderTargetKindEnum? kind, double scale,
            OpenUsdIntentProfileEnum intentProfile = OpenUsdIntentProfileEnum.UaToUsdTelemetry,
            OpenUsdSignalRoleEnum signalRole = OpenUsdSignalRoleEnum.Observable,
            string? sourceSemanticId = null,
            OpenUsdAlarmAspectEnum? alarmAspect = null,
            NodeId? commandTargetNodeId = null,
            string? commandTriggerPropertyName = null)
        {
            OpenUsdLiveBindingState b = rep.AddxBinding_(SystemContext, new QualifiedName(name, ns));

            b.CreateOrReplaceBindingDefinitionId(SystemContext, null!).Value = new Uuid(bindingDefinitionId);
            b.CreateOrReplaceEnabled(SystemContext, null!).Value = true;
            b.CreateOrReplaceIntentProfile(SystemContext, null!).Value = intentProfile;
            b.CreateOrReplaceTargetStage(SystemContext, null!).Value = m_cellStage!.NodeId;
            b.CreateOrReplaceTargetPrimPath(SystemContext, null!).Value = targetPrimPath;
            b.CreateOrReplaceTargetPropertyName(SystemContext, null!).Value = targetPropertyName;
            b.CreateOrReplaceTargetUsdTypeName(SystemContext, null!).Value = targetUsdTypeName;

            if (sourceNodeId != null)
            {
                b.CreateOrReplaceSourceNodeId(
                    SystemContext,
                    SystemContext.CreateOpenUsdLiveBindingType_SourceNodeId(b, forInstance: true))
                    .Value = (NodeId)sourceNodeId;
            }
            b.CreateOrReplaceSignalRole(
                SystemContext,
                SystemContext.CreateOpenUsdLiveBindingType_SignalRole(b, forInstance: true))
                .Value = signalRole;
            if (!string.IsNullOrEmpty(sourceSemanticId))
            {
                b.CreateOrReplaceSourceSemanticId(
                    SystemContext,
                    SystemContext.CreateOpenUsdLiveBindingType_SourceSemanticId(b, forInstance: true))
                    .Value = sourceSemanticId;
            }
            if (alarmAspect != null)
            {
                b.CreateOrReplaceAlarmAspect(
                    SystemContext,
                    SystemContext.CreateOpenUsdLiveBindingType_AlarmAspect(b, forInstance: true))
                    .Value = alarmAspect.Value;
            }
            if (commandTargetNodeId != null)
            {
                b.CreateOrReplaceCommandTargetNodeId(
                    SystemContext,
                    SystemContext.CreateOpenUsdLiveBindingType_CommandTargetNodeId(b, forInstance: true))
                    .Value = (NodeId)commandTargetNodeId;
            }
            if (!string.IsNullOrEmpty(commandTriggerPropertyName))
            {
                b.CreateOrReplaceCommandTriggerPropertyName(
                    SystemContext,
                    SystemContext.CreateOpenUsdLiveBindingType_CommandTriggerPropertyName(b, forInstance: true))
                    .Value = commandTriggerPropertyName;
            }
            if (kind != null)
            {
                b.CreateOrReplaceRenderTargetKind(
                    SystemContext,
                    SystemContext.CreateOpenUsdLiveBindingType_RenderTargetKind(b, forInstance: true))
                    .Value = kind.Value;
            }
            b.CreateOrReplaceScale(
                SystemContext,
                SystemContext.CreateOpenUsdLiveBindingType_Scale(b, forInstance: true))
                .Value = scale;
            b.CreateOrReplaceBadQualityAction(
                SystemContext,
                SystemContext.CreateOpenUsdLiveBindingType_BadQualityAction(b, forInstance: true))
                .Value = OpenUsdBadQualityActionEnum.Skip;
        }

        // Instantiates the OpenUsdComponentBinding <Component> placeholder on a
        // representation and sets its members (spec §5.12–5.14).
        private void CreateComponentBinding(
            OpenUsdRepresentationState rep, ushort ns, string name, Guid bindingDefinitionId,
            OpenUsdCardinalityEnum cardinality, OpenUsdCompositionArcEnum arc, string targetPrimPath,
            NodeId? componentRepresentation = null, string? assetReference = null,
            bool dynamic = false, NodeId? changeEventSource = null,
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
            if (componentTypeDefinition != null)
            {
                b.CreateOrReplaceComponentTypeDefinition(SystemContext,
                    SystemContext.CreateOpenUsdComponentBindingType_ComponentTypeDefinition(b, forInstance: true))
                    .Value = (NodeId)componentTypeDefinition;
            }
        }
    }
}
