/* ========================================================================
 * Copyright (c) 2005-2024 The OPC Foundation, Inc. All rights reserved.
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

using Microsoft.CodeAnalysis;
using Opc.Ua.Export;
using Opc.Ua.Schema.Model;
using Opc.Ua.Types;
using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Globalization;
using System.IO;
using System.Linq;
using SourceProductionContext = SGF.SgfSourceProductionContext;

namespace Opc.Ua.SourceGeneration
{
    /// <summary>
    /// Nodeset compiler
    /// </summary>
    internal sealed class NodesetFileCollection
    {
        /// <summary>
        /// The files in the collection
        /// </summary>
        public Dictionary<string, string> Files => m_nodesets
            .ToDictionary(x => x.Key, x => x.Value.FileName);

        /// <summary>
        /// The models in the collection
        /// </summary>
        public IEnumerable<string> ModelUris => m_nodesets.Values
            .Where(x => !x.Info.Ignore)
            .Select(x => x.Info.ModelUri)
            .Where(x => !string.IsNullOrEmpty(x));

        /// <summary>
        /// Create collection
        /// </summary>
        public NodesetFileCollection(
            ImmutableArray<(AdditionalText, NodesetOptions)> nodeset2Files,
            SourceProductionContext context,
            IFileSystem fileSystem)
        {
            m_context = context;
            foreach ((AdditionalText file, NodesetOptions options) in nodeset2Files)
            {
                try
                {
                    if (!NodeSetToModelDesign.IsNodeSet(fileSystem, file.Path))
                    {
                        continue;
                    }

                    using Stream istrm = fileSystem.OpenRead(file.Path);
                    SystemContext systemContext = new(null);
                    var nodeset = UANodeSet.Read(istrm);
                    var collection = new NodeStateCollection();

                    try
                    {
                        nodeset.Import(systemContext, collection);
                    }
                    catch (Exception e)
                    {
                        context.ReportDiagnostic(
                            Diagnostic.Create(SourceGenerator.GenericError,
                            Location.None,
                            $"NodeSet could not be loaded ({file.Path}): {e.Message}"));
                        return;
                    }

                    if (nodeset.Models == null ||
                        nodeset.Models.Length == 0 ||
                        string.IsNullOrEmpty(nodeset.Models[0].ModelUri))
                    {
                        context.ReportDiagnostic(
                           Diagnostic.Create(SourceGenerator.GenericError,
                           Location.None,
                           $"NodeSet is missing model definition ({file.Path})."));
                        continue;
                    }

                    ModelTableEntry model = nodeset.Models[0];
                    if (!Uri.IsWellFormedUriString(model.ModelUri, UriKind.Absolute))
                    {
                        context.ReportDiagnostic(
                           Diagnostic.Create(SourceGenerator.GenericError,
                           Location.None,
                           $"NodeSet ModelURI is not valid ({model.ModelUri})."));
                        continue;
                    }

                    string name = GetNameFromUri(model.ModelUri); // Get a sane name and prefix
                    var info = new NodesetFile
                    {
                        FileName = file.Path,
                        NodeSet = nodeset,
                        Info = new NodesetOptions // Set reasonable defaults if not provided
                        {
                            ModelUri = !string.IsNullOrEmpty(options.ModelUri) ?
                                options.ModelUri : model.ModelUri,
                            Version = !string.IsNullOrEmpty(options.Version) ?
                                options.Version :
                                model.PublicationDate.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture),
                            Name = !string.IsNullOrEmpty(options.Name) ?
                                options.Name : name,
                            Prefix = !string.IsNullOrEmpty(options.Prefix) ?
                                options.Prefix : name,
                            Ignore = options.Ignore
                        }
                    };

                    if (m_nodesets.TryGetValue(model.ModelUri, out NodesetFile existing) &&
                        existing.Info.Version.CompareTo(info.Info.Version, StringComparison.Ordinal) < 0)
                    {
                        info.PreviousVersions = [];

                        if (existing.PreviousVersions != null)
                        {
                            info.PreviousVersions.AddRange(existing.PreviousVersions);
                        }

                        existing.PreviousVersions = null;
                        info.PreviousVersions.Add(existing);
                    }
                    m_nodesets[model.ModelUri] = info;
                }
                catch (Exception ex)
                {
                    context.ReportDiagnostic(
                        Diagnostic.Create(SourceGenerator.Exception,
                        Location.None,
                        $"Could not parse NodeSet ({file.Path}): {ex.Message}.",
                        ex));
                }
            }
        }

        /// <summary>
        /// Get nodeset and dependencies for the model uri
        /// </summary>
        /// <returns></returns>
        public List<string> GetDesignFileListForModel(
            string modelUri,
            out NodesetFile nodeset)
        {
            if (!m_nodesets.TryGetValue(modelUri, out nodeset))
            {
                return null;
            }

            Dictionary<string, NodesetFile> dependencies = [];
            if (!CollectDependencies(nodeset, dependencies))
            {
                return null;
            }

            List<string> files = [$"{nodeset.FileName},{nodeset.Info.Prefix},{nodeset.Info.Name}"];
            foreach (NodesetFile dependency in dependencies.Values
                .Where(x => x.Info.ModelUri != Namespaces.OpcUa))
            {
                files.Add($"{dependency.FileName},{dependency.Info.Prefix},{dependency.Info.Name}");
            }
            return files;
        }

        /// <summary>
        /// Collect dependencies
        /// </summary>
        private bool CollectDependencies(
            NodesetFile target,
            Dictionary<string, NodesetFile> dependencies)
        {
            if (target.NodeSet.NamespaceUris == null)
            {
                return true;
            }

            foreach (string ns in target.NodeSet.NamespaceUris)
            {
                if (dependencies.ContainsKey(ns) || ns == target.Info.ModelUri)
                {
                    continue;
                }

                if (!m_nodesets.TryGetValue(ns, out NodesetFile nodeset))
                {
                    m_context.ReportDiagnostic(
                        Diagnostic.Create(SourceGenerator.GenericError,
                        Location.None,
                        $"NodeSet ({target.Info.ModelUri}) dependency is missing ({ns})."));
                    return false;
                }

                // favour the version in the same directory as the target.
                if (nodeset.PreviousVersions != null &&
                    Path.GetDirectoryName(nodeset.FileName) != Path.GetDirectoryName(target.FileName))
                {
                    foreach (NodesetFile ii in nodeset.PreviousVersions)
                    {
                        if (Path.GetDirectoryName(ii.FileName) == Path.GetDirectoryName(target.FileName))
                        {
                            nodeset = ii;
                            break;
                        }
                    }
                }

                dependencies[ns] = nodeset;
                if (!CollectDependencies(nodeset, dependencies))
                {
                    return false;
                }
            }
            return true;
        }

        private static string GetNameFromUri(string uri)
        {
            var builder = new Uri(uri);
            string path = builder.LocalPath.TrimEnd('/');

            if (path.StartsWith("/UA/", StringComparison.OrdinalIgnoreCase))
            {
                path = path[4..];
            }

            if (path.StartsWith("/OpcUa/", StringComparison.OrdinalIgnoreCase))
            {
                path = path[7..];
            }

            path = path.Trim('/')
                .Replace("/", string.Empty)
                .Replace('-', '_')
                .Replace('+', '_');

            int colon = path.LastIndexOf(':');
            if (colon != -1)
            {
                path = path[(colon + 1)..];
            }

            // Remove invalid path characters
            Path.GetInvalidFileNameChars()
                .ToList()
                .ForEach(c => path = path.Replace(c, '_'));
            return path;
        }

        /// <summary>
        /// An entry in the collection
        /// </summary>
        internal sealed class NodesetFile
        {
            public NodesetOptions Info { get; set; }
            public string FileName { get; set; }
            public UANodeSet NodeSet { get; set; }
            public List<NodesetFile> PreviousVersions { get; set; }
        }

        private readonly Dictionary<string, NodesetFile> m_nodesets = [];
        private readonly SourceProductionContext m_context;
    }
}
