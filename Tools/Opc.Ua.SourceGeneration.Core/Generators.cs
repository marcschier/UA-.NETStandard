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

using System.Collections.Generic;
using Opc.Ua.Types;

namespace Opc.Ua.SourceGeneration
{
    /// <summary>
    /// Source Generation API
    /// </summary>
    public static class Generators
    {
        internal const string StackNamespacePrefix = "Opc.Ua";

        /// <summary>
        /// Generate code from design files
        /// </summary>
        /// <param name="designFiles"></param>
        /// <param name="fileSystem"></param>
        /// <param name="exclusions"></param>
        /// <param name="telemetry"></param>
        /// <param name="useAllowSubtypes"></param>
        public static void GenerateCode(
            this DesignFileCollection designFiles,
            IFileSystem fileSystem,
            string[] exclusions,
            ITelemetryContext telemetry,
            bool useAllowSubtypes = false)
        {
            if (designFiles.DesignFiles.Count == 0)
            {
                return;
            }
            var generator = new ModelGenerator(fileSystem, telemetry);
            // The rest of the input is processed as design files
            generator.ValidateAndUpdateIds(
                designFiles.DesignFiles,
                null, // identifierFile,
                exclusions,
                designFiles.Options,
                useAllowSubtypes);

            generator.Emit(string.Empty);
        }

        /// <summary>
        /// Generate from nodesets
        /// </summary>
        /// <param name="nodesets"></param>
        /// <param name="fileSystem"></param>
        /// <param name="exclusions"></param>
        /// <param name="telemetry"></param>
        public static void GenerateCode(
            this NodesetFileCollection nodesets,
            IFileSystem fileSystem,
            string[] exclusions,
            ITelemetryContext telemetry)
        {
            if (nodesets.Files.Count == 0)
            {
                return;
            }
            foreach (string modelUri in nodesets.ModelUris)
            {
                var generator = new ModelGenerator(fileSystem, telemetry)
                {
                    AvailableNodeSets = nodesets.Files
                };
                List<string> designFilesForModel = nodesets.GetDesignFileListForModel(
                    modelUri,
                    out NodesetFile nodeset);
                if (designFilesForModel == null || nodeset.Info.Ignore)
                {
                    continue;
                }
                generator.ValidateAndUpdateIds(
                    designFilesForModel,
                    null,
                    exclusions);
                generator.Emit(string.Empty);
            }
        }

        /// <summary>
        /// Generate the .net stack code
        /// </summary>
        /// <param name="fileSystem">The root file system to use</param>
        /// <param name="outputDir">The output folder in it</param>
        /// <param name="exclusions">Optional exclusions</param>
        /// <param name="telemetry">A telemetry context for logging</param>
        public static void GenerateStack(
            IFileSystem fileSystem,
            string outputDir,
            IReadOnlyList<string> exclusions,
            ITelemetryContext telemetry)
        {
            // Combine with embedded resources in this assembly.
            fileSystem = typeof(Generators).Assembly
                .AsFileSystem("Opc.Ua.SourceGeneration.Design")
                .WithFallback(fileSystem);

            // Generate standard types
            var generator = new ModelGenerator(
                fileSystem,
                telemetry);
            generator.ValidateAndUpdateIds(
                [
                    BuiltInDesignFiles.StandardTypesXml,
                    BuiltInDesignFiles.UACoreServicesXml
                ],
                BuiltInDesignFiles.StandardTypesCsv,
                exclusions,
                new DesignFileOptions
                {
                    StartId = 0,
                    ModelVersion = "1.05.06", // <--- Read from version file
                    ModelPublicationDate = "2025-11-08", // <--- Read from version file
                    ReleaseCandidate = true
                },
                false);

            // Generate schemas
            var typeDictionaries = new Dictionary<string, string>();
            var xmlSchema = new XmlSchemaGenerator(
                fileSystem,
                BuiltInDesignFiles.UACoreServicesXml,
                outputDir,
                typeDictionaries,
                exclusions);
            TextFileResource xmlSchemaResource = xmlSchema.Emit(
                StackNamespacePrefix);

            typeDictionaries = [];
            var binarySchema = new BinarySchemaGenerator(
                fileSystem,
                BuiltInDesignFiles.UACoreServicesXml,
                outputDir,
                typeDictionaries,
                exclusions);
            TextFileResource binarySchemaResource = binarySchema.Emit(
                StackNamespacePrefix,
                Namespaces.OpcUa);

            // Embed schemas
            var schemaResources = new ResourceGenerator(
                fileSystem,
                outputDir);
            schemaResources.Embed(
                StackNamespacePrefix,
                "XmlSchemas",
                false,
                binarySchemaResource,
                xmlSchemaResource);

            // Create constants
            var nodeDictionaries = new Dictionary<string, string>();
            var attributes = new ConstantsGenerator(
                fileSystem,
                BuiltInDesignFiles.UAAttributesXml,
                outputDir,
                nodeDictionaries,
                exclusions);
            attributes.Generate(
                StackNamespacePrefix,
                "Attributes",
                BuiltInDesignFiles.AttributesCsv);
            var statusCodes = new ConstantsGenerator(
                fileSystem,
                BuiltInDesignFiles.UAStatusCodesXml,
                outputDir,
                nodeDictionaries,
                exclusions);
            statusCodes.Generate(
                StackNamespacePrefix,
                "StatusCodes",
                BuiltInDesignFiles.StatusCodesCsv);

            var core = new StackGenerator(
                fileSystem,
                BuiltInDesignFiles.UACoreServicesXml,
                outputDir,
                nodeDictionaries,
                exclusions);
            core.Generate(
                StackNamespacePrefix,
                "Core",
                true);

            generator.Emit(outputDir);
        }
    }
}
