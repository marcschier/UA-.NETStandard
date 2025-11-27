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
using System.Threading;

namespace Opc.Ua.SourceGeneration
{
    /// <summary>
    /// Generator options
    /// </summary>
    public sealed class GeneratorOptions
    {
        /// <summary>
        /// Optimize generated code for compile speed.
        /// </summary>
        public bool OptimizeForCompileSpeed { get; set; }

        /// <summary>
        /// Generation should be cancelled
        /// </summary>
        public CancellationToken Cancellation { get; set; }
    }

    /// <summary>
    /// Source Generation API
    /// </summary>
    public static class Generators
    {
        internal const string StackNamespacePrefix = "Opc.Ua";

        /// <summary>
        /// Generate code from design files
        /// </summary>
        /// <param name="designFiles">Design files to process</param>
        /// <param name="fileSystem">File system abstraction to use</param>
        /// <param name="outputDir">Output folder or null</param>
        /// <param name="exclusions">Exclusion map</param>
        /// <param name="telemetry">Telemetry context for logging</param>
        /// <param name="options">Generator options</param>
        /// <param name="useAllowSubtypes">allow subtypes</param>
        public static void GenerateCode(
            this DesignFileCollection designFiles,
            IFileSystem fileSystem,
            string outputDir,
            string[] exclusions,
            ITelemetryContext telemetry,
            GeneratorOptions options = null,
            bool useAllowSubtypes = false)
        {
            if (designFiles.DesignFiles.Count == 0)
            {
                return;
            }
            // Combine with embedded resources in this assembly.
            fileSystem = typeof(Generators).Assembly
                .AsFileSystem("Opc.Ua.SourceGeneration.Design")
                .WithFallback(fileSystem);

            options ??= new GeneratorOptions();
            var generator = new ModelGenerator(
                fileSystem,
                outputDir,
                telemetry,
                options);
            // The rest of the input is processed as design files
            generator.ValidateAndUpdateIds(
                designFiles.DesignFiles,
                null, // identifierFile,
                exclusions,
                designFiles.Options,
                useAllowSubtypes);

            generator.Emit();
        }

        /// <summary>
        /// Generate from nodesets
        /// </summary>
        /// <param name="nodesets">Nodesets to process</param>
        /// <param name="fileSystem">File system abstraction to use</param>
        /// <param name="outputDir">Output folder or null</param>
        /// <param name="exclusions">Exclusion map</param>
        /// <param name="telemetry">Telemetry context for logging</param>
        /// <param name="options">Generator options</param>
        public static void GenerateCode(
            this NodesetFileCollection nodesets,
            IFileSystem fileSystem,
            string outputDir,
            string[] exclusions,
            ITelemetryContext telemetry,
            GeneratorOptions options = null)
        {
            if (nodesets.Files.Count == 0)
            {
                return;
            }
            // Combine with embedded resources in this assembly.
            fileSystem = typeof(Generators).Assembly
                .AsFileSystem("Opc.Ua.SourceGeneration.Design")
                .WithFallback(fileSystem);

            options ??= new GeneratorOptions();
            foreach (string modelUri in nodesets.ModelUris)
            {
                var generator = new ModelGenerator(
                    fileSystem,
                    outputDir,
                    telemetry,
                    options)
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
                generator.Emit();
            }
        }

        /// <summary>
        /// Generate the .net stack code
        /// </summary>
        /// <param name="fileSystem">The root file system to use</param>
        /// <param name="outputDir">Output folder or null</param>
        /// <param name="exclusions">Optional exclusions</param>
        /// <param name="telemetry">A telemetry context for logging</param>
        /// <param name="options">Generator options</param>
        public static void GenerateStack(
            IFileSystem fileSystem,
            string outputDir,
            IReadOnlyList<string> exclusions,
            ITelemetryContext telemetry,
            GeneratorOptions options = null)
        {
            // Combine with embedded resources in this assembly.
            fileSystem = typeof(Generators).Assembly
                .AsFileSystem("Opc.Ua.SourceGeneration.Design")
                .WithFallback(fileSystem);

            // Generate standard types as models just like for other models.
            var modelGenerator = new ModelGenerator(
                fileSystem,
                outputDir,
                telemetry,
                options);
            options ??= new GeneratorOptions();
            modelGenerator.ValidateAndUpdateIds(
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
            var stackGenerator = new StackGenerator(
                fileSystem,
                outputDir,
                exclusions,
                options);
            stackGenerator.Emit();
            modelGenerator.Emit(skipSchemas: true);
        }
    }
}
