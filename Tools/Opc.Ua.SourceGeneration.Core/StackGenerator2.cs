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
using System.IO;
using Opc.Ua.Schema.Types;

namespace Opc.Ua.SourceGeneration
{
    internal static class StackGenerator2
    {
        internal sealed class Files
        {
            public Dictionary<string, string> XmlSchemas;
            public Dictionary<string, string> BinarySchemas;
            public Dictionary<string, string> NodeDictionaries;
            public Dictionary<string, string> TypeDictionaries;

            public Files()
            {
                XmlSchemas = [];
                BinarySchemas = [];
                NodeDictionaries = [];
                TypeDictionaries = [];
            }
        }

        private static void ProcessDictionary(
            IFileSystem fileSystem,
            string name,
            string input,
            string output,
            Files files,
            string specificationVersion,
            IReadOnlyList<string> exclusions)
        {
            var validator = new TypeDictionaryValidator();
            validator.Validate(input);
        }

        private static void GenerateDotNet(
            Files files,
            string modelDir,
            string csvDir,
            string outputDir,
            string specificationVersion,
            IReadOnlyList<string> exclusions)
        {
            var generator7 = new ConstantsGenerator(
                $"{modelDir}UA Attributes.xml",
                outputDir,
                files.NodeDictionaries,
                exclusions);

            generator7.Generate(
                "Opc.Ua",
                "Attributes",
                $"{csvDir}Attributes.csv",
                false);

            var generator8 = new ConstantsGenerator(
                $"{modelDir}UA Status Codes.xml",
                outputDir,
                files.NodeDictionaries,
                exclusions);

            generator8.Generate(
                "Opc.Ua",
                "StatusCodes",
                $"{csvDir}Status Codes.csv",
                false);

            var generator10 = new StackGenerator(
                $"{modelDir}UA Core Services.xml",
                outputDir,
                files.TypeDictionaries,
                exclusions);

            generator10.Generate("Opc.Ua", "Core", true);
        }

        public static void GenerateDotNet(
            IFileSystem fileSystem,
            IReadOnlyList<string> designFilePaths,
            string identifierFilePath,
            string rootDir,
            string specificationVersion,
            IReadOnlyList<string> exclusions)
        {
            string modelDir = Path.GetDirectoryName(designFilePaths[0]) + "\\";
            string csvDir = Path.GetDirectoryName(identifierFilePath) + "\\";

            var files = new Files();

            ProcessDictionary(
                fileSystem,
                string.Empty,
                $"{modelDir}UA Core Services.xml",
                rootDir,
                files,
                specificationVersion,
                exclusions);

            GenerateDotNet(files, modelDir, csvDir, rootDir, specificationVersion, exclusions);
        }
    }
}
