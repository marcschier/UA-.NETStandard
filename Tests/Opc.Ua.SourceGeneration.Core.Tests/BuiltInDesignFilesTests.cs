/* ========================================================================
 * Copyright (c) 2005-2020 The OPC Foundation, Inc. All rights reserved.
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

using System.IO;
using System.Threading.Tasks;
using NUnit.Framework;

namespace Opc.Ua.SourceGeneration
{
    /// <summary>
    /// Test Client Services.
    /// </summary>
    [TestFixture]
    [Category("SourceGeneration")]
    [SetCulture("en-us")]
    [SetUICulture("en-us")]
    public class BuiltInDesignFilesTests
    {
        [DatapointSource]
        public string[] Resources =
        [
            BuiltInDesignFiles.AttributesCsv,
            BuiltInDesignFiles.BuiltInTypesXml,
            BuiltInDesignFiles.ServerCapabilitiesCsv,
            BuiltInDesignFiles.StandardTypesCsv,
            BuiltInDesignFiles.StandardTypesXml,
            BuiltInDesignFiles.StatusCodesCsv,
            BuiltInDesignFiles.UAAttributesXml,
            BuiltInDesignFiles.UACoreServicesXml,
            BuiltInDesignFiles.UAStatusCodesXml
        ];

        [Theory]
        public async Task TestResourcesLoadFromResourceFileSystemAsync(string file, bool withDesignPath)
        {
            IFileSystem fs = typeof(BuiltInDesignFiles).Assembly.AsFileSystem(
                withDesignPath ? "Opc.Ua.SourceGeneration.Design" : null);
            Assert.That(fs.Exists(file), Is.True, $"File '{file}' should exist in resource file system.");
            using TextReader reader = fs.CreateTextReader(file);
            string content = await reader.ReadToEndAsync().ConfigureAwait(false);
            Assert.That(content, Is.Not.Empty, $"File '{file}' should have content.");
        }
    }
}
