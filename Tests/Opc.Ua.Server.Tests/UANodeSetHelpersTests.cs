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
using System.Text;
using NUnit.Framework;
using Opc.Ua.Tests;
using Assert = NUnit.Framework.Legacy.ClassicAssert;

namespace Opc.Ua.Server.Tests.Stack.Schema
{
    /// <summary>
    /// Tests for the UANodeSet helper.
    /// </summary>
    [TestFixture]
    [Category("UANodeSet")]
    [SetCulture("en-us")]
    [SetUICulture("en-us")]
    [Parallelizable]
    public class UANodeSetHelpersTests
    {
        [Test]
        public void TestDataNodeSet2ValidationTest()
        {
            using var inputStream = TestData.NodeSet2.XmlAsStream;
            NodeSet2ValidationTest(inputStream);
        }

        [Test]
        public void BoilerNodeSet2ValidationTest()
        {
            using var inputStream = Boiler.NodeSet2.XmlAsStream;
            NodeSet2ValidationTest(inputStream);
        }

        [Test]
        public void MemoryBufferNodeSet2ValidationTest()
        {
            using var inputStream = MemoryBuffer.NodeSet2.XmlAsStream;
            NodeSet2ValidationTest(inputStream);
        }

        /// <summary>
        /// Test NodeSet2 import.
        /// </summary>
        private void NodeSet2ValidationTest(Stream importStream)
        {
            ITelemetryContext telemetry = NUnitTelemetryContext.Create();

            var importedNodeSet = Export.UANodeSet.Read(importStream);
            Assert.NotNull(importedNodeSet);

            var importedNodeStates = new NodeStateCollection();
            var localContext = new SystemContext(telemetry) { NamespaceUris = new NamespaceTable() };
            if (importedNodeSet.NamespaceUris != null)
            {
                foreach (string namespaceUri in importedNodeSet.NamespaceUris)
                {
                    localContext.NamespaceUris.Append(namespaceUri);
                }
            }
            importedNodeSet.Import(localContext, importedNodeStates);
        }
    }
}
