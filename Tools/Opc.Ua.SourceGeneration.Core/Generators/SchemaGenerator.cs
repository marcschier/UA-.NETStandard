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

using Opc.Ua.Schema.Types;
using Opc.Ua.Types;
using System;
using System.Collections.Generic;
using System.Text;
using System.Xml;

namespace Opc.Ua.SourceGeneration
{
    /// <summary>
    /// Generates a schema based on a UA Type Dictionary.
    /// </summary>
    internal class SchemaGenerator
    {
        /// <summary>
        /// Loads and validates the type dictionary.
        /// </summary>
        internal SchemaGenerator(
            IFileSystem fileSystem,
            string typeDictionary,
            string outputDirectory,
            Dictionary<string, string> knownFiles,
            IReadOnlyList<string> exclusions)
        {
            // load and validate type dictionary.
            Validator = new TypeDictionaryValidator(
                fileSystem,
                knownFiles);
            Validator.Validate(typeDictionary);

            Exclusions = exclusions;
            FileSystem = fileSystem ?? LocalFileSystem.Instance;
            KnownFiles = knownFiles ?? [];

            // save output directory.
            OutputDirectory = outputDirectory;

            // index namespace uris.
            IndexNamespaceUris();
        }

        /// <summary>
        /// File system used
        /// </summary>
        protected IFileSystem FileSystem { get; }

        /// <summary>
        /// Known files for namespaces tables
        /// </summary>
        internal Dictionary<string, string> KnownFiles { get; }

        /// <summary>
        /// Excluded fields and types.
        /// </summary>
        internal IReadOnlyList<string> Exclusions { get; set; }

        /// <summary>
        /// The validator used to verify the type dictionary.
        /// </summary>
        internal TypeDictionaryValidator Validator { get; }

        /// <summary>
        /// The dictionary being processed.
        /// </summary>
        internal TypeDictionary Dictionary => Validator.Dictionary;

        /// <summary>
        /// The namespace uris referenced by types in the dictionary.
        /// </summary>
        internal IList<string> NamespaceUris => m_namespaceUris;

        /// <summary>
        /// The directory used to place any output files.
        /// </summary>
        internal string OutputDirectory { get; }

        /// <summary>
        /// The current target namespace.
        /// </summary>
        internal string TargetNamespace
        {
            get
            {
                if (m_namespaceUris.Count > 0)
                {
                    return m_namespaceUris[0];
                }

                return null;
            }

            set
            {
                // ensure the target namespace is the first namespace.
                int index = m_namespaceUris.IndexOf(value);

                if (index != 0)
                {
                    if (index != -1)
                    {
                        m_namespaceUris.RemoveAt(index);
                    }

                    m_namespaceUris.Insert(0, value);
                }
            }
        }

        /// <summary>
        /// Returns the datatypes in the dictionary.
        /// </summary>
        internal List<DataType> GetListOfTypes(bool exportAll)
        {
            return [.. GetListOfTypes(null, exportAll, false)];
        }

        /// <summary>
        /// Returns the datatypes in the dictionary.
        /// </summary>
        internal IReadOnlyList<DataType> GetListOfTypes(Type type, bool exportAll, bool exportApi)
        {
            return Validator.GetDataTypeList(type, null, null, exportAll, exportApi);
        }

        /// <summary>
        /// Returns a name qualified with a namespace prefix.
        /// </summary>
        internal string GetPrefixedName(XmlQualifiedName qname)
        {
            return qname.GetPrefixedName(m_namespaceUris);
        }

        /// <summary>
        /// Creates a description from the documentation element.
        /// </summary>
        internal static void CreateDescription(
            Template template,
            string token,
            Documentation documentation)
        {
            var buffer = new StringBuilder();

            if (documentation != null &&
                documentation.Text != null &&
                documentation.Text.Length > 0)
            {
                for (int ii = 0; ii < documentation.Text.Length; ii++)
                {
                    if (buffer.Length > 0)
                    {
                        buffer.Append(Environment.NewLine);
                    }
                    buffer.Append(documentation.Text[ii]);
                }
            }
            template.AddReplacement(token, buffer.ToString(), ["Dummy"]);
        }

        /// <summary>
        /// Fetches all of the fields for a complex type by following the base type.
        /// </summary>
        internal void GetFields(ComplexType complexType, List<FieldType> fields)
        {
            if (!complexType.BaseType.IsNull() &&
                Validator.ResolveType(complexType.BaseType) is ComplexType baseType)
            {
                GetFields(baseType, fields);
            }

            if (complexType.Field != null)
            {
                foreach (FieldType field in complexType.Field)
                {
                    if (!TypeDictionaryValidator.IsExcluded(Exclusions, field))
                    {
                        fields.Add(field);
                    }
                }
            }
        }

        /// <summary>
        /// Saves a namespace uri.
        /// </summary>
        private void IndexNamespaceUri(string namespaceUri)
        {
            if (!string.IsNullOrEmpty(namespaceUri) &&
                namespaceUri != Namespaces.OpcUaBuiltInTypes &&
                !m_namespaceUris.Contains(namespaceUri))
            {
                m_namespaceUris.Add(namespaceUri);
            }
        }

        /// <summary>
        /// Collects namespaces uris referenced by the types in the dictionary.
        /// </summary>
        private void IndexNamespaceUris()
        {
            m_namespaceUris = [];

            foreach (DataType datatype in Dictionary.Items)
            {
                IndexNamespaceUri(datatype.QName.Namespace);

                if (datatype is TypeDeclaration declaration && !declaration.SourceType.IsNull())
                {
                    IndexNamespaceUri(declaration.SourceType.Namespace);
                }

                if (datatype is ComplexType complexType)
                {
                    if (!complexType.BaseType.IsNull())
                    {
                        IndexNamespaceUri(complexType.BaseType.Namespace);
                    }

                    foreach (FieldType fieldType in ((ComplexType)datatype).Field)
                    {
                        IndexNamespaceUri(fieldType.DataType.Namespace);
                    }
                }

                if (datatype is ServiceType serviceType)
                {
                    foreach (FieldType fieldType in serviceType.Request)
                    {
                        IndexNamespaceUri(fieldType.DataType.Namespace);
                    }

                    foreach (FieldType fieldType in serviceType.Response)
                    {
                        IndexNamespaceUri(fieldType.DataType.Namespace);
                    }
                }
            }
        }

        private List<string> m_namespaceUris;
    }
}
