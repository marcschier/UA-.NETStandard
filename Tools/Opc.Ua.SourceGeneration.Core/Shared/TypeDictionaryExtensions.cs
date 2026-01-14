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

using System.Collections.Generic;
using System.Text;
using Opc.Ua.Schema.Types;
using Opc.Ua.Types;

namespace Opc.Ua.SourceGeneration
{
    /// <summary>
    /// Type dictionary extensions
    /// </summary>
    internal static class TypeDictionaryExtensions
    {
        /// <summary>
        /// Returns the list of datatypes to process.
        /// </summary>
        public static IReadOnlyList<DataType> GetDataTypeList(
            this TypeDictionaryValidator validator)
        {
            // collect datatypes with the specified type.
            var datatypes = new List<DataType>();

            foreach (TypeDictionary dictionary in validator.LoadedTypeDictionaries)
            {
                if (dictionary.TargetNamespace != Namespaces.OpcUaBuiltInTypes)
                {
                    CollectDatatypes(dictionary, datatypes);
                }
            }

            // include identifiers from the target dictionary.
            CollectDatatypes(validator.Dictionary, datatypes);
            return datatypes;
        }

        /// <summary>
        /// Returns the list of datatypes to process.
        /// </summary>
        private static void CollectDatatypes(
            this TypeDictionary dictionary,
            List<DataType> datatypes)
        {
            if (dictionary == null || dictionary.Items == null || datatypes == null)
            {
                return;
            }

            // include identifiers from the target dictionary.
            foreach (DataType datatype in dictionary.Items)
            {
                if (datatype is ComplexType complexType)
                {
                    GetDataTypeList(complexType.Field, datatypes);
                }

                if (datatype is ServiceType serviceType)
                {
                    GetDataTypeList(serviceType.Request, datatypes);
                    GetDataTypeList(serviceType.Response, datatypes);
                }

                datatypes.Add(datatype);
            }
        }

        /// <summary>
        /// Creates a description from a documentation element.
        /// </summary>
        public static string GetDescription(this Documentation documentation)
        {
            if (documentation == null || documentation.Text == null)
            {
                return null;
            }

            var buffer = new StringBuilder();

            for (int ii = 0; ii < documentation.Text.Length; ii++)
            {
                if (buffer.Length > 0)
                {
                    buffer.Append(' ');
                }

                buffer.Append(documentation.Text[ii]);
            }

            return buffer.ToString();
        }

        /// <summary>
        /// Returns the list of datatypes to process.
        /// </summary>
        private static void GetDataTypeList(FieldType[] fields, List<DataType> datatypes)
        {
            if (fields != null)
            {
                foreach (FieldType field in fields)
                {
                    if (field.ComplexType != null)
                    {
                        datatypes.Add(field.ComplexType);
                        GetDataTypeList(field.ComplexType.Field, datatypes);
                    }
                }
            }
        }
    }
}
