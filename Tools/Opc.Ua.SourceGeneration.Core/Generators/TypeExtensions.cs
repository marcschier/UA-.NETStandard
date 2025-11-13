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

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Xml;
using Opc.Ua.Schema.Model;
using Opc.Ua.Schema.Types;
using Opc.Ua.Types;

namespace Opc.Ua.SourceGeneration
{
    /// <summary>
    /// Type system extensions
    /// </summary>
    internal static class TypeExtensions
    {
        /// <summary>
        /// Returns the list of datatypes to process.
        /// </summary>
        /// <exception cref="ArgumentNullException"><paramref name="validator"/> is <c>null</c>.</exception>
        public static IReadOnlyList<DataType> GetDataTypeList(
            this TypeDictionaryValidator validator,
            Type type,
            IReadOnlyList<string> dictionariesToExport,
            IReadOnlyList<string> exclusions,
            bool exportAll,
            bool exportApi)
        {
            if (validator == null)
            {
                throw new ArgumentNullException(nameof(validator));
            }

            // collect datatypes with the specified type.
            var datatypes = new List<DataType>();

            foreach (TypeDictionary dictionary in validator.LoadedFiles.Values.Cast<TypeDictionary>())
            {
                if (dictionary.TargetNamespace != Namespaces.OpcUaBuiltInTypes)
                {
                    if (exportAll || dictionariesToExport?.Contains(dictionary.TargetNamespace) == true)
                    {
                        CollectDatatypes(dictionary, type, datatypes, exportApi);
                    }
                }
            }

            // include identifiers from the target dictionary.
            CollectDatatypes(validator.Dictionary, type, datatypes, exportApi);

            if (exclusions == null)
            {
                return datatypes;
            }

            var datatypes2 = new List<DataType>();
            foreach (DataType ii in datatypes)
            {
                if (!TypeDictionaryValidator.IsExcluded(exclusions, ii))
                {
                    datatypes2.Add(ii);
                }
            }

            return datatypes2;
        }

        /// <summary>
        /// Returns the list of datatypes to process.
        /// </summary>
        public static void CollectDatatypes(
            this TypeDictionary dictionary,
            Type type,
            List<DataType> datatypes,
            bool exportApi)
        {
            if (dictionary == null || dictionary.Items == null || datatypes == null)
            {
                return;
            }

            // include identifiers from the target dictionary.
            foreach (DataType datatype in dictionary.Items)
            {
                if (type == null || type.IsInstanceOfType(datatype))
                {
                    if (datatype is ComplexType complexType)
                    {
                        GetDataTypeList(type, complexType.Field, datatypes);
                    }

                    if (datatype is ServiceType serviceType)
                    {
                        if (exportApi && serviceType.InterfaceType == InterfaceType.SecureChannel)
                        {
                            continue;
                        }

                        GetDataTypeList(type, serviceType.Request, datatypes);
                        GetDataTypeList(type, serviceType.Response, datatypes);
                    }

                    datatypes.Add(datatype);
                }
            }
        }

        /// <summary>
        /// Returns the list of datatypes to process.
        /// </summary>
        private static void GetDataTypeList(Type type, FieldType[] fields, List<DataType> datatypes)
        {
            if (fields != null)
            {
                foreach (FieldType field in fields)
                {
                    if (field.ComplexType != null)
                    {
                        if (type == null || type.IsInstanceOfType(field.ComplexType))
                        {
                            datatypes.Add(field.ComplexType);
                            GetDataTypeList(type, field.ComplexType.Field, datatypes);
                        }
                    }
                }
            }
        }

        /// <summary>
        /// Is overridden instance.
        /// </summary>
        public static bool IsOverridden(this InstanceDesign instance)
        {
            return instance.OveriddenNode != null &&
                instance.ModellingRule != ModellingRule.None &&
                instance.ModellingRule != ModellingRule.ExposesItsArray &&
                instance.ModellingRule != ModellingRule.MandatoryPlaceholder &&
                instance.ModellingRule != ModellingRule.OptionalPlaceholder;
        }

        /// <summary>
        /// Returns the merged instance for an overriden node.
        /// </summary>
        public static InstanceDesign GetMergedInstance(this InstanceDesign instance)
        {
            for (NodeDesign parent = instance.Parent; parent != null; parent = parent.Parent)
            {
                if (parent.Parent == null && parent.Hierarchy != null)
                {
                    string relativePath = instance.SymbolicId.Name;

                    int index = relativePath.IndexOf('_', StringComparison.Ordinal);

                    if (index != -1)
                    {
                        relativePath = relativePath[(index + 1)..];
                    }

                    if (parent.Hierarchy.Nodes.TryGetValue(relativePath, out HierarchyNode hierarchyNode) &&
                        hierarchyNode.Instance is InstanceDesign instanceDesign)
                    {
                        return instanceDesign;
                    }

                    break;
                }
            }

            return instance;
        }

        /// <summary>
        /// Checks if the instance is a built in property that should not be generatd.
        /// </summary>
        public static bool IsBuiltInProperty(this InstanceDesign instance)
        {
            if (instance == null)
            {
                return true;
            }

            if (instance.Parent is MethodDesign)
            {
                if (instance.SymbolicName ==
                    new XmlQualifiedName("InputArguments", Namespaces.OpcUa))
                {
                    return true;
                }

                if (instance.SymbolicName ==
                    new XmlQualifiedName("OutputArguments", Namespaces.OpcUa))
                {
                    return true;
                }
            }

            return instance.Parent is VariableDesign &&
                instance.SymbolicName ==
                    new XmlQualifiedName("EnumStrings", Namespaces.OpcUa);
        }

        /// <summary>
        /// Returns a name qualified with a namespace prefix.
        /// </summary>
        public static string GetPrefixedName(this XmlQualifiedName qname, List<string> namespaceUris)
        {
            if (qname.IsNull())
            {
                return string.Empty;
            }

            if (qname.Namespace == Namespaces.OpcUaBuiltInTypes)
            {
                return CoreUtils.Format("ua:{0}", qname.Name);
            }

            int index = namespaceUris.IndexOf(qname.Namespace);

            if (index > 0)
            {
                return CoreUtils.Format("s{0}:{1}", index - 1, qname.Name);
            }

            return qname.Name;
        }

        /// <summary>
        /// Returns the data type to use for the value of a variable or the argument of a method.
        /// </summary>
        public static string GetBinaryDataType(
            this DataTypeDesign dataType,
            string targetNamespace,
            Namespace[] namespaces)
        {
            switch (dataType.BasicDataType)
            {
                case BasicDataType.Boolean:
                    return "opc:Boolean";
                case BasicDataType.SByte:
                    return "opc:SByte";
                case BasicDataType.Byte:
                    return "opc:Byte";
                case BasicDataType.Int16:
                    return "opc:Int16";
                case BasicDataType.UInt16:
                    return "opc:UInt16";
                case BasicDataType.Int32:
                    return "opc:Int32";
                case BasicDataType.UInt32:
                    return "opc:UInt32";
                case BasicDataType.Int64:
                    return "opc:Int64";
                case BasicDataType.UInt64:
                    return "opc:UInt64";
                case BasicDataType.Float:
                    return "opc:Float";
                case BasicDataType.Double:
                    return "opc:Double";
                case BasicDataType.String:
                    return "opc:String";
                case BasicDataType.DateTime:
                    return "opc:DateTime";
                case BasicDataType.Guid:
                    return "opc:Guid";
                case BasicDataType.ByteString:
                    return "opc:ByteString";
                case BasicDataType.XmlElement:
                    return "ua:XmlElement";
                case BasicDataType.NodeId:
                    return "ua:NodeId";
                case BasicDataType.ExpandedNodeId:
                    return "ua:ExpandedNodeId";
                case BasicDataType.StatusCode:
                    return "ua:StatusCode";
                case BasicDataType.DiagnosticInfo:
                    return "ua:DiagnosticInfo";
                case BasicDataType.QualifiedName:
                    return "ua:QualifiedName";
                case BasicDataType.LocalizedText:
                    return "ua:LocalizedText";
                case BasicDataType.DataValue:
                    return "ua:DataValue";
                case BasicDataType.Number:
                case BasicDataType.Integer:
                case BasicDataType.UInteger:
                case BasicDataType.BaseDataType:
                    return "ua:Variant";
                default:
                    if (dataType.SymbolicName ==
                        new XmlQualifiedName("Structure", Namespaces.OpcUa))
                    {
                        return CoreUtils.Format("ua:ExtensionObject");
                    }

                    if (dataType.SymbolicName ==
                        new XmlQualifiedName("Enumeration", Namespaces.OpcUa))
                    {
                        if (dataType.IsOptionSet)
                        {
                            return GetBinaryDataType(
                                (DataTypeDesign)dataType.BaseTypeNode,
                                targetNamespace,
                                namespaces);
                        }

                        return CoreUtils.Format("opc:Int32");
                    }

                    string prefix = "tns";

                    if (dataType.SymbolicName.Namespace != targetNamespace)
                    {
                        if (dataType.SymbolicName.Namespace == Namespaces.OpcUa)
                        {
                            prefix = "ua";
                        }
                        else
                        {
                            prefix = GetXmlNamespacePrefix(
                                namespaces,
                                dataType.SymbolicName.Namespace);
                        }
                    }
                    return CoreUtils.Format("{0}:{1}", prefix, dataType.SymbolicName.Name);
            }
        }

        /// <summary>
        /// Returns the data type to use for the value of a variable or the argument of a method.
        /// </summary>
        public static string GetXmlDataType(
            this DataTypeDesign dataType,
            ValueRank valueRank,
            string targetNamespace,
            Namespace[] namespaces)
        {
            if (valueRank != ValueRank.Scalar)
            {
                switch (dataType.BasicDataType)
                {
                    case BasicDataType.Boolean:
                        return "ua:ListOfBoolean";
                    case BasicDataType.SByte:
                        return "ua:ListOfSByte";
                    case BasicDataType.Int16:
                        return "ua:ListOfInt16";
                    case BasicDataType.UInt16:
                        return "ua:ListOfUInt16";
                    case BasicDataType.Int32:
                        return "ua:ListOfInt32";
                    case BasicDataType.UInt32:
                        return "ua:ListOfUInt32";
                    case BasicDataType.Int64:
                        return "ua:ListOfInt64";
                    case BasicDataType.UInt64:
                        return "ua:ListOfUInt64";
                    case BasicDataType.Float:
                        return "ua:ListOfFloat";
                    case BasicDataType.Double:
                        return "ua:ListOfDouble";
                    case BasicDataType.String:
                        return "ua:ListOfString";
                    case BasicDataType.DateTime:
                        return "ua:ListOfDateTime";
                    case BasicDataType.Guid:
                        return "ua:ListOfGuid";
                    case BasicDataType.ByteString:
                        return "ua:ListOfByteString";
                    case BasicDataType.XmlElement:
                        return "ua:ListOfXmlElement";
                    case BasicDataType.NodeId:
                        return "ua:ListOfNodeId";
                    case BasicDataType.ExpandedNodeId:
                        return "ua:ListOfExpandedNodeId";
                    case BasicDataType.StatusCode:
                        return "ua:ListOfStatusCode";
                    case BasicDataType.DiagnosticInfo:
                        return "ua:ListOfDiagnosticInfo";
                    case BasicDataType.QualifiedName:
                        return "ua:ListOfQualifiedName";
                    case BasicDataType.LocalizedText:
                        return "ua:ListOfLocalizedText";
                    case BasicDataType.DataValue:
                        return "ua:ListOfDataValue";
                    case BasicDataType.Number:
                    case BasicDataType.Integer:
                    case BasicDataType.UInteger:
                    case BasicDataType.BaseDataType:
                        return "ua:ListOfVariant";
                    default:
                        if (dataType.SymbolicName ==
                            new XmlQualifiedName("Structure", Namespaces.OpcUa))
                        {
                            return CoreUtils.Format("ua:ListOfExtensionObject");
                        }

                        if (dataType.SymbolicName ==
                            new XmlQualifiedName("Enumeration", Namespaces.OpcUa))
                        {
                            if (dataType.IsOptionSet)
                            {
                                return GetXmlDataType(
                                    (DataTypeDesign)dataType.BaseTypeNode,
                                    valueRank,
                                    targetNamespace,
                                    namespaces);
                            }

                            return CoreUtils.Format("ua:ListOfInt32");
                        }

                        string prefix = "tns";

                        if (dataType.SymbolicName.Namespace != targetNamespace)
                        {
                            if (dataType.SymbolicName.Namespace == Namespaces.OpcUa)
                            {
                                if (dataType.SymbolicName.Name == "Enumeration")
                                {
                                    if (dataType.IsOptionSet)
                                    {
                                        return GetXmlDataType(
                                            (DataTypeDesign)dataType.BaseTypeNode,
                                            valueRank,
                                            targetNamespace,
                                            namespaces);
                                    }

                                    return CoreUtils.Format("ua:ListOfInt32");
                                }

                                prefix = "ua";
                            }
                            else
                            {
                                prefix = GetXmlNamespacePrefix(namespaces, dataType.SymbolicName.Namespace);
                            }
                        }

                        return CoreUtils.Format("{0}:ListOf{1}", prefix, dataType.SymbolicName.Name);
                }
            }

            switch (dataType.BasicDataType)
            {
                case BasicDataType.Boolean:
                    return "xs:boolean";
                case BasicDataType.SByte:
                    return "xs:byte";
                case BasicDataType.Byte:
                    return "xs:unsignedByte";
                case BasicDataType.Int16:
                    return "xs:short";
                case BasicDataType.UInt16:
                    return "xs:unsignedShort";
                case BasicDataType.Int32:
                    return "xs:int";
                case BasicDataType.UInt32:
                    return "xs:unsignedInt";
                case BasicDataType.Int64:
                    return "xs:long";
                case BasicDataType.UInt64:
                    return "xs:unsignedLong";
                case BasicDataType.Float:
                    return "xs:float";
                case BasicDataType.Double:
                    return "xs:double";
                case BasicDataType.String:
                    return "xs:string";
                case BasicDataType.DateTime:
                    return "xs:dateTime";
                case BasicDataType.Guid:
                    return "ua:Guid";
                case BasicDataType.ByteString:
                    return "xs:base64Binary";
                case BasicDataType.XmlElement:
                    return "ua:XmlElement";
                case BasicDataType.NodeId:
                    return "ua:NodeId";
                case BasicDataType.ExpandedNodeId:
                    return "ua:ExpandedNodeId";
                case BasicDataType.StatusCode:
                    return "ua:StatusCode";
                case BasicDataType.DiagnosticInfo:
                    return "ua:DiagnosticInfo";
                case BasicDataType.QualifiedName:
                    return "ua:QualifiedName";
                case BasicDataType.LocalizedText:
                    return "ua:LocalizedText";
                case BasicDataType.DataValue:
                    return "ua:DataValue";
                case BasicDataType.Number:
                case BasicDataType.Integer:
                case BasicDataType.UInteger:
                case BasicDataType.BaseDataType:
                    return "ua:Variant";
                default:
                    if (dataType.SymbolicName ==
                        new XmlQualifiedName("Structure", Namespaces.OpcUa))
                    {
                        return CoreUtils.Format("ua:ExtensionObject");
                    }

                    if (dataType.SymbolicName ==
                        new XmlQualifiedName("Enumeration", Namespaces.OpcUa))
                    {
                        if (dataType.IsOptionSet)
                        {
                            return GetXmlDataType(
                                (DataTypeDesign)dataType.BaseTypeNode,
                                valueRank,
                                targetNamespace,
                                namespaces);
                        }

                        return CoreUtils.Format("xs:int");
                    }

                    string prefix = "tns";

                    if (dataType.SymbolicName.Namespace != targetNamespace)
                    {
                        if (dataType.SymbolicName.Namespace == Namespaces.OpcUa)
                        {
                            if (dataType.SymbolicName.Name == "Enumeration")
                            {
                                if (dataType.IsOptionSet)
                                {
                                    return GetXmlDataType(
                                        (DataTypeDesign)dataType.BaseTypeNode,
                                        valueRank,
                                        targetNamespace,
                                        namespaces);
                                }

                                return CoreUtils.Format("xs:int");
                            }

                            prefix = "ua";
                        }
                        else
                        {
                            prefix = GetXmlNamespacePrefix(namespaces, dataType.SymbolicName.Namespace);
                        }
                    }

                    return CoreUtils.Format("{0}:{1}", prefix, dataType.SymbolicName.Name);
            }
        }

        /// <summary>
        /// Returns a constant for the namespace uri.
        /// </summary>
        public static Namespace GetNamespace(this Namespace[] namespaces, string namespaceUri)
        {
            if (namespaces != null)
            {
                foreach (Namespace ns in namespaces)
                {
                    if (ns.Value == namespaceUri)
                    {
                        return ns;
                    }
                }
            }

            return null;
        }

        /// <summary>
        /// Returns a constant for the namespace uri.
        /// </summary>
        public static string GetConstantForXmlNamespace(this Namespace[] namespaces, string namespaceUri)
        {
            Namespace ns = GetNamespace(namespaces, namespaceUri);
            if (ns != null)
            {
                if (!string.IsNullOrEmpty(ns.XmlNamespace))
                {
                    return CoreUtils.Format("{1}.Namespaces.{0}Xsd", ns.Name, ns.Prefix);
                }

                return CoreUtils.Format("{1}.Namespaces.{0}", ns.Name, ns.Prefix);
            }
            return null;
        }

        /// <summary>
        /// Returns the XML prefix for the specified namespace.
        /// </summary>
        public static string GetXmlNamespacePrefix(this Namespace[] namespaces, string namespaceUri)
        {
            if (namespaceUri == null)
            {
                return null;
            }

            if (namespaces != null)
            {
                for (int ii = 0; ii < namespaces.Length; ii++)
                {
                    if (namespaces[ii].Value == namespaceUri)
                    {
                        if (string.IsNullOrEmpty(namespaces[ii].XmlPrefix))
                        {
                            return CoreUtils.Format("s{0}", ii);
                        }

                        return namespaces[ii].XmlPrefix;
                    }
                }
            }

            return null;
        }

        public static bool IsMethodTypeNode(this NodeDesign node)
        {
            if (node == null)
            {
                return false;
            }

            string symbol = node.SymbolicId.Name;

            int index = symbol.IndexOf('_', StringComparison.Ordinal);

            if (index > 0)
            {
                symbol = symbol[..index];
            }

            return symbol.EndsWith("MethodType", StringComparison.Ordinal);
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
        /// Checks for a null qualified name.
        /// </summary>
        public static bool IsNull(this XmlQualifiedName qname)
        {
            if (qname == null)
            {
                return true;
            }

            if (string.IsNullOrEmpty(qname.Name))
            {
                return true;
            }

            return false;
        }
    }
}
