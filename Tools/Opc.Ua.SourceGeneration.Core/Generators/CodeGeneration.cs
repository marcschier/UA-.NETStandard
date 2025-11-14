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
using System.Globalization;
using System.Linq;
using System.Xml;
using Opc.Ua.Schema.Model;
using Opc.Ua.Schema.Types;
using Opc.Ua.Types;

namespace Opc.Ua.SourceGeneration
{
    /// <summary>
    /// Dotnet code generation support.
    /// </summary>
    internal static class CodeGeneration
    {
        /// <summary>
        /// Returns the default value for a field.
        /// </summary>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="validator"/> is <c>null</c>.
        /// </exception>
        public static string GetDotNetDefaultValue(
            this TypeDictionaryValidator validator,
            FieldType fieldType)
        {
            if (validator == null)
            {
                throw new ArgumentNullException(nameof(validator));
            }

            if (fieldType == null)
            {
                return "null";
            }

            DataType datatype = validator.ResolveType(fieldType.DataType);

            if (datatype == null || string.IsNullOrEmpty(datatype.Name))
            {
                return "null";
            }

            if (fieldType.ValueRank >= 0)
            {
                switch (datatype.Name)
                {
                    case "Guid":
                        return "new UuidCollection()";
                    default:
                        return CoreUtils.Format("new {0}Collection()", datatype.Name);
                }
            }

            if (datatype is EnumeratedType enumeratedType)
            {
                return CoreUtils.Format("{0}.{1}", datatype.Name, enumeratedType.Value[0].Name);
            }

            if (datatype.QName.Namespace != Namespaces.OpcUaBuiltInTypes)
            {
                return CoreUtils.Format("new {0}()", datatype.Name);
            }

            switch (datatype.Name)
            {
                case "Boolean":
                    return "false";
                case "SByte":
                case "Byte":
                case "Int16":
                case "UInt16":
                case "Int32":
                case "UInt32":
                case "Int64":
                case "UInt64":
                case "Float":
                case "Double":
                    return "0";
                case "String":
                case "ByteString":
                case "ExtensionObject":
                case "XmlElement":
                    return "null";
                case "Guid":
                    return "Opc.Ua.Uuid.Empty";
                case "DateTime":
                    return "DateTime.MinValue";
                case "StatusCode":
                    return "Opc.Ua.StatusCodes.Good";
                case "NodeId":
                    return "Opc.Ua.NodeId.Null";
                case "ExpandedNodeId":
                    return "Opc.Ua.ExpandedNodeId.Null";
                case "LocalizedText":
                    return "Opc.Ua.LocalizedText.Null";
                case "QualifiedName":
                    return "Opc.Ua.QualifiedName.Null";
                default:
                    return CoreUtils.Format("new {0}()", datatype.Name);
            }
        }

        /// <summary>
        /// Returns a name qualified with a namespace prefix.
        /// </summary>
        /// <exception cref="ArgumentNullException"><paramref name="validator"/> is <c>null</c>.</exception>
        public static string GetDotNetTypeName(
            this TypeDictionaryValidator validator,
            XmlQualifiedName qname,
            int valueRank)
        {
            if (validator == null)
            {
                throw new ArgumentNullException(nameof(validator));
            }

            if (qname.IsNull())
            {
                return string.Empty;
            }

            DataType datatype = validator.ResolveType(qname);

            if (datatype != null)
            {
                qname = datatype.QName;
            }

            string type = qname.Name;

            if (qname.Namespace == Namespaces.OpcUaBuiltInTypes)
            {
                // translate built-in types to .NET types.
                if (valueRank < 0)
                {
                    switch (qname.Name)
                    {
                        case "Boolean":
                            type = "bool";
                            break;
                        case "SByte":
                            type = "sbyte";
                            break;
                        case "Byte":
                            type = "byte";
                            break;
                        case "Int16":
                            type = "short";
                            break;
                        case "UInt16":
                            type = "ushort";
                            break;
                        case "Int32":
                            type = "int";
                            break;
                        case "UInt32":
                            type = "uint";
                            break;
                        case "Int64":
                            type = "long";
                            break;
                        case "UInt64":
                            type = "ulong";
                            break;
                        case "Float":
                            type = "float";
                            break;
                        case "Double":
                            type = "double";
                            break;
                        case "String":
                            type = "string";
                            break;
                        case "DateTime":
                            type = "DateTime";
                            break;
                        case "Guid":
                            type = "Uuid";
                            break;
                        case "ByteString":
                            type = "byte[]";
                            break;
                    }
                }
                else
                {
                    switch (qname.Name)
                    {
                        case "Guid":
                            type = "Uuid";
                            break;
                    }
                }
            }

            if (valueRank >= 0)
            {
                return CoreUtils.Format("{0}Collection", type);
            }

            return type;
        }

        /// <summary>
        /// Returns the class name to use when creating an instance of the type.
        /// </summary>
        public static string GetClassName(
            this InstanceDesign instance,
            string targetNamespace,
            Namespace[] namespaces)
        {
            if (instance is MethodDesign method)
            {
                string className = method.SymbolicName.Name;

                if (method.TypeDefinition != null)
                {
                    className = method.TypeDefinition.Name;
                }

                if (className.EndsWith("MethodType", StringComparison.Ordinal))
                {
                    className = className[..^"MethodType".Length];
                }
                else if (className.EndsWith("Type", StringComparison.Ordinal))
                {
                    className = className[..^"Type".Length];
                }

                if (method.HasArguments)
                {
                    return CoreUtils.Format("{0}MethodState", className);
                }

                return "MethodState";
            }

            if (instance is not VariableDesign variable)
            {
                return CoreUtils.Format("{0}State", FixClassName(instance.TypeDefinitionNode));
            }

            var variableType = instance.TypeDefinitionNode as VariableTypeDesign;

            // check if the variable type restricted the datatype to eliminate the need for a template parameter.
            if (variableType.DataTypeNode.IsRequiredParameterInTemplates(variableType.ValueRank))
            {
                return CoreUtils.Format("{0}State", FixClassName(variableType));
            }

            // check if the variable instance did not restrict the datatype.
            if (!variable.DataTypeNode.IsRequiredParameterInTemplates(variable.ValueRank))
            {
                return CoreUtils.Format("{0}State", FixClassName(variableType));
            }

            // instance restricted the datatype but the type did not not.
            BasicDataType basicType = variable.DataTypeNode.BasicDataType;

            string scalarName;
            switch (basicType)
            {
                case BasicDataType.UserDefined:
                    scalarName = FixClassName(variable.DataTypeNode);
                    break;
                case BasicDataType.Structure:
                    scalarName = "ExtensionObject";
                    break;
                default:
                    scalarName = GetDotNetTypeName(
                        variable.DataTypeNode,
                        targetNamespace,
                        namespaces);
                    break;
            }

            if (variable.ValueRank == ValueRank.Array)
            {
                return CoreUtils.Format("{0}State<{1}[]>", FixClassName(variableType), scalarName);
            }

            if (IsIndeterminateType(variable))
            {
                return $"{FixClassName(variableType)}State";
            }

            // add hack for TwoStateDiscreteType which always has to be bool.
            if (variableType.SymbolicName == new XmlQualifiedName("TwoStateDiscreteType", Namespaces.OpcUa))
            {
                return $"{FixClassName(variableType)}State";
            }

            return CoreUtils.Format("{0}State<{1}>", FixClassName(variableType), scalarName);
        }

        /// <summary>
        /// Returns the class name to use when creating an instance of the type.
        /// </summary>
        public static string GetBaseClassName(this TypeDesign type, Namespace[] namespaces)
        {
            if (type is not DataTypeDesign dataType || type.BaseTypeNode == null)
            {
                return type.BaseTypeNode.SymbolicName.Name;
            }

            if (((DataTypeDesign)dataType.BaseTypeNode).BasicDataType == BasicDataType.Structure)
            {
                return "IEncodeable";
            }

            string ns = namespaces.GetNamespacePrefix(type.BaseTypeNode.SymbolicId.Namespace);
            return ns + "." + type.BaseTypeNode.SymbolicName.Name;
        }

        /// <summary>
        /// Returns a qualifier for the namespace to use in code.
        /// </summary>
        public static string GetNamespacePrefix(this Namespace[] namespaces, string namespaceUri)
        {
            if (namespaces != null)
            {
                foreach (Namespace ns in namespaces)
                {
                    if (ns.Value == namespaceUri)
                    {
                        return CoreUtils.Format("{0}", ns.Prefix);
                    }
                }
            }

            return null;
        }

        /// <summary>
        /// Returns a constant string for the namespace uri.
        /// </summary>
        public static string GetConstantSymbolForNamespace(this Namespace[] namespaces, string namespaceUri)
        {
            Namespace ns = namespaces.GetNamespace(namespaceUri);
            if (ns != null)
            {
                return CoreUtils.Format("{1}.Namespaces.{0}", ns.Name, ns.Prefix);
            }
            return null;
        }

        public static bool IsOverriddenWithSameClass(
            this InstanceDesign instance,
            string targetNamespace,
            Namespace[] namespaces)
        {
            if (!instance.IsOverridden())
            {
                return false;
            }

            string x = instance.GetMergedInstance().GetClassName(targetNamespace, namespaces);
            string y = instance.OveriddenNode.GetClassName(targetNamespace, namespaces);

            if (y.StartsWith("BaseDataVariableState<", StringComparison.Ordinal) &&
                x.StartsWith("BaseDataVariableState<", StringComparison.Ordinal))
            {
                return true;
            }

            return x == y;
        }

        private static bool IsIndeterminateType(this InstanceDesign instance)
        {
            if (instance is VariableDesign variable)
            {
                if (variable.ValueRank is not ValueRank.Scalar and not ValueRank.Array)
                {
                    return true;
                }

                if (variable.DataType ==
                    new XmlQualifiedName(BrowseNames.Enumeration, Namespaces.OpcUa))
                {
                    return true;
                }
            }

            return false;
        }

        public static string EnsureUniqueEnumName(this Parameter target)
        {
            if (target?.Parent is DataTypeDesign dt && dt.HasFields)
            {
                HashSet<string> names = [];

                foreach (Parameter field in dt.Fields)
                {
                    int count = 1;
                    string check = field.Name;

                    if (names.Contains(check))
                    {
                        check = field.Name + "_" + field.Identifier;
                    }

                    while (names.Contains(check))
                    {
                        check = field.Name + "_v" + count++;
                    }

                    if (target.Identifier == field.Identifier)
                    {
                        return check;
                    }

                    names.Add(check);
                }
            }

            return target?.Name;
        }

        /// <summary>
        /// Returns the field name of a child node.
        /// </summary>
        public static string GetChildFieldName(this Parameter field)
        {
            if (field == null)
            {
                return string.Empty;
            }

            return CoreUtils.Format(
                "m_{0}{1}",
                field.Name[..1].ToLowerInvariant(),
                field.Name[1..]);
        }

        /// <summary>
        /// Returns the field name of a child node.
        /// </summary>
        public static string GetChildFieldName(this InstanceDesign instance)
        {
            if (instance == null)
            {
                return string.Empty;
            }

            string name = CoreUtils.Format(
                "m_{0}{1}",
                instance.SymbolicName.Name[..1].ToLowerInvariant(),
                instance.SymbolicName.Name[1..]);
            if (instance is MethodDesign)
            {
                return CoreUtils.Format("{0}Method", name);
            }

            return name;
        }

        /// <summary>
        /// Fixes class names for nodes.
        /// </summary>
        public static string FixClassName(this TypeDesign node)
        {
            if (node is DataTypeDesign)
            {
                return node.SymbolicId.Name;
            }

            if (node is ObjectTypeDesign objectType &&
                objectType.ClassName == "ObjectSource")
            {
                return "BaseObject";
            }

            if (node is VariableTypeDesign variableType &&
                variableType.ClassName == "DataVariable")
            {
                return "BaseDataVariable";
            }

            return node.ClassName;
        }

        /// <summary>
        /// Returns checks if the field is a reference type.
        /// </summary>
        public static bool IsDotNetReferenceType(
            this TypeDictionaryValidator validator,
            FieldType fieldType)
        {
            DataType datatype = validator.ResolveType(fieldType.DataType);

            if (datatype == null || string.IsNullOrEmpty(datatype.Name))
            {
                return false;
            }

            if (fieldType.ValueRank >= 0)
            {
                return true;
            }

            if (datatype is EnumeratedType)
            {
                return false;
            }

            if (datatype.QName.Namespace != Namespaces.OpcUaBuiltInTypes)
            {
                return true;
            }

            switch (datatype.Name)
            {
                case "Boolean":
                case "SByte":
                case "Byte":
                case "Int16":
                case "UInt16":
                case "Int32":
                case "UInt32":
                case "Int64":
                case "UInt64":
                case "Float":
                case "Double":
                case "Guid":
                case "DateTime":
                case "StatusCode":
                case "Variant":
                    return false;
                default:
                    return true;
            }
        }

        /// <summary>
        /// Returns the NodeClass of a Node
        /// </summary>
        public static string GetNodeClassString(this NodeDesign node)
        {
            if (node is VariableDesign)
            {
                return "Variable";
            }

            if (node is VariableTypeDesign)
            {
                return "VariableType";
            }

            if (node is ObjectDesign)
            {
                return "Object";
            }

            if (node is ObjectTypeDesign)
            {
                return "ObjectType";
            }

            if (node is ReferenceTypeDesign)
            {
                return "ReferenceType";
            }

            if (node is DataTypeDesign)
            {
                return "DataType";
            }

            if (node is MethodDesign)
            {
                return "Method";
            }

            if (node is ViewDesign)
            {
                return "View";
            }

            return "Node";
        }

        /// <summary>
        /// Returns a boolean value as text.
        /// </summary>
        public static string GetBooleanString(bool value)
        {
            return value ? "true" : "false";
        }

        /// <summary>
        /// Maps the event notifier flag onto a string.
        /// </summary>
        public static string GetEventNotifierString(bool supportsEvents)
        {
            if (supportsEvents)
            {
                return "EventNotifiers.SubscribeToEvents";
            }

            return "EventNotifiers.None";
        }

        /// <summary>
        /// Maps the access level enumeration onto a string.
        /// </summary>
        public static string GetAccessLevelString(this AccessLevel accessLevel)
        {
            return accessLevel switch
            {
                AccessLevel.Read => "AccessLevels.CurrentRead",
                AccessLevel.Write => "AccessLevels.CurrentWrite",
                AccessLevel.ReadWrite => "AccessLevels.CurrentReadOrWrite",
                AccessLevel.HistoryRead => "AccessLevels.HistoryRead",
                AccessLevel.HistoryWrite => "AccessLevels.HistoryWrite",
                AccessLevel.HistoryReadWrite => "AccessLevels.HistoryReadOrWrite",
                _ => "AccessLevels.None"
            };
        }

        /// <summary>
        /// Maps the value rank enumeration onto a string.
        /// </summary>
        public static string GetValueRankString(this ValueRank valueRank, string arrayDimensions)
        {
            switch (valueRank)
            {
                case ValueRank.Array:
                    return "ValueRanks.OneDimension";
                case ValueRank.Scalar:
                    return "ValueRanks.Scalar";
                case ValueRank.Any:
                case ValueRank.ScalarOrArray:
                    return "ValueRanks.Any";
                case ValueRank.ScalarOrOneDimension:
                    return "ValueRanks.ScalarOrOneDimension";
                case ValueRank.OneOrMoreDimensions:
                    if (string.IsNullOrEmpty(arrayDimensions))
                    {
                        return "ValueRanks.OneOrMoreDimensions";
                    }

                    string[] dimensions = arrayDimensions.Split([','], StringSplitOptions.RemoveEmptyEntries);

                    if (dimensions.Length == 1)
                    {
                        return "ValueRanks.TwoDimensions";
                    }
                    return CoreUtils.Format("{0}", dimensions.Length + 1);
            }

            return "ValueRanks.Any";
        }

        /// <summary>
        /// Maps the array dimensions onto a constant declaration.
        /// </summary>
        public static string GetArrayDimensionsString(this ValueRank valueRank, string arrayDimensions)
        {
            if (valueRank != ValueRank.OneOrMoreDimensions)
            {
                return "null";
            }
            return CoreUtils.Format("new uint[] {{{0}}}", arrayDimensions);
        }

        /// <summary>
        /// Maps the MinimumSamplingInterval onto a constant.
        /// </summary>
        public static string GetMinimumSamplingIntervalString(int minimumSamplingInterval)
        {
            return minimumSamplingInterval switch
            {
                -1 => "MinimumSamplingIntervals.Indeterminate",
                0 => "MinimumSamplingIntervals.Continuous",
                _ => minimumSamplingInterval.ToString(CultureInfo.InvariantCulture)
            };
        }

        /// <summary>
        /// Whether a template parameter is required.
        /// </summary>
        public static string GetDefaultDotNetValue(
            this DataTypeDesign dataType,
            ValueRank valueRank,
            XmlElement defaultValue,
            object decodedValue,
            bool useVariantForObject,
            string targetNamespace,
            Namespace[] namespaces,
            IServiceMessageContext context)
        {
            if (valueRank == ValueRank.Array)
            {
                if (!useVariantForObject)
                {
                    return "null";
                }
                return CoreUtils.Format("new {0}()", GetDotNetTypeName(dataType, valueRank, targetNamespace, namespaces));
            }

            if (dataType.BasicDataType == BasicDataType.BaseDataType || valueRank != ValueRank.Scalar)
            {
                if (useVariantForObject)
                {
                    return "Variant.Null";
                }

                return "null";
            }

            TypeInfo decodedValueType = null;

            if (decodedValue == null && defaultValue != null)
            {
                using var decoder = new XmlDecoder(defaultValue, context);
                decodedValue = decoder.ReadVariantContents(out decodedValueType);
            }

            switch (dataType.BasicDataType)
            {
                case BasicDataType.Boolean:
                    if (decodedValue is not bool boolValue)
                    {
                        boolValue = false;
                    }

                    if (defaultValue != null && decodedValueType == TypeInfo.Scalars.Boolean)
                    {
                        return boolValue ? "true" : "false";
                    }

                    // this is technically a bug but the potential for side effects is
                    // so large that it is better to leave as is.
                    return boolValue ? "false" : "true";
                case BasicDataType.SByte:
                    if (decodedValue is not sbyte sbyteValue)
                    {
                        sbyteValue = 0;
                    }
                    return CoreUtils.Format("(sbyte){0}", sbyteValue);
                case BasicDataType.Byte:
                    if (decodedValue is not byte byteValue)
                    {
                        byteValue = 0;
                    }
                    return CoreUtils.Format("(byte){0}", byteValue);
                case BasicDataType.Int16:
                    if (decodedValue is not short shortValue)
                    {
                        shortValue = 0;
                    }
                    return CoreUtils.Format("(short){0}", shortValue);
                case BasicDataType.UInt16:
                    if (decodedValue is not ushort ushortValue)
                    {
                        ushortValue = 0;
                    }
                    return CoreUtils.Format("(ushort){0}", ushortValue);
                case BasicDataType.Int32:
                    if (decodedValue is not int intValue)
                    {
                        intValue = 0;
                    }
                    return CoreUtils.Format("(int){0}", intValue);
                case BasicDataType.UInt32:
                    if (decodedValue is not uint uintValue)
                    {
                        uintValue = 0;
                    }
                    return CoreUtils.Format("(uint){0}", uintValue);
                case BasicDataType.Integer:
                case BasicDataType.Int64:
                    if (decodedValue is not long longValue)
                    {
                        longValue = 0;
                    }
                    return CoreUtils.Format("(long){0}", longValue);
                case BasicDataType.UInteger:
                case BasicDataType.UInt64:
                    if (decodedValue is not ulong ulongValue)
                    {
                        ulongValue = 0;
                    }
                    return CoreUtils.Format("(ulong){0}", ulongValue);
                case BasicDataType.Float:
                    if (decodedValue is not float floatValue)
                    {
                        floatValue = 0;
                    }
                    return CoreUtils.Format("(float){0}", floatValue);
                case BasicDataType.Number:
                case BasicDataType.Double:
                    if (decodedValue is not double doubleValue)
                    {
                        doubleValue = 0;
                    }
                    return CoreUtils.Format("(double){0}", doubleValue);
                case BasicDataType.String:
                    if (decodedValue is not string stringValue)
                    {
                        return "null";
                    }
                    return CoreUtils.Format("\"{0}\"", stringValue);
                case BasicDataType.DateTime:
                    if (decodedValue is not DateTime dateTimeValue)
                    {
                        return "DateTime.MinValue";
                    }
                    return CoreUtils.Format(
                        "DateTime.ParseExact(\"{0:yyyy-MM-dd HH:mm:ss}\", \"yyyy-MM-dd HH:mm:ss\", System.Globalization.CultureInfo.InvariantCulture)",
                        dateTimeValue);
                case BasicDataType.Guid:
                    if (decodedValue is not Uuid uuidValue)
                    {
                        return "Uuid.Empty";
                    }
                    return CoreUtils.Format("new Uuid(\"{0}\")", uuidValue);
                case BasicDataType.ByteString:
                    if (decodedValue is not byte[] byteStringValue)
                    {
                        return "null";
                    }
                    return CoreUtils.Format("CoreUtils.FromHexString(\"{0}\")", CoreUtils.ToHexString(byteStringValue));
                case BasicDataType.NodeId:
                    if (decodedValue is not NodeId nodeId)
                    {
                        return "null";
                    }

                    if (nodeId.NamespaceIndex == 0 || nodeId.NamespaceIndex >= namespaces.Length)
                    {
                        return CoreUtils.Format("NodeId.Parse(\"{0}\")", nodeId);
                    }

                    var absoluteId = new ExpandedNodeId(nodeId, namespaces[nodeId.NamespaceIndex].Value);
                    return CoreUtils.Format("ExpandedNodeId.Parse(\"{0}\", context.NamespaceUris)", absoluteId);
                case BasicDataType.ExpandedNodeId:
                    if (decodedValue is not ExpandedNodeId expandedNodeId)
                    {
                        return "null";
                    }
                    return CoreUtils.Format("ExpandedNodeId.Parse(\"{0}\")", expandedNodeId);
                case BasicDataType.QualifiedName:
                    if (decodedValue is not QualifiedName qualifiedName)
                    {
                        return "null";
                    }
                    return CoreUtils.Format("QualifiedName.Parse(\"{0}\")", qualifiedName);
                case BasicDataType.LocalizedText:
                    if (decodedValue is not LocalizedText localizedText)
                    {
                        return "null";
                    }
                    return CoreUtils.Format("new LocalizedText(\"{0}\", \"{1}\")", localizedText.Locale, localizedText.Text);
                case BasicDataType.StatusCode:
                    if (decodedValue is not StatusCode statusCode)
                    {
                        return "StatusCodes.Good";
                    }
                    return CoreUtils.Format("(StatusCode){0}", statusCode);
                case BasicDataType.Enumeration:
                    if (dataType.SymbolicId == new XmlQualifiedName("Enumeration", Namespaces.OpcUa))
                    {
                        return "0";
                    }
                    if (dataType.BaseTypeNode.SymbolicId == new XmlQualifiedName("OptionSet", Namespaces.OpcUa))
                    {
                        return $"new {dataType.SymbolicName.Name}()";
                    }
                    if (dataType.IsOptionSet)
                    {
                        return "0";
                    }
                    if (dataType.IsOptionSet)
                    {
                        return CoreUtils.Format("{0}.None", dataType.SymbolicName.Name);
                    }
                    return CoreUtils.Format("{0}.{1}", dataType.SymbolicName.Name, dataType.Fields[0].Name);
                case BasicDataType.DataValue:
                    return "new DataValue()";
                case BasicDataType.Structure:
                case BasicDataType.XmlElement:
                    return "null";
                case BasicDataType.UserDefined:
                    if (useVariantForObject)
                    {
                        return CoreUtils.Format(
                            "new {0}()",
                            GetDotNetTypeName(dataType, ValueRank.Scalar, targetNamespace, namespaces));
                    }

                    return "null";
                default:
                    return "null";
            }
        }

        /// <summary>
        /// Returns the data type for a method argument.
        /// </summary>
        public static string GetMethodArgumentDotNetType(
            this DataTypeDesign datatype,
            ValueRank valueRank,
            string targetNamespace,
            Namespace[] namespaces)
        {
            string typeName = GetDotNetTypeName(datatype, targetNamespace, namespaces);

            if (typeName == "Guid")
            {
                typeName = "Uuid";
            }
            else if (typeName == "IEncodeable")
            {
                typeName = "ExtensionObject";
            }

            if (valueRank == ValueRank.Array)
            {
                if (typeName == "object")
                {
                    typeName = "Variant";
                }

                return typeName + "[]";
            }

            if (valueRank == ValueRank.Scalar)
            {
                return typeName;
            }

            return "object";
        }

        /// <summary>
        /// Returns true if the type is nullable
        /// </summary>
        /// <param name="type"></param>
        /// <returns></returns>
        public static bool IsNullable(this BasicDataType type)
        {
            switch (type)
            {
                case BasicDataType.Boolean:
                case BasicDataType.SByte:
                case BasicDataType.Byte:
                case BasicDataType.Int16:
                case BasicDataType.UInt16:
                case BasicDataType.Int32:
                case BasicDataType.UInt32:
                case BasicDataType.Int64:
                case BasicDataType.UInt64:
                case BasicDataType.Float:
                case BasicDataType.Double:
                case BasicDataType.StatusCode:
                case BasicDataType.Enumeration:
                    return false;
            }

            return true;
        }

        /// <summary>
        /// Returns system type for a basic data type.
        /// </summary>
        public static string GetDotNetTypeName(
            this DataTypeDesign datatype,
            string targetNamespace,
            Namespace[] namespaces)
        {
            switch (datatype.BasicDataType)
            {
                case BasicDataType.Boolean:
                    return "bool";
                case BasicDataType.SByte:
                    return "sbyte";
                case BasicDataType.Byte:
                    return "byte";
                case BasicDataType.Int16:
                    return "short";
                case BasicDataType.UInt16:
                    return "ushort";
                case BasicDataType.Int32:
                    return "int";
                case BasicDataType.UInt32:
                    return "uint";
                case BasicDataType.Int64:
                    return "long";
                case BasicDataType.UInt64:
                    return "ulong";
                case BasicDataType.Float:
                    return "float";
                case BasicDataType.Double:
                    return "double";
                case BasicDataType.String:
                    return "string";
                case BasicDataType.DateTime:
                    return "DateTime";
                case BasicDataType.Guid:
                    return "Guid";
                case BasicDataType.ByteString:
                    return "byte[]";
                case BasicDataType.XmlElement:
                    return "XmlElement";
                case BasicDataType.NodeId:
                    return "NodeId";
                case BasicDataType.ExpandedNodeId:
                    return "ExpandedNodeId";
                case BasicDataType.StatusCode:
                    return "StatusCode";
                case BasicDataType.DiagnosticInfo:
                    return "DiagnosticInfo";
                case BasicDataType.QualifiedName:
                    return "QualifiedName";
                case BasicDataType.LocalizedText:
                    return "LocalizedText";
                case BasicDataType.DataValue:
                    return "DataValue";
                case BasicDataType.Number:
                case BasicDataType.Integer:
                case BasicDataType.UInteger:
                case BasicDataType.BaseDataType:
                    return "object";
                case BasicDataType.Structure:
                    return "ExtensionObject";
                case BasicDataType.Enumeration:
                    if (datatype.SymbolicId == new XmlQualifiedName("Enumeration", Namespaces.OpcUa))
                    {
                        return "int";
                    }

                    if (datatype.IsOptionSet)
                    {
                        return GetDotNetTypeName((DataTypeDesign)datatype.BaseTypeNode, targetNamespace, namespaces);
                    }

                    return datatype.SymbolicName.Name;
                case BasicDataType.UserDefined:
                    if (datatype.SymbolicId.Namespace != targetNamespace)
                    {
                        Namespace ns = namespaces.FirstOrDefault(x => x.Value == datatype.SymbolicId.Namespace);
                        return $"{ns.Prefix}.{datatype.SymbolicName.Name}";
                    }

                    return datatype.SymbolicName.Name;
            }

            return "object";
        }

        /// <summary>
        /// Returns system type for a basic data type.
        /// </summary>
        public static string GetDotNetTypeName(
            this DataTypeDesign datatype,
            ValueRank valueRank,
            string targetNamespace,
            Namespace[] namespaces)
        {
            if (valueRank == ValueRank.Scalar)
            {
                string typeName = GetDotNetTypeName(datatype, targetNamespace, namespaces);

                if (typeName == "Guid")
                {
                    return "Uuid";
                }

                if (typeName == "object")
                {
                    return "Variant";
                }

                if (typeName == "IEncodeable")
                {
                    return "ExtensionObject";
                }

                return typeName;
            }

            if (valueRank == ValueRank.Array)
            {
                switch (datatype.BasicDataType)
                {
                    case BasicDataType.Boolean:
                        return "BooleanCollection";
                    case BasicDataType.SByte:
                        return "SByteCollection";
                    case BasicDataType.Byte:
                        return "ByteCollection";
                    case BasicDataType.Int16:
                        return "Int16Collection";
                    case BasicDataType.UInt16:
                        return "UInt16Collection";
                    case BasicDataType.Int32:
                        return "Int32Collection";
                    case BasicDataType.UInt32:
                        return "UInt32Collection";
                    case BasicDataType.Int64:
                        return "Int64Collection";
                    case BasicDataType.UInt64:
                        return "UInt64Collection";
                    case BasicDataType.Float:
                        return "FloatCollection";
                    case BasicDataType.Double:
                        return "DoubleCollection";
                    case BasicDataType.String:
                        return "StringCollection";
                    case BasicDataType.DateTime:
                        return "DateTimeCollection";
                    case BasicDataType.Guid:
                        return "UuidCollection";
                    case BasicDataType.ByteString:
                        return "ByteStringCollection";
                    case BasicDataType.XmlElement:
                        return "XmlElementCollection";
                    case BasicDataType.NodeId:
                        return "NodeIdCollection";
                    case BasicDataType.ExpandedNodeId:
                        return "ExpandedNodeIdCollection";
                    case BasicDataType.StatusCode:
                        return "StatusCodeCollection";
                    case BasicDataType.DiagnosticInfo:
                        return "DiagnosticInfoCollection";
                    case BasicDataType.QualifiedName:
                        return "QualifiedNameCollection";
                    case BasicDataType.LocalizedText:
                        return "LocalizedTextCollection";
                    case BasicDataType.DataValue:
                        return "DataValueCollection";
                    case BasicDataType.Number:
                    case BasicDataType.Integer:
                    case BasicDataType.UInteger:
                    case BasicDataType.BaseDataType:
                        return "VariantCollection";
                    case BasicDataType.Structure:
                        return "ExtensionObjectCollection";
                    case BasicDataType.Enumeration:
                        if (datatype.SymbolicId == new XmlQualifiedName("Enumeration", Namespaces.OpcUa))
                        {
                            return "Int32Collection";
                        }

                        if (datatype.IsOptionSet || datatype.BaseType != new XmlQualifiedName("Enumeration", Namespaces.OpcUa))
                        {
                            return GetDotNetTypeName((DataTypeDesign)datatype.BaseTypeNode, valueRank, targetNamespace, namespaces);
                        }

                        return datatype.SymbolicName.Name + "Collection";
                    case BasicDataType.UserDefined:
                        return datatype.SymbolicName.Name + "Collection";
                }
            }

            return "Variant";
        }

        /// <summary>
        /// Whether a template parameter is required.
        /// </summary>
        public static bool IsRequiredParameterInTemplates(
            this DataTypeDesign dataType,
            ValueRank valueRank)
        {
            if (dataType.BasicDataType
                is not BasicDataType.BaseDataType
                and not BasicDataType.Number
                and not BasicDataType.UInteger
                and not BasicDataType.Integer &&
                valueRank
                    is not ValueRank.OneOrMoreDimensions
                    and not ValueRank.ScalarOrOneDimension
                    and not ValueRank.ScalarOrArray)
            {
                return true;
            }
            if (valueRank == ValueRank.Array)
            {
                return true;
            }
            return false;
        }
    }
}
