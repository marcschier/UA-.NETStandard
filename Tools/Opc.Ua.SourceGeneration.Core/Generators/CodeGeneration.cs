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
                        return "new global::Opc.Ua.UuidCollection()";
                    default:
                        return CoreUtils.Format("new {0}Collection()", datatype.Name);
                }
            }

            if (datatype is EnumeratedType enumeratedType)
            {
                return CoreUtils.Format(
                    "{0}.{1}",
                    datatype.Name,
                    enumeratedType.Value[0].Name);
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
                    return "global::Opc.Ua.Uuid.Empty";
                case "DateTime":
                    return "global::System.DateTime.MinValue";
                case "StatusCode":
                    return "global::Opc.Ua.StatusCodes.Good";
                case "NodeId":
                    return "global::Opc.Ua.NodeId.Null";
                case "ExpandedNodeId":
                    return "global::Opc.Ua.ExpandedNodeId.Null";
                case "LocalizedText":
                    return "global::Opc.Ua.LocalizedText.Null";
                case "QualifiedName":
                    return "global::Opc.Ua.QualifiedName.Null";
                default:
                    return CoreUtils.Format("new {0}()", datatype.Name);
            }
        }

        /// <summary>
        /// Returns a name qualified with a namespace prefix.
        /// </summary>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="validator"/> is <c>null</c>.</exception>
        public static string GetDotNetTypeName(
            this TypeDictionaryValidator validator,
            XmlQualifiedName qname,
            int valueRank,
            bool nullable = false)
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
            if (datatype is EnumeratedType)
            {
                nullable = false;
            }

            if (datatype != null && !datatype.QName.IsNull())
            {
                qname = datatype.QName;
            }

            string typeName = qname.Name;
            if (qname.Namespace == Namespaces.OpcUaBuiltInTypes)
            {
                // translate built-in types to .NET types.
                if (valueRank < 0)
                {
                    switch (qname.Name)
                    {
                        case "Boolean":
                            return "bool";
                        case "SByte":
                            return "sbyte";
                        case "Byte":
                            return "byte";
                        case "Int16":
                            return "short";
                        case "UInt16":
                            return "ushort";
                        case "Int32":
                            return "int";
                        case "UInt32":
                            return "uint";
                        case "Int64":
                            return "long";
                        case "UInt64":
                            return "ulong";
                        case "Float":
                            return "float";
                        case "Double":
                            return "double";
                        case "String":
                            return !nullable ? "string" : "string?";
                        case "DateTime":
                            return "global::System.DateTime";
                        case "Guid":
                            return "global::Opc.Ua.Uuid";
                        case "ByteString":
                            return !nullable ? "byte[]" : "byte[]?";
                    }
                }
                switch (qname.Name)
                {
                    case "Guid":
                        typeName = "global::Opc.Ua.Uuid";
                        break;
                }
            }
            if (valueRank >= 0)
            {
                // Leave collections always non nullable even though they can
                // serialized as null value.  But properties are always init
                // as collection never null
                return CoreUtils.Format("{0}Collection", typeName);
            }
            return !nullable ?
                typeName : CoreUtils.Format("{0}?", typeName);
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

                    if (className.EndsWith("MethodType", StringComparison.Ordinal))
                    {
                        className = className[..^"MethodType".Length];
                    }
                    else if (className.EndsWith("Type", StringComparison.Ordinal))
                    {
                        className = className[..^"Type".Length];
                    }
                }
                if (className.EndsWith("MethodType", StringComparison.Ordinal))
                {
                    className = className[..^"MethodType".Length];
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

            // check if the variable type restricted the datatype to eliminate the
            // need for a template parameter.
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
                    scalarName = "global::Opc.Ua.ExtensionObject";
                    break;
                default:
                    scalarName = GetDotNetTypeName(
                        variable.DataTypeNode,
                        targetNamespace,
                        namespaces,
                        nullable: false);
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
                return "global::Opc.Ua.IEncodeable";
            }

            string ns = namespaces.GetNamespacePrefix(type.BaseTypeNode.SymbolicId.Namespace);
            return ns + "." + type.BaseTypeNode.SymbolicName.Name;
        }

        /// <summary>
        /// Returns the class name to use when creating an instance of the type.
        /// </summary>
        public static bool IsDerivedDataType(this TypeDesign type, Namespace[] namespaces)
        {
            if (type is not DataTypeDesign || type.BaseTypeNode is not DataTypeDesign dtd)
            {
                return true;
            }
            return dtd.BasicDataType != BasicDataType.Structure;
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
                return "global::Opc.Ua.EventNotifiers.SubscribeToEvents";
            }

            return "global::Opc.Ua.EventNotifiers.None";
        }

        /// <summary>
        /// Maps the access level enumeration onto a string.
        /// </summary>
        public static string GetAccessLevelString(this AccessLevel accessLevel)
        {
            return accessLevel switch
            {
                AccessLevel.Read => "global::Opc.Ua.AccessLevels.CurrentRead",
                AccessLevel.Write => "global::Opc.Ua.AccessLevels.CurrentWrite",
                AccessLevel.ReadWrite => "global::Opc.Ua.AccessLevels.CurrentReadOrWrite",
                AccessLevel.HistoryRead => "global::Opc.Ua.AccessLevels.HistoryRead",
                AccessLevel.HistoryWrite => "global::Opc.Ua.AccessLevels.HistoryWrite",
                AccessLevel.HistoryReadWrite => "global::Opc.Ua.AccessLevels.HistoryReadOrWrite",
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
                    return "global::Opc.Ua.ValueRanks.OneDimension";
                case ValueRank.Scalar:
                    return "global::Opc.Ua.ValueRanks.Scalar";
                case ValueRank.Any:
                case ValueRank.ScalarOrArray:
                    return "global::Opc.Ua.ValueRanks.Any";
                case ValueRank.ScalarOrOneDimension:
                    return "global::Opc.Ua.ValueRanks.ScalarOrOneDimension";
                case ValueRank.OneOrMoreDimensions:
                    if (string.IsNullOrEmpty(arrayDimensions))
                    {
                        return "global::Opc.Ua.ValueRanks.OneOrMoreDimensions";
                    }

                    string[] dimensions = arrayDimensions.Split([','], StringSplitOptions.RemoveEmptyEntries);

                    if (dimensions.Length == 1)
                    {
                        return "global::Opc.Ua.ValueRanks.TwoDimensions";
                    }
                    return CoreUtils.Format("{0}", dimensions.Length + 1);
            }

            return "global::Opc.Ua.ValueRanks.Any";
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
                -1 => "global::Opc.Ua.MinimumSamplingIntervals.Indeterminate",
                0 => "global::Opc.Ua.MinimumSamplingIntervals.Continuous",
                _ => minimumSamplingInterval.ToString(CultureInfo.InvariantCulture)
            };
        }

        /// <summary>
        /// Whether this is a reference type and implicitly nullable
        /// </summary>
        public static bool IsDotNetReferenceType(
            this DataTypeDesign dataType,
            ValueRank valueRank)
        {
            return !IsDotNetValueType(dataType, valueRank);
        }

        /// <summary>
        /// Whether the data type supports equality comparison in .NET.
        /// </summary>
        public static bool IsDotNetEqualityComparable(
            this DataTypeDesign dataType,
            ValueRank valueRank)
        {
            if (IsDotNetValueType(dataType, valueRank))
            {
                return true;
            }
            if (valueRank == ValueRank.Scalar)
            {
                switch (dataType.BasicDataType)
                {
                    case BasicDataType.String:
                        // Use equality for strings
                        return true;
                    default:
                        return false;
                }
            }
            return false;
        }

        /// <summary>
        /// If the data type is a value type in .NET.
        /// </summary>
        public static bool IsDotNetValueType(
            this DataTypeDesign dataType,
            ValueRank valueRank)
        {
            if (valueRank != ValueRank.Scalar)
            {
                return false;
            }
            switch (dataType.BasicDataType)
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
                case BasicDataType.DateTime:
                case BasicDataType.Guid:
                case BasicDataType.NodeId:
                case BasicDataType.ExpandedNodeId:
                case BasicDataType.QualifiedName:
                case BasicDataType.LocalizedText:
                case BasicDataType.StatusCode:
                // case BasicDataType.BaseDataType: // Variant
                    return true;
                default:
                    return false;
            }
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
                return CoreUtils.Format("new {0}()", GetDotNetTypeName(
                    dataType,
                    valueRank,
                    targetNamespace,
                    namespaces,
                    nullable: false));
            }

            if (dataType.BasicDataType == BasicDataType.BaseDataType ||
                valueRank != ValueRank.Scalar)
            {
                if (useVariantForObject)
                {
                    return "global::Opc.Ua.Variant.Null";
                }

                return "null";
            }

            TypeInfo decodedValueType = default;

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
                    if (stringValue.Length == 0)
                    {
                        return "string.Empty";
                    }
                    return CoreUtils.Format("\"{0}\"", stringValue);
                case BasicDataType.DateTime:
                    if (decodedValue is not DateTime dateTimeValue ||
                        dateTimeValue == DateTime.MinValue)
                    {
                        return "global::System.DateTime.MinValue";
                    }
                    return CoreUtils.Format(
                        "global::System.DateTime.ParseExact(\"{0:yyyy-MM-dd HH:mm:ss}\", \"yyyy-MM-dd HH:mm:ss\", global::System.Globalization.CultureInfo.InvariantCulture)",
                        dateTimeValue);
                case BasicDataType.Guid:
                    if (decodedValue is Uuid uuid)
                    {
                        decodedValue = uuid.Guid;
                    }
                    if (decodedValue is not Guid guidValue ||
                        guidValue == Guid.Empty)
                    {
                        return "global::Opc.Ua.Uuid.Empty";
                    }
                    return CoreUtils.Format(
                        "global::Opc.Ua.Uuid.Parse(\"{0}\")",
                        guidValue);
                case BasicDataType.ByteString:
                    if (decodedValue is not byte[] byteStringValue)
                    {
                        return "null";
                    }
                    return CoreUtils.Format(
                        "CoreUtils.FromHexString(\"{0}\")",
                        CoreUtils.ToHexString(byteStringValue));
                case BasicDataType.NodeId:
                    if (decodedValue is not NodeId nodeId ||
                        nodeId.IsNullNodeId)
                    {
                        return "global::Opc.Ua.NodeId.Null";
                    }
                    if (nodeId.NamespaceIndex == 0 ||
                        nodeId.NamespaceIndex >= namespaces.Length)
                    {
                        return CoreUtils.Format(
                            "global::Opc.Ua.NodeId.Parse(\"{0}\")",
                            nodeId);
                    }
                    var absoluteId = new ExpandedNodeId(
                        nodeId,
                        namespaces[nodeId.NamespaceIndex].Value);
                    return CoreUtils.Format(
                        "ExpandedNodeId.Parse(\"{0}\", context.NamespaceUris)",
                        absoluteId);
                case BasicDataType.ExpandedNodeId:
                    if (decodedValue is not ExpandedNodeId expandedNodeId ||
                        expandedNodeId.IsNull)
                    {
                        return "global::Opc.Ua.ExpandedNodeId.Null";
                    }
                    return CoreUtils.Format(
                        "global::Opc.Ua.ExpandedNodeId.Parse(\"{0}\")",
                        expandedNodeId);
                case BasicDataType.QualifiedName:
                    if (decodedValue is not QualifiedName qualifiedName ||
                        qualifiedName.IsNullQn)
                    {
                        return "global::Opc.Ua.QualifiedName.Null";
                    }
                    return CoreUtils.Format(
                        "global::Opc.Ua.QualifiedName.Parse(\"{0}\")",
                        qualifiedName);
                case BasicDataType.LocalizedText:
                    if (decodedValue is not LocalizedText localizedText ||
                        localizedText.IsNullOrEmpty)
                    {
                        return "global::Opc.Ua.LocalizedText.Null";
                    }
                    return CoreUtils.Format(
                        "new global::Opc.Ua.LocalizedText(\"{0}\", \"{1}\")",
                        localizedText.Locale,
                        localizedText.Text);
                case BasicDataType.StatusCode:
                    if (decodedValue is not StatusCode statusCode ||
                        statusCode.Code == 0)
                    {
                        return "global::Opc.Ua.StatusCodes.Good";
                    }
                    return CoreUtils.Format("(StatusCode){0}", statusCode);
                case BasicDataType.Enumeration:
                    if (dataType.SymbolicId ==
                        new XmlQualifiedName("Enumeration", Namespaces.OpcUa))
                    {
                        return "0";
                    }
                    if (dataType.BaseTypeNode.SymbolicId ==
                        new XmlQualifiedName("OptionSet", Namespaces.OpcUa))
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
                    return CoreUtils.Format(
                        "{0}.{1}",
                        dataType.SymbolicName.Name,
                        dataType.Fields[0].Name);
                case BasicDataType.DataValue:
                    return "new global::Opc.Ua.DataValue()";
                case BasicDataType.Structure:
                case BasicDataType.XmlElement:
                    return "null";
                case BasicDataType.UserDefined:
                    if (useVariantForObject)
                    {
                        return CoreUtils.Format(
                            "new {0}()",
                            GetDotNetTypeName(
                                dataType,
                                ValueRank.Scalar,
                                targetNamespace,
                                namespaces,
                                nullable: false));
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
            Namespace[] namespaces,
            bool isOptional)
        {
            string typeName = GetDotNetTypeName(
                datatype,
                targetNamespace,
                namespaces,
                nullable: isOptional);

            if (typeName is "global::Opc.Ua.IEncodeable")
            {
                typeName = "global::Opc.Ua.ExtensionObject";
            }
            else if (typeName is "global::Opc.Ua.IEncodeable?")
            {
                typeName = "global::Opc.Ua.ExtensionObject?";
            }
            if (valueRank == ValueRank.Array)
            {
                if (typeName is "object" or "object?")
                {
                    typeName = "global::Opc.Ua.Variant";
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
        public static bool IsXmlNillable(this BasicDataType type)
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
            Namespace[] namespaces,
            bool nullable = false)
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
                    return !nullable ? "string" : "string?";
                case BasicDataType.DateTime:
                    return "global::System.DateTime";
                case BasicDataType.Guid:
                    return "global::Opc.Ua.Uuid";
                case BasicDataType.ByteString:
                    return !nullable ? "byte[]" : "byte[]?";
                case BasicDataType.XmlElement:
                    return "global::System.Xml.XmlElement";
                case BasicDataType.NodeId:
                    return "global::Opc.Ua.NodeId";
                case BasicDataType.ExpandedNodeId:
                    return "global::Opc.Ua.ExpandedNodeId";
                case BasicDataType.StatusCode:
                    return "global::Opc.Ua.StatusCode";
                case BasicDataType.DiagnosticInfo:
                    return !nullable ? "global::Opc.Ua.DiagnosticInfo" : "global::Opc.Ua.DiagnosticInfo?";
                case BasicDataType.QualifiedName:
                    return "global::Opc.Ua.QualifiedName";
                case BasicDataType.LocalizedText:
                    return "global::Opc.Ua.LocalizedText";
                case BasicDataType.DataValue:
                    return "global::Opc.Ua.DataValue";
                case BasicDataType.Structure:
                    return "global::Opc.Ua.ExtensionObject";
                case BasicDataType.Enumeration:
                    if (datatype.SymbolicId ==
                        new XmlQualifiedName("Enumeration", Namespaces.OpcUa))
                    {
                        return "int";
                    }

                    if (datatype.IsOptionSet)
                    {
                        return GetDotNetTypeName(
                            (DataTypeDesign)datatype.BaseTypeNode,
                            targetNamespace,
                            namespaces,
                            nullable); // Should it always be non nullable?
                    }
                    return datatype.SymbolicName.Name;
                case BasicDataType.UserDefined:
                    string typeName;
                    if (datatype.SymbolicId.Namespace != targetNamespace)
                    {
                        Namespace ns = namespaces
                            .FirstOrDefault(x => x.Value == datatype.SymbolicId.Namespace);
                        typeName = $"{ns.Prefix}.{datatype.SymbolicName.Name}";
                    }
                    else
                    {
                        typeName = datatype.SymbolicName.Name;
                    }
                    if (datatype.IsEnumeration)
                    {
                        return typeName;
                    }
                    // TODO: Handle nullable user defined types
                    // All of these are always set to default type in properties when null
                    // is passed.
                    return typeName; // !nullable ? typeName : typeName + "?";
            }
            return !nullable ? "object" : "object?";
        }

        /// <summary>
        /// Returns system type for a basic data type.
        /// </summary>
        public static string GetDotNetTypeName(
            this DataTypeDesign datatype,
            ValueRank valueRank,
            string targetNamespace,
            Namespace[] namespaces,
            bool nullable = false)
        {
            if (valueRank == ValueRank.Scalar)
            {
                string typeName = GetDotNetTypeName(
                    datatype,
                    targetNamespace,
                    namespaces,
                    nullable);

                if (typeName is "object" or "object?")
                {
                    return "global::Opc.Ua.Variant";
                }

                if (typeName is "global::Opc.Ua.IEncodeable")
                {
                    return "global::Opc.Ua.ExtensionObject";
                }

                if (typeName is "global::Opc.Ua.IEncodeable?")
                {
                    return "global::Opc.Ua.ExtensionObject?";
                }
                return typeName;
            }

            if (valueRank == ValueRank.Array)
            {
                string typeName = GetCollectionTypeName();
                if (typeName != null)
                {
                    // Leave collections always non nullable even though they can
                    // serialized as null value. But properties are always init
                    // as collection never null
                    // return !nullable ? typeName : typeName + "?";
                    return typeName;
                }

                string GetCollectionTypeName()
                {
                    switch (datatype.BasicDataType)
                    {
                        case BasicDataType.Boolean:
                            return "global::Opc.Ua.BooleanCollection";
                        case BasicDataType.SByte:
                            return "global::Opc.Ua.SByteCollection";
                        case BasicDataType.Byte:
                            return "global::Opc.Ua.ByteCollection";
                        case BasicDataType.Int16:
                            return "global::Opc.Ua.Int16Collection";
                        case BasicDataType.UInt16:
                            return "global::Opc.Ua.UInt16Collection";
                        case BasicDataType.Int32:
                            return "global::Opc.Ua.Int32Collection";
                        case BasicDataType.UInt32:
                            return "global::Opc.Ua.UInt32Collection";
                        case BasicDataType.Int64:
                            return "global::Opc.Ua.Int64Collection";
                        case BasicDataType.UInt64:
                            return "global::Opc.Ua.UInt64Collection";
                        case BasicDataType.Float:
                            return "global::Opc.Ua.FloatCollection";
                        case BasicDataType.Double:
                            return "global::Opc.Ua.DoubleCollection";
                        case BasicDataType.String:
                            return "global::Opc.Ua.StringCollection";
                        case BasicDataType.DateTime:
                            return "global::Opc.Ua.DateTimeCollection";
                        case BasicDataType.Guid:
                            return "global::Opc.Ua.UuidCollection";
                        case BasicDataType.ByteString:
                            return "global::Opc.Ua.ByteStringCollection";
                        case BasicDataType.XmlElement:
                            return "global::Opc.Ua.XmlElementCollection";
                        case BasicDataType.NodeId:
                            return "global::Opc.Ua.NodeIdCollection";
                        case BasicDataType.ExpandedNodeId:
                            return "global::Opc.Ua.ExpandedNodeIdCollection";
                        case BasicDataType.StatusCode:
                            return "global::Opc.Ua.StatusCodeCollection";
                        case BasicDataType.DiagnosticInfo:
                            return "global::Opc.Ua.DiagnosticInfoCollection";
                        case BasicDataType.QualifiedName:
                            return "global::Opc.Ua.QualifiedNameCollection";
                        case BasicDataType.LocalizedText:
                            return "global::Opc.Ua.LocalizedTextCollection";
                        case BasicDataType.DataValue:
                            return "global::Opc.Ua.DataValueCollection";
                        case BasicDataType.Number:
                        case BasicDataType.Integer:
                        case BasicDataType.UInteger:
                        case BasicDataType.BaseDataType:
                            return "global::Opc.Ua.VariantCollection";
                        case BasicDataType.Structure:
                            return "global::Opc.Ua.ExtensionObjectCollection";
                        case BasicDataType.Enumeration:
                            if (datatype.SymbolicId ==
                                new XmlQualifiedName("Enumeration", Namespaces.OpcUa))
                            {
                                return "global::Opc.Ua.Int32Collection";
                            }

                            if (datatype.IsOptionSet ||
                                datatype.BaseType !=
                                    new XmlQualifiedName("Enumeration", Namespaces.OpcUa))
                            {
                                return GetDotNetTypeName(
                                    (DataTypeDesign)datatype.BaseTypeNode,
                                    valueRank,
                                    targetNamespace,
                                    namespaces,
                                    nullable: false);
                            }
                            return datatype.SymbolicName.Name + "Collection";
                        case BasicDataType.UserDefined:
                            return datatype.SymbolicName.Name + "Collection";
                    }
                    return null; // Default to variant
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
