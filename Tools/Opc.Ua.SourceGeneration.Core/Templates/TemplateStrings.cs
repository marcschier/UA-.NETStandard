namespace Opc.Ua.SourceGeneration
{
    /// <summary>
    /// Template strings
    /// </summary>
    internal static class TemplateStrings
    {
        /// <summary>
        /// ConstantsGenerator.cs  line#154
        /// </summary>
        public static string ModelCompiler_StackGenerator_DataTypes_Templates_Constants_File_cs =>
            """
            // ***START***
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
            using System.Reflection;

            namespace _Prefix_
            {
                /// <summary>
                /// A class that defines constants used by UA applications.
                /// </summary>
                /// <exclude />
                [System.CodeDom.Compiler.GeneratedCodeAttribute("Opc.Ua.ModelCompiler", "1.0.0.0")]
                [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverageAttribute()]
                public static partial class _ClassName_
                {
                    // ListOfIdentifiers
                }
            }
            // ***END***
            """;

        /// <summary>
        /// ConstantsGenerator.cs  line#158
        /// </summary>
        public static string ModelCompiler_StackGenerator_DataTypes_Templates_Constants_Constant_cs =>
            """
            // ***START***
            /// <summary>
            /// _Description_
            /// </summary>
            public const _IdType_ _SymbolicId_ = _Identifier_;
            // ***END***
            """;

        /// <summary>
        /// ConstantsGenerator.cs  line#198
        /// </summary>
        public static string ModelCompiler_StackGenerator_DataTypes_Templates_Constants_DataTypes_cs =>
            """
            // ***START***
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
            using System.Reflection;

            namespace _Prefix_
            {
                /// <summary>
                /// A class that defines identifiers for datatypes.
                /// </summary>
                /// <exclude />
                [System.CodeDom.Compiler.GeneratedCodeAttribute("Opc.Ua.ModelCompiler", "1.0.0.0")]
                [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverageAttribute()]
                public static partial class DataTypes
                {
                    // ListOfIdentifiers
                }

                /// <summary>
                /// A class that defines identifiers for datatype encodings.
                /// </summary>
                /// <exclude />
                [System.CodeDom.Compiler.GeneratedCodeAttribute("Opc.Ua.ModelCompiler", "1.0.0.0")]
                [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverageAttribute()]
                public static partial class Objects
                {
                    // ListOfEncodings
                }
            }
            // ***END***
            """;

        /// <summary>
        /// ConstantsGenerator.cs  line#270
        /// </summary>
        public static string ModelCompiler_StackGenerator_DataTypes_Templates_Constants_Encodings_cs => null;

        /// <summary>
        /// XmlSchemaGenerator.cs  line#181
        /// </summary>
        public static string ModelCompiler_StackGenerator_DataTypes_Templates_XmlSchema_Message_wsdl =>
            """
            <!--***START***-->
            <wsdl:message name="_NAME_Message">
              <wsdl:part name="parameters" element="s0:_NAME_Request"/>
            </wsdl:message>
            <wsdl:message name="_NAME_ResponseMessage">
              <wsdl:part name="parameters" element="s0:_NAME_Response"/>
            </wsdl:message>
            <wsdl:message name="_NAME__FaultMessage">
              <wsdl:part name="detail" element="s0:ServiceFault" />
            </wsdl:message>
            <!--***END***-->
            """;

        /// <summary>
        /// BinarySchemaGenerator.cs  line#81
        /// </summary>
        public static string ModelCompiler_StackGenerator_DataTypes_Templates_BinarySchema_File_xml =>
            """
            <!--***START***-->
            <opc:TypeDictionary
              xmlns:s0="ListOfNamespaces"
              xmlns:opc="http://opcfoundation.org/BinarySchema/"
              xmlns:ua="http://opcfoundation.org/UA/"
              xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
              DefaultByteOrder="LittleEndian"
              TargetNamespace="_DictionaryUri_"
            >
              <!-- Imports -->

              <!-- ListOfTypes -->

            </opc:TypeDictionary>
            <!--***END***-->
            """;

        /// <summary>
        /// BinarySchemaGenerator.cs  line#125
        /// </summary>
        public static string ModelCompiler_StackGenerator_DataTypes_Templates_BinarySchema_OpaqueType_xml =>
            """
            <!--***START***-->
            <opc:OpaqueType Name="_TypeName_">
              <opc:Documentation>_Description_</opc:Documentation>
            </opc:OpaqueType>
            <!--***END***-->
            """;

        /// <summary>
        /// BinarySchemaGenerator.cs  line#185
        /// </summary>
        public static string ModelCompiler_StackGenerator_DataTypes_Templates_BinarySchema_BuiltInTypes_bsd =>
            """
            <!-- ***START*** -->
            <opc:Import Namespace="http://opcfoundation.org/BinarySchema/" />

            <opc:StructuredType Name="XmlElement">
                <opc:Documentation>An XML element encoded as a UTF-8 string.</opc:Documentation>
                <opc:Field Name="Length" TypeName="opc:Int32" />
                <opc:Field Name="Value" TypeName="opc:Char" LengthField="Length" />
              </opc:StructuredType>

              <opc:EnumeratedType Name="NodeIdType" LengthInBits="6">
                <opc:Documentation>The possible encodings for a NodeId value.</opc:Documentation>
                <opc:EnumeratedValue Name="TwoByte" Value="0" />
                <opc:EnumeratedValue Name="FourByte" Value="1" />
                <opc:EnumeratedValue Name="Numeric" Value="2" />
                <opc:EnumeratedValue Name="String" Value="3" />
                <opc:EnumeratedValue Name="Guid" Value="4" />
                <opc:EnumeratedValue Name="ByteString" Value="5" />
              </opc:EnumeratedType>

              <opc:StructuredType Name="TwoByteNodeId">
                <opc:Field Name="Identifier" TypeName="opc:Byte" />
              </opc:StructuredType>

              <opc:StructuredType Name="FourByteNodeId">
                <opc:Field Name="NamespaceIndex" TypeName="opc:Byte" />
                <opc:Field Name="Identifier" TypeName="opc:UInt16" />
              </opc:StructuredType>

              <opc:StructuredType Name="NumericNodeId">
                <opc:Field Name="NamespaceIndex" TypeName="opc:UInt16" />
                <opc:Field Name="Identifier" TypeName="opc:UInt32" />
              </opc:StructuredType>

              <opc:StructuredType Name="StringNodeId">
                <opc:Field Name="NamespaceIndex" TypeName="opc:UInt16" />
                <opc:Field Name="Identifier" TypeName="opc:CharArray" />
              </opc:StructuredType>

              <opc:StructuredType Name="GuidNodeId">
                <opc:Field Name="NamespaceIndex" TypeName="opc:UInt16" />
                <opc:Field Name="Identifier" TypeName="opc:Guid" />
              </opc:StructuredType>

              <opc:StructuredType Name="ByteStringNodeId">
                <opc:Field Name="NamespaceIndex" TypeName="opc:UInt16" />
                <opc:Field Name="Identifier" TypeName="opc:ByteString" />
              </opc:StructuredType>

              <opc:StructuredType Name="NodeId">
                <opc:Documentation>An identifier for a node in a UA server address space.</opc:Documentation>
                <opc:Field Name="NodeIdType" TypeName="ua:NodeIdType" />
                <opc:Field Name="Reserved1" TypeName="opc:Bit" Length="2" />
                <opc:Field Name="TwoByte" TypeName="ua:TwoByteNodeId" SwitchField="NodeIdType" SwitchValue="0" />
                <opc:Field Name="FourByte" TypeName="ua:FourByteNodeId" SwitchField="NodeIdType" SwitchValue="1" />
                <opc:Field Name="Numeric" TypeName="ua:NumericNodeId" SwitchField="NodeIdType" SwitchValue="2" />
                <opc:Field Name="String" TypeName="ua:StringNodeId" SwitchField="NodeIdType" SwitchValue="3" />
                <opc:Field Name="Guid" TypeName="ua:GuidNodeId" SwitchField="NodeIdType" SwitchValue="4" />
                <opc:Field Name="ByteString" TypeName="ua:ByteStringNodeId" SwitchField="NodeIdType" SwitchValue="5" />
              </opc:StructuredType>

              <opc:StructuredType Name="ExpandedNodeId">
                <opc:Documentation>An identifier for a node in a UA server address space qualified with a complete namespace string.</opc:Documentation>
                <opc:Field Name="NodeIdType" TypeName="ua:NodeIdType" />
                <opc:Field Name="ServerIndexSpecified" TypeName="opc:Bit" />
                <opc:Field Name="NamespaceURISpecified" TypeName="opc:Bit" />
                <opc:Field Name="TwoByte" TypeName="ua:TwoByteNodeId" SwitchField="NodeIdType" SwitchValue="0" />
                <opc:Field Name="FourByte" TypeName="ua:FourByteNodeId" SwitchField="NodeIdType" SwitchValue="1" />
                <opc:Field Name="Numeric" TypeName="ua:NumericNodeId" SwitchField="NodeIdType" SwitchValue="2" />
                <opc:Field Name="String" TypeName="ua:StringNodeId" SwitchField="NodeIdType" SwitchValue="3" />
                <opc:Field Name="Guid" TypeName="ua:GuidNodeId" SwitchField="NodeIdType" SwitchValue="4" />
                <opc:Field Name="ByteString" TypeName="ua:ByteStringNodeId" SwitchField="NodeIdType" SwitchValue="5" />
                <opc:Field Name="NamespaceURI" TypeName="opc:CharArray" SwitchField="NamespaceURISpecified"/>
                <opc:Field Name="ServerIndex" TypeName="opc:UInt32" SwitchField="ServerIndexSpecified"/>
              </opc:StructuredType>

              <opc:OpaqueType Name="StatusCode" LengthInBits="32" ByteOrderSignificant="true">
                <opc:Documentation>A 32-bit status code value.</opc:Documentation>
              </opc:OpaqueType>

              <opc:StructuredType Name="DiagnosticInfo">
                <opc:Documentation>A recursive structure containing diagnostic information associated with a status code.</opc:Documentation>
                <opc:Field Name="SymbolicIdSpecified" TypeName="opc:Bit" />
                <opc:Field Name="NamespaceURISpecified" TypeName="opc:Bit" />
                <opc:Field Name="LocalizedTextSpecified" TypeName="opc:Bit" />
                <opc:Field Name="LocaleSpecified" TypeName="opc:Bit" />
                <opc:Field Name="AdditionalInfoSpecified" TypeName="opc:Bit" />
                <opc:Field Name="InnerStatusCodeSpecified" TypeName="opc:Bit" />
                <opc:Field Name="InnerDiagnosticInfoSpecified" TypeName="opc:Bit" />
                <opc:Field Name="Reserved1" TypeName="opc:Bit" Length="1" />
                <opc:Field Name="SymbolicId" TypeName="opc:Int32" SwitchField="SymbolicIdSpecified" />
                <opc:Field Name="NamespaceURI" TypeName="opc:Int32" SwitchField="NamespaceURISpecified" />
                <opc:Field Name="Locale" TypeName="opc:Int32" SwitchField="LocaleSpecified" />
                <opc:Field Name="LocalizedText" TypeName="opc:Int32" SwitchField="LocalizedTextSpecified" />
                <opc:Field Name="AdditionalInfo" TypeName="opc:CharArray" SwitchField="AdditionalInfoSpecified" />
                <opc:Field Name="InnerStatusCode" TypeName="ua:StatusCode" SwitchField="InnerStatusCodeSpecified" />
                <opc:Field Name="InnerDiagnosticInfo" TypeName="ua:DiagnosticInfo" SwitchField="InnerDiagnosticInfoSpecified" />
              </opc:StructuredType>

              <opc:StructuredType Name="QualifiedName">
                <opc:Documentation>A string qualified with a namespace index.</opc:Documentation>
                <opc:Field Name="NamespaceIndex" TypeName="opc:UInt16" />
                <opc:Field Name="Name" TypeName="opc:CharArray" />
              </opc:StructuredType>

              <opc:StructuredType Name="LocalizedText">
                <opc:Documentation>A string qualified with a namespace index.</opc:Documentation>
                <opc:Field Name="LocaleSpecified" TypeName="opc:Bit" />
                <opc:Field Name="TextSpecified" TypeName="opc:Bit" />
                <opc:Field Name="Reserved1" TypeName="opc:Bit" Length="6" />
                <opc:Field Name="Locale" TypeName="opc:CharArray" SwitchField="LocaleSpecified" />
                <opc:Field Name="Text" TypeName="opc:CharArray" SwitchField="TextSpecified" />
              </opc:StructuredType>

              <opc:StructuredType Name="DataValue">
                <opc:Documentation>A value with an associated timestamp, and quality.</opc:Documentation>
                <opc:Field Name="ValueSpecified" TypeName="opc:Bit" />
                <opc:Field Name="StatusCodeSpecified" TypeName="opc:Bit" />
                <opc:Field Name="SourceTimestampSpecified" TypeName="opc:Bit" />
                <opc:Field Name="ServerTimestampSpecified" TypeName="opc:Bit" />
                <opc:Field Name="SourcePicosecondsSpecified" TypeName="opc:Bit" />
                <opc:Field Name="ServerPicosecondsSpecified" TypeName="opc:Bit" />
                <opc:Field Name="Reserved1" TypeName="opc:Bit" Length="2" />
                <opc:Field Name="Value" TypeName="ua:Variant" SwitchField="ValueSpecified" />
                <opc:Field Name="StatusCode" TypeName="ua:StatusCode" SwitchField="StatusCodeSpecified" />
                <opc:Field Name="SourceTimestamp" TypeName="opc:DateTime" SwitchField="SourceTimestampSpecified" />
                <opc:Field Name="SourcePicoseconds" TypeName="opc:UInt16" SwitchField="SourcePicosecondsSpecified" />
                <opc:Field Name="ServerTimestamp" TypeName="opc:DateTime" SwitchField="ServerTimestampSpecified" />
                <opc:Field Name="ServerPicoseconds" TypeName="opc:UInt16" SwitchField="ServerPicosecondsSpecified" />
              </opc:StructuredType>

              <opc:StructuredType Name="ExtensionObject">
                <opc:Documentation>A serialized object prefixed with its data type identifier.</opc:Documentation>
                <opc:Field Name="TypeIdSpecified" TypeName="opc:Bit" />
                <opc:Field Name="BinaryBody" TypeName="opc:Bit" />
                <opc:Field Name="XmlBody" TypeName="opc:Bit" />
                <opc:Field Name="Reserved1" TypeName="opc:Bit" Length="5" />
                <opc:Field Name="TypeId" TypeName="ua:ExpandedNodeId" SwitchField="TypeIdSpecified" />
                <opc:Field Name="BodyLength" TypeName="opc:Int32" />
                <opc:Field Name="Body" TypeName="opc:Byte" LengthField="BodyLength" />
              </opc:StructuredType>

              <opc:StructuredType Name="Variant">
                <opc:Documentation>A union of several types.</opc:Documentation>
                <opc:Field Name="VariantType" TypeName="opc:Bit" Length="6" />
                <opc:Field Name="ArrayDimensionsSpecified" TypeName="opc:Bit" Length="1"/>
                <opc:Field Name="ArrayLengthSpecified" TypeName="opc:Bit" Length="1"/>
                <opc:Field Name="ArrayLength" TypeName="opc:Int32" SwitchField="ArrayLengthSpecified" />
                <opc:Field Name="Boolean" TypeName="opc:Boolean" LengthField="ArrayLength" SwitchField="VariantType" SwitchValue="1" />
                <opc:Field Name="SByte" TypeName="opc:SByte" LengthField="ArrayLength" SwitchField="VariantType" SwitchValue="2" />
                <opc:Field Name="Byte" TypeName="opc:Byte" LengthField="ArrayLength" SwitchField="VariantType" SwitchValue="3" />
                <opc:Field Name="Int16" TypeName="opc:Int16" LengthField="ArrayLength" SwitchField="VariantType" SwitchValue="4" />
                <opc:Field Name="UInt16" TypeName="opc:UInt16" LengthField="ArrayLength" SwitchField="VariantType" SwitchValue="5" />
                <opc:Field Name="Int32" TypeName="opc:Int32" LengthField="ArrayLength" SwitchField="VariantType" SwitchValue="6" />
                <opc:Field Name="UInt32" TypeName="opc:UInt32" LengthField="ArrayLength" SwitchField="VariantType" SwitchValue="7" />
                <opc:Field Name="Int64" TypeName="opc:Int64" LengthField="ArrayLength" SwitchField="VariantType" SwitchValue="8" />
                <opc:Field Name="UInt64" TypeName="opc:UInt64" LengthField="ArrayLength" SwitchField="VariantType" SwitchValue="9" />
                <opc:Field Name="Float" TypeName="opc:Float" LengthField="ArrayLength" SwitchField="VariantType" SwitchValue="10" />
                <opc:Field Name="Double" TypeName="opc:Double" LengthField="ArrayLength" SwitchField="VariantType" SwitchValue="11" />
                <opc:Field Name="String" TypeName="opc:CharArray" LengthField="ArrayLength" SwitchField="VariantType" SwitchValue="12" />
                <opc:Field Name="DateTime" TypeName="opc:DateTime" LengthField="ArrayLength" SwitchField="VariantType" SwitchValue="13" />
                <opc:Field Name="Guid" TypeName="opc:Guid" LengthField="ArrayLength" SwitchField="VariantType" SwitchValue="14" />
                <opc:Field Name="ByteString" TypeName="opc:ByteString" LengthField="ArrayLength" SwitchField="VariantType" SwitchValue="15" />
                <opc:Field Name="XmlElement" TypeName="ua:XmlElement" LengthField="ArrayLength" SwitchField="VariantType" SwitchValue="16" />
                <opc:Field Name="NodeId" TypeName="ua:NodeId" LengthField="ArrayLength" SwitchField="VariantType" SwitchValue="17" />
                <opc:Field Name="ExpandedNodeId" TypeName="ua:ExpandedNodeId" LengthField="ArrayLength" SwitchField="VariantType" SwitchValue="18" />
                <opc:Field Name="StatusCode" TypeName="ua:StatusCode" LengthField="ArrayLength" SwitchField="VariantType" SwitchValue="19" />
                <opc:Field Name="QualifiedName" TypeName="ua:QualifiedName" LengthField="ArrayLength" SwitchField="VariantType" SwitchValue="20" />
                <opc:Field Name="LocalizedText" TypeName="ua:LocalizedText" LengthField="ArrayLength" SwitchField="VariantType" SwitchValue="21" />
                <opc:Field Name="ExtensionObject" TypeName="ua:ExtensionObject" LengthField="ArrayLength" SwitchField="VariantType" SwitchValue="22" />
                <opc:Field Name="DataValue" TypeName="ua:DataValue" LengthField="ArrayLength" SwitchField="VariantType" SwitchValue="23" />
                <opc:Field Name="Variant" TypeName="ua:Variant" LengthField="ArrayLength" SwitchField="VariantType" SwitchValue="24" />
                <opc:Field Name="DiagnosticInfo" TypeName="ua:DiagnosticInfo" LengthField="ArrayLength" SwitchField="VariantType" SwitchValue="25" />
                <opc:Field Name="NoOfArrayDimensions" TypeName="opc:Int32" SwitchField="ArrayDimensionsSpecified" />
                <opc:Field Name="ArrayDimensions" TypeName="opc:Int32" LengthField="NoOfArrayDimensions" SwitchField="ArrayDimensionsSpecified" />
              </opc:StructuredType>

              <opc:EnumeratedType Name="NamingRuleType" LengthInBits="32">
                <opc:EnumeratedValue Name="Mandatory" Value="1" />
                <opc:EnumeratedValue Name="Optional" Value="2" />
                <opc:EnumeratedValue Name="Constraint" Value="3" />
              </opc:EnumeratedType>

            <!-- ***END*** -->
            """;

        /// <summary>
        /// BinarySchemaGenerator.cs  line#209
        /// </summary>
        public static string ModelCompiler_StackGenerator_DataTypes_Templates_BinarySchema_ComplexType_xml =>
            """
            <!--***START***-->
            <opc:StructuredType Name="_TypeName_"  BaseType="_BaseType_">
              <opc:Documentation>_Description_</opc:Documentation>
              <!-- ListOfFields -->
            </opc:StructuredType>
            <!--***END***-->
            """;

        /// <summary>
        /// BinarySchemaGenerator.cs  line#214
        /// </summary>
        public static string ModelCompiler_StackGenerator_DataTypes_Templates_BinarySchema_EnumeratedType_xml =>
            """
            <!--***START***-->
            <opc:EnumeratedType Name="_TypeName_" LengthInBits="_LengthInBits_"_IsOptionSet_>
              <opc:Documentation>_Description_</opc:Documentation>
              <!-- ListOfValues -->
            </opc:EnumeratedType>
            <!--***END***-->
            """;

        /// <summary>
        /// BinarySchemaGenerator.cs  line#219
        /// </summary>
        public static string ModelCompiler_StackGenerator_DataTypes_Templates_BinarySchema_ServiceType_xml =>
            """
            <!--***START***-->
            <opc:StructuredType Name="_TypeName_Request">
              <opc:Documentation>_Description_</opc:Documentation>
              <!-- ListOfRequestParameters -->
            </opc:StructuredType>

            <opc:StructuredType Name="_TypeName_Response">
              <opc:Documentation>_Description_</opc:Documentation>
              <!-- ListOfResponseParameters -->
            </opc:StructuredType>
            <!--***END***-->
            """;

        /// <summary>
        /// BinarySchemaGenerator.cs  line#310
        /// </summary>
        public static string ModelCompiler_StackGenerator_DataTypes_Templates_BinarySchema_EnumeratedValue_xml => null;

        /// <summary>
        /// BinarySchemaGenerator.cs  line#310
        /// BinarySchemaGenerator.cs  line#321
        /// BinarySchemaGenerator.cs  line#329
        /// </summary>
        public static string ModelCompiler_StackGenerator_DataTypes_Templates_BinarySchema_Field_xml => null;

        /// <summary>
        /// ModelGenerator.cs  line#278
        /// </summary>
        public static string ModelCompiler_Templates_Version2_PredefinedNodesFile_cs =>
            """
            // ***START***
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
            using System.Text;
            using System.IO;
            // ListOfImports

            #pragma warning disable 1591

            namespace _Namespace_
            {
                #region _ClassName_ Declarations
                [System.CodeDom.Compiler.GeneratedCodeAttribute("Opc.Ua.ModelCompiler", "1.0.0.0")]
                [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverageAttribute()]
                public static partial class PredefinedNodes
                {
                    #region PredefinedNodes Declarations
                    // <summary/>
                    public static NodeStateCollection Load(ISystemContext context)
                    {
                        byte[] initializationBuffer = _Decode_(
                        // InitializationString
                        );
                        using (MemoryStream stream = new MemoryStream(initializationBuffer))
                        {
                            NodeStateCollection predefinedNodes = new NodeStateCollection();
                            predefinedNodes.LoadFrom_Encoding_(context, stream, true);
                            return predefinedNodes;
                        }
                    }
                    #endregion
                }
                #endregion
            }
            // ***END***
            """;

        /// <summary>
        /// ModelGenerator.cs  line#559
        /// </summary>
        public static string ModelCompiler_Templates_XmlSchema_File_xml =>
            """
            <!--***START***-->
            <xs:schema
              xmlns:s0="ListOfNamespaces"
              xmlns:xs="http://www.w3.org/2001/XMLSchema"
              xmlns:ua="http://opcfoundation.org/UA/2008/02/Types.xsd"
              xmlns:tns="_Namespace_"
              targetNamespace="_Namespace_"
              elementFormDefault="qualified"
            >
              <xs:annotation>
                <xs:appinfo>
                  <tns:Model />
                </xs:appinfo>
              </xs:annotation>

              <!-- Imports -->
              <!-- BuiltInTypes -->
              <!-- ListOfTypes -->

            </xs:schema>
            <!--***END***-->
            """;

        /// <summary>
        /// ModelGenerator.cs  line#590
        /// XmlSchemaGenerator.cs  line#392
        /// </summary>
        public static string ModelCompiler_StackGenerator_DataTypes_Templates_XmlSchema_BuiltInTypes_xsd =>
            """
              <!-- WARNING - this information is copied from Common\Schema\Xml\BuiltInTypes.xsd -->
              <!-- ***START*** -->
              <xs:element name="Boolean" type="xs:boolean" />

              <xs:complexType name="ListOfBoolean">
                <xs:sequence>
                  <xs:element name="Boolean" type="xs:boolean" minOccurs="0" maxOccurs="unbounded" />
                </xs:sequence>
              </xs:complexType>
              <xs:element name="ListOfBoolean" type="tns:ListOfBoolean" nillable="true"></xs:element>

              <xs:element name="Number" nillable="true" type="xs:decimal" />

              <xs:element name="Integer" nillable="true" type="xs:integer" />

              <xs:element name="UInteger" nillable="true" type="xs:positiveInteger" />

              <xs:element name="SByte" type="xs:byte" />

              <xs:complexType name="ListOfSByte">
                <xs:sequence>
                  <xs:element name="SByte" type="xs:byte" minOccurs="0" maxOccurs="unbounded" />
                </xs:sequence>
              </xs:complexType>
              <xs:element name="ListOfSByte" type="tns:ListOfSByte" nillable="true"></xs:element>

              <xs:element name="Byte" type="xs:unsignedByte" />

              <xs:complexType name="ListOfByte">
                <xs:sequence>
                  <xs:element name="Byte" type="xs:unsignedByte" minOccurs="0" maxOccurs="unbounded" />
                </xs:sequence>
              </xs:complexType>
              <xs:element name="ListOfByte" type="tns:ListOfByte" nillable="true"></xs:element>

              <xs:element name="Int16" type="xs:short" />

              <xs:complexType name="ListOfInt16">
                <xs:sequence>
                  <xs:element name="Int16" type="xs:short" minOccurs="0" maxOccurs="unbounded" />
                </xs:sequence>
              </xs:complexType>
              <xs:element name="ListOfInt16" type="tns:ListOfInt16" nillable="true"></xs:element>

              <xs:element name="UInt16" type="xs:unsignedShort" />

              <xs:complexType name="ListOfUInt16">
                <xs:sequence>
                  <xs:element name="UInt16" type="xs:unsignedShort" minOccurs="0" maxOccurs="unbounded" />
                </xs:sequence>
              </xs:complexType>
              <xs:element name="ListOfUInt16" type="tns:ListOfUInt16" nillable="true"></xs:element>

              <xs:element name="Int32" type="xs:int" />

              <xs:complexType name="ListOfInt32">
                <xs:sequence>
                  <xs:element name="Int32" type="xs:int" minOccurs="0" maxOccurs="unbounded" />
                </xs:sequence>
              </xs:complexType>
              <xs:element name="ListOfInt32" type="tns:ListOfInt32" nillable="true"></xs:element>

              <xs:element name="UInt32" type="xs:unsignedInt" />

              <xs:complexType name="ListOfUInt32">
                <xs:sequence>
                  <xs:element name="UInt32" type="xs:unsignedInt" minOccurs="0" maxOccurs="unbounded" />
                </xs:sequence>
              </xs:complexType>
              <xs:element name="ListOfUInt32" type="tns:ListOfUInt32" nillable="true"></xs:element>

              <xs:element name="Int64" type="xs:long" />

              <xs:complexType name="ListOfInt64">
                <xs:sequence>
                  <xs:element name="Int64" type="xs:long" minOccurs="0" maxOccurs="unbounded" />
                </xs:sequence>
              </xs:complexType>
              <xs:element name="ListOfInt64" type="tns:ListOfInt64" nillable="true"></xs:element>

              <xs:element name="UInt64" type="xs:unsignedLong" />

              <xs:complexType name="ListOfUInt64">
                <xs:sequence>
                  <xs:element name="UInt64" type="xs:unsignedLong" minOccurs="0" maxOccurs="unbounded" />
                </xs:sequence>
              </xs:complexType>
              <xs:element name="ListOfUInt64" type="tns:ListOfUInt64" nillable="true"></xs:element>

              <xs:element name="Float" type="xs:float" />

              <xs:complexType name="ListOfFloat">
                <xs:sequence>
                  <xs:element name="Float" type="xs:float" minOccurs="0" maxOccurs="unbounded" />
                </xs:sequence>
              </xs:complexType>
              <xs:element name="ListOfFloat" type="tns:ListOfFloat" nillable="true"></xs:element>

              <xs:element name="Double" type="xs:double" />

              <xs:complexType name="ListOfDouble">
                <xs:sequence>
                  <xs:element name="Double" type="xs:double" minOccurs="0" maxOccurs="unbounded" />
                </xs:sequence>
              </xs:complexType>
              <xs:element name="ListOfDouble" type="tns:ListOfDouble" nillable="true"></xs:element>

              <xs:element name="String" nillable="true" type="xs:string" />

              <xs:complexType name="ListOfString">
                <xs:sequence>
                  <xs:element name="String" type="xs:string" minOccurs="0" maxOccurs="unbounded" />
                </xs:sequence>
              </xs:complexType>
              <xs:element name="ListOfString" type="tns:ListOfString" nillable="true"></xs:element>

              <xs:element name="DateTime" nillable="true" type="xs:dateTime" />

              <xs:complexType name="ListOfDateTime">
                <xs:sequence>
                  <xs:element name="DateTime" type="xs:dateTime" minOccurs="0" maxOccurs="unbounded" />
                </xs:sequence>
              </xs:complexType>
              <xs:element name="ListOfDateTime" type="tns:ListOfDateTime" nillable="true"></xs:element>

              <xs:complexType name="Guid">
                <xs:sequence>
                  <xs:element name="String" type="xs:string" minOccurs="0" maxOccurs="1" nillable="true" />
                </xs:sequence>
              </xs:complexType>
              <xs:element name="Guid" type="tns:Guid" nillable="true"></xs:element>

              <xs:complexType name="ListOfGuid">
                <xs:sequence>
                  <xs:element name="Guid" type="tns:Guid" minOccurs="0" maxOccurs="unbounded" />
                </xs:sequence>
              </xs:complexType>
              <xs:element name="ListOfGuid" type="tns:ListOfGuid" nillable="true"></xs:element>

              <xs:element name="ByteString" nillable="true" type="xs:base64Binary" />

              <xs:complexType name="ListOfByteString">
                <xs:sequence>
                  <xs:element name="ByteString" type="xs:base64Binary" minOccurs="0" maxOccurs="unbounded" nillable="true" />
                </xs:sequence>
              </xs:complexType>
              <xs:element name="ListOfByteString" type="tns:ListOfByteString" nillable="true"></xs:element>

              <xs:complexType name="ListOfXmlElement">
                <xs:sequence>
                  <xs:element name="XmlElement" minOccurs="0" maxOccurs="unbounded" nillable="true">
                    <xs:complexType>
                      <xs:sequence>
                        <xs:any minOccurs="0" processContents="lax"/>
                      </xs:sequence>
                    </xs:complexType>
                  </xs:element>
                </xs:sequence>
              </xs:complexType>
              <xs:element name="ListOfXmlElement" type="tns:ListOfXmlElement" nillable="true"></xs:element>

              <xs:complexType name="NodeId">
                <xs:sequence>
                  <xs:element name="Identifier" type="xs:string" minOccurs="0" maxOccurs="1" nillable="true" />
                </xs:sequence>
              </xs:complexType>
              <xs:element name="NodeId" type="tns:NodeId" nillable="true"></xs:element>

              <xs:complexType name="ListOfNodeId">
                <xs:sequence>
                  <xs:element name="NodeId" type="tns:NodeId" minOccurs="0" maxOccurs="unbounded" nillable="true" />
                </xs:sequence>
              </xs:complexType>
              <xs:element name="ListOfNodeId" type="tns:ListOfNodeId" nillable="true"></xs:element>

              <xs:complexType name="ExpandedNodeId">
                <xs:sequence>
                  <xs:element name="Identifier" type="xs:string" minOccurs="0" maxOccurs="1" nillable="true" />
                </xs:sequence>
              </xs:complexType>
              <xs:element name="ExpandedNodeId" type="tns:ExpandedNodeId" nillable="true"></xs:element>

              <xs:complexType name="ListOfExpandedNodeId">
                <xs:sequence>
                  <xs:element name="ExpandedNodeId" type="tns:ExpandedNodeId" minOccurs="0" maxOccurs="unbounded" nillable="true" />
                </xs:sequence>
              </xs:complexType>
              <xs:element name="ListOfExpandedNodeId" type="tns:ListOfExpandedNodeId" nillable="true"></xs:element>

              <xs:complexType name="StatusCode">
                <xs:sequence>
                  <xs:element name="Code" type="xs:unsignedInt" minOccurs="0" maxOccurs="1" />
                </xs:sequence>
              </xs:complexType>
              <xs:element name="StatusCode" type="tns:StatusCode"></xs:element>

              <xs:complexType name="ListOfStatusCode">
                <xs:sequence>
                  <xs:element name="StatusCode" type="tns:StatusCode" minOccurs="0" maxOccurs="unbounded" nillable="true" />
                </xs:sequence>
              </xs:complexType>
              <xs:element name="ListOfStatusCode" type="tns:ListOfStatusCode" nillable="true"></xs:element>

              <xs:complexType name="DiagnosticInfo">
                <xs:sequence>
                  <xs:element name="SymbolicId" type="xs:int" minOccurs="0" maxOccurs="1" />
                  <xs:element name="NamespaceUri" type="xs:int" minOccurs="0" maxOccurs="1" />
                  <xs:element name="Locale" type="xs:int" minOccurs="0" maxOccurs="1" />
                  <xs:element name="LocalizedText" type="xs:int" minOccurs="0" maxOccurs="1" />
                  <xs:element name="AdditionalInfo" type="xs:string" minOccurs="0" maxOccurs="1" />
                  <xs:element name="InnerStatusCode" type="tns:StatusCode" minOccurs="0" maxOccurs="1" />
                  <xs:element name="InnerDiagnosticInfo" type="tns:DiagnosticInfo" minOccurs="0" maxOccurs="1" nillable="true" />
                </xs:sequence>
              </xs:complexType>
              <xs:element name="DiagnosticInfo" type="tns:DiagnosticInfo" nillable="true"></xs:element>

              <xs:complexType name="ListOfDiagnosticInfo">
                <xs:sequence>
                  <xs:element name="DiagnosticInfo" type="tns:DiagnosticInfo" minOccurs="0" maxOccurs="unbounded" nillable="true" />
                </xs:sequence>
              </xs:complexType>
              <xs:element name="ListOfDiagnosticInfo" type="tns:ListOfDiagnosticInfo" nillable="true"></xs:element>

              <xs:complexType name="LocalizedText">
                <xs:sequence>
                  <xs:element name="Locale" type="xs:string" minOccurs="0" nillable="true" />
                  <xs:element name="Text" type="xs:string" minOccurs="0"  nillable="true" />
                </xs:sequence>
              </xs:complexType>
              <xs:element name="LocalizedText" type="tns:LocalizedText" nillable="true" />

              <xs:complexType name="ListOfLocalizedText">
                <xs:sequence>
                  <xs:element name="LocalizedText" type="tns:LocalizedText" minOccurs="0" maxOccurs="unbounded" nillable="true" />
                </xs:sequence>
              </xs:complexType>
              <xs:element name="ListOfLocalizedText" type="tns:ListOfLocalizedText" nillable="true"></xs:element>

              <xs:complexType name="QualifiedName">
                <xs:sequence>
                  <xs:element name="NamespaceIndex" type="xs:unsignedShort" minOccurs="0" />
                  <xs:element name="Name" type="xs:string" minOccurs="0" nillable="true" />
                </xs:sequence>
              </xs:complexType>
              <xs:element name="QualifiedName" type="tns:QualifiedName" nillable="true" />

              <xs:complexType name="ListOfQualifiedName">
                <xs:sequence>
                  <xs:element name="QualifiedName" type="tns:QualifiedName" minOccurs="0" maxOccurs="unbounded" nillable="true" />
                </xs:sequence>
              </xs:complexType>
              <xs:element name="ListOfQualifiedName" type="tns:ListOfQualifiedName" nillable="true"></xs:element>

              <xs:complexType name="ExtensionObjectBody">
                <xs:sequence>
                  <xs:any minOccurs="0" processContents="lax" />
                </xs:sequence>
              </xs:complexType>

              <xs:complexType name="ExtensionObject">
                <xs:sequence>
                  <xs:element name="TypeId" type="tns:ExpandedNodeId" minOccurs="0" nillable="true" />
                  <xs:element name="Body" minOccurs="0" type ="tns:ExtensionObjectBody" nillable="true" />
                </xs:sequence>
              </xs:complexType>
              <xs:element name="ExtensionObject" type="tns:ExtensionObject" nillable="true" />

              <xs:complexType name="ListOfExtensionObject">
                <xs:sequence>
                  <xs:element name="ExtensionObject" type="tns:ExtensionObject" minOccurs="0" maxOccurs="unbounded" nillable="true" />
                </xs:sequence>
              </xs:complexType>
              <xs:element name="ListOfExtensionObject" type="tns:ListOfExtensionObject" nillable="true"></xs:element>

              <xs:complexType name="Decimal">
                <xs:sequence>
                  <xs:element name="TypeId" type="tns:NodeId" minOccurs="0" />
                  <xs:element name="Body" minOccurs="0">
                    <xs:complexType>
                      <xs:sequence>
                        <xs:element name="Scale" type="xs:short" />
                        <xs:element name="Value" type="xs:string" />
                      </xs:sequence>
                    </xs:complexType>
                  </xs:element>
                </xs:sequence>
              </xs:complexType>

              <xs:complexType name="Matrix">
                <xs:sequence>
                  <xs:element name="Dimensions" type="tns:ListOfInt32" minOccurs="0" nillable="true" />
                  <xs:element name="Value" minOccurs="0" nillable="true">
                    <xs:complexType mixed="false">
                      <xs:choice maxOccurs="unbounded">
                        <xs:element name="Boolean" type="xs:boolean" minOccurs="0" />
                        <xs:element name="SByte" type="xs:byte" minOccurs="0" />
                        <xs:element name="Byte" type="xs:unsignedByte" minOccurs="0" />
                        <xs:element name="Int16" type="xs:short" minOccurs="0" />
                        <xs:element name="UInt16" type="xs:unsignedShort" minOccurs="0" />
                        <xs:element name="Int32" type="xs:int" minOccurs="0" />
                        <xs:element name="UInt32" type="xs:unsignedInt" minOccurs="0" />
                        <xs:element name="Int64" type="xs:long" minOccurs="0" />
                        <xs:element name="UInt64" type="xs:unsignedLong" minOccurs="0" />
                        <xs:element name="Float" type="xs:float" minOccurs="0" />
                        <xs:element name="Double" type="xs:double" minOccurs="0" />
                        <xs:element name="String" type="xs:string" minOccurs="0" />
                        <xs:element name="DateTime" type="xs:dateTime" minOccurs="0" />
                        <xs:element name="Guid" type="tns:Guid" minOccurs="0" />
                        <xs:element name="ByteString" type="xs:base64Binary" minOccurs="0" />
                        <xs:element name="XmlElement" minOccurs="0" nillable="true">
                          <xs:complexType>
                            <xs:sequence>
                              <xs:any minOccurs="0" processContents="lax" />
                            </xs:sequence>
                          </xs:complexType>
                        </xs:element>
                        <xs:element name="StatusCode" type="tns:StatusCode" minOccurs="0" />
                        <xs:element name="NodeId" type="tns:NodeId" minOccurs="0" />
                        <xs:element name="ExpandedNodeId" type="tns:ExpandedNodeId" minOccurs="0" />
                        <xs:element name="QualifiedName" type="tns:QualifiedName" minOccurs="0" />
                        <xs:element name="LocalizedText" type="tns:LocalizedText" minOccurs="0" />
                        <xs:element name="ExtensionObject" type="tns:ExtensionObject" minOccurs="0" />
                        <xs:element name="Variant" type="tns:Variant" minOccurs="0" />
                      </xs:choice>
                    </xs:complexType>
                  </xs:element>
                </xs:sequence>
              </xs:complexType>
              <xs:element name="Matrix" type="tns:Matrix" nillable="true" />

              <xs:complexType name="VariantValue">
                <xs:choice>
                  <xs:element name="Boolean" type="xs:boolean" minOccurs="0" />
                  <xs:element name="SByte" type="xs:byte" minOccurs="0" />
                  <xs:element name="Byte" type="xs:unsignedByte" minOccurs="0" />
                  <xs:element name="Int16" type="xs:short" minOccurs="0" />
                  <xs:element name="UInt16" type="xs:unsignedShort" minOccurs="0" />
                  <xs:element name="Int32" type="xs:int" minOccurs="0" />
                  <xs:element name="UInt32" type="xs:unsignedInt" minOccurs="0" />
                  <xs:element name="Int64" type="xs:long" minOccurs="0" />
                  <xs:element name="UInt64" type="xs:unsignedLong" minOccurs="0" />
                  <xs:element name="Float" type="xs:float" minOccurs="0" />
                  <xs:element name="Double" type="xs:double" minOccurs="0" />
                  <xs:element name="String" type="xs:string" minOccurs="0" />
                  <xs:element name="DateTime" type="xs:dateTime" minOccurs="0" />
                  <xs:element name="Guid" type="tns:Guid" minOccurs="0" />
                  <xs:element name="ByteString" type="xs:base64Binary" minOccurs="0" />
                  <xs:element name="XmlElement" minOccurs="0" nillable="true">
                    <xs:complexType>
                      <xs:sequence>
                        <xs:any minOccurs="0" processContents="lax" />
                      </xs:sequence>
                    </xs:complexType>
                  </xs:element>
                  <xs:element name="StatusCode" type="tns:StatusCode" minOccurs="0" />
                  <xs:element name="NodeId" type="tns:NodeId" minOccurs="0" />
                  <xs:element name="ExpandedNodeId" type="tns:ExpandedNodeId" minOccurs="0" />
                  <xs:element name="QualifiedName" type="tns:QualifiedName" minOccurs="0" />
                  <xs:element name="LocalizedText" type="tns:LocalizedText" minOccurs="0" />
                  <xs:element name="ExtensionObject" type="tns:ExtensionObject" minOccurs="0" />
                  <xs:element name="ListOfBoolean" type="tns:ListOfBoolean" minOccurs="0" />
                  <xs:element name="ListOfSByte" type="tns:ListOfSByte" minOccurs="0" />
                  <xs:element name="ListOfByte" type="tns:ListOfByte" minOccurs="0" />
                  <xs:element name="ListOfInt16" type="tns:ListOfInt16" minOccurs="0" />
                  <xs:element name="ListOfUInt16" type="tns:ListOfUInt16" minOccurs="0" />
                  <xs:element name="ListOfInt32" type="tns:ListOfInt32" minOccurs="0" />
                  <xs:element name="ListOfUInt32" type="tns:ListOfUInt32" minOccurs="0" />
                  <xs:element name="ListOfInt64" type="tns:ListOfInt64" minOccurs="0" />
                  <xs:element name="ListOfUInt64" type="tns:ListOfUInt64" minOccurs="0" />
                  <xs:element name="ListOfFloat" type="tns:ListOfFloat" minOccurs="0" />
                  <xs:element name="ListOfDouble" type="tns:ListOfDouble" minOccurs="0" />
                  <xs:element name="ListOfString" type="tns:ListOfString" minOccurs="0" />
                  <xs:element name="ListOfDateTime" type="tns:ListOfDateTime" minOccurs="0" />
                  <xs:element name="ListOfGuid" type="tns:ListOfGuid" minOccurs="0" />
                  <xs:element name="ListOfByteString" type="tns:ListOfByteString" minOccurs="0" />
                  <xs:element name="ListOfXmlElement" type="tns:ListOfXmlElement" minOccurs="0" />
                  <xs:element name="ListOfStatusCode" type="tns:ListOfStatusCode" minOccurs="0" />
                  <xs:element name="ListOfNodeId" type="tns:ListOfNodeId" minOccurs="0" />
                  <xs:element name="ListOfExpandedNodeId" type="tns:ListOfExpandedNodeId" minOccurs="0" />
                  <xs:element name="ListOfQualifiedName" type="tns:ListOfQualifiedName" minOccurs="0" />
                  <xs:element name="ListOfLocalizedText" type="tns:ListOfLocalizedText" minOccurs="0" />
                  <xs:element name="ListOfExtensionObject" type="tns:ListOfExtensionObject" minOccurs="0" />
                  <xs:element name="ListOfVariant" type="tns:ListOfVariant" minOccurs="0" />
                  <xs:element name="Matrix" type="tns:Matrix" minOccurs="0" />
                </xs:choice>
              </xs:complexType>

              <xs:complexType name="Variant">
                <xs:sequence>
                  <xs:element name="Value" type="tns:VariantValue" minOccurs="0" nillable="true" />
                </xs:sequence>
              </xs:complexType>
              <xs:element name="Variant" type="tns:Variant" nillable="true" />

              <xs:complexType name="ListOfVariant">
                <xs:sequence>
                  <xs:element name="Variant" type="tns:Variant" minOccurs="0" maxOccurs="unbounded" nillable="true" />
                </xs:sequence>
              </xs:complexType>
              <xs:element name="ListOfVariant" type="tns:ListOfVariant" nillable="true"></xs:element>

              <xs:complexType name="DataValue">
                <xs:sequence>
                  <xs:element name="Value" type="tns:Variant" minOccurs="0" nillable="true" />
                  <xs:element name="StatusCode" type="tns:StatusCode" minOccurs="0" />
                  <xs:element name="SourceTimestamp" type="xs:dateTime" minOccurs="0" />
                  <xs:element name="ServerTimestamp" type="xs:dateTime" minOccurs="0" />
                </xs:sequence>
              </xs:complexType>
              <xs:element name="DataValue" type="tns:DataValue" nillable="true"/>

              <xs:complexType name="ListOfDataValue">
                <xs:sequence>
                  <xs:element name="DataValue" type="tns:DataValue" minOccurs="0" maxOccurs="unbounded" nillable="true" />
                </xs:sequence>
              </xs:complexType>
              <xs:element name="ListOfDataValue" type="tns:ListOfDataValue" nillable="true"></xs:element>

              <xs:element name="InvokeServiceRequest" type="xs:base64Binary" nillable="true" />
              <xs:element name="InvokeServiceResponse" type="xs:base64Binary" nillable="true" />
              <!-- ***END*** -->
            """;

        /// <summary>
        /// ModelGenerator.cs  line#692
        /// ModelGenerator.cs  line#709
        /// </summary>
        public static string ModelCompiler_Templates_XmlSchema_DerivedType_xml =>
            """
            <!--***START***-->
            <xs:complexType name="_TypeName_">
              <!-- Documentation -->
              <xs:complexContent mixed="false">
                <xs:extension base="_BaseType_">
                  <xs:sequence>
                    <!-- ListOfFields -->
                  </xs:sequence>
                </xs:extension>
              </xs:complexContent>
            </xs:complexType>
            <xs:element name="_TypeName_" type="tns:_TypeName_" />
            <!-- CollectionType -->
            <!--***END***-->
            """;

        /// <summary>
        /// ModelGenerator.cs  line#695
        /// </summary>
        public static string ModelCompiler_Templates_XmlSchema_EnumeratedType_xml =>
            """
            <!--***START***-->
            <xs:simpleType  name="_TypeName_">
              <!-- Documentation -->
              <xs:restriction base="xs:string">
                <!-- ListOfFields -->
              </xs:restriction>
            </xs:simpleType>
            <xs:element name="_TypeName_" type="tns:_TypeName_" />
            <!-- CollectionType -->
            <!--***END***-->
            """;

        /// <summary>
        /// ModelGenerator.cs  line#701
        /// </summary>
        public static string ModelCompiler_Templates_XmlSchema_Union_xml =>
            """
            <!--***START***-->
            <xs:complexType name="_TypeName_">
              <!-- Documentation -->
              <xs:sequence>
                <xs:element name="SwitchField" type="xs:unsignedInt" minOccurs="0" />
                <xs:choice>
                  <!-- ListOfFields -->
                </xs:choice>
              </xs:sequence>
            </xs:complexType>
            <xs:element name="_TypeName_" type="tns:_TypeName_" />
            <!-- CollectionType -->
            <!--***END***-->
            """;

        /// <summary>
        /// ModelGenerator.cs  line#705
        /// </summary>
        public static string ModelCompiler_Templates_XmlSchema_ComplexType_xml =>
            """
            <!--***START***-->
            <xs:complexType name="_TypeName_">
              <!-- Documentation -->
              <xs:sequence>
                <!-- ListOfFields -->
              </xs:sequence>
            </xs:complexType>
            <xs:element name="_TypeName_" type="tns:_TypeName_" />
            <!-- CollectionType -->
            <!--***END***-->
            """;

        /// <summary>
        /// ModelGenerator.cs  line#713
        /// </summary>
        public static string ModelCompiler_Templates_XmlSchema_SimpleType_xml =>
            """
            <!--***START***-->
            <xs:element name="_TypeName_" type="_BaseType_" />
            <!--***END***-->
            """;

        /// <summary>
        /// ModelGenerator.cs  line#762
        /// </summary>
        public static string ModelCompiler_Templates_XmlSchema_Documentation_xml =>
            """
            <!--***START***-->
            <xs:annotation>
              <xs:documentation>_Description_</xs:documentation>
            </xs:annotation>
            <!--***END***-->
            """;

        /// <summary>
        /// ModelGenerator.cs  line#769
        /// </summary>
        public static string ModelCompiler_Templates_XmlSchema_CollectionType_xml =>
            """
            <!--***START***-->
            <xs:complexType name="ListOf_TypeName_">
              <xs:sequence>
                <xs:element name="_TypeName_" type="tns:_TypeName_" minOccurs="0" maxOccurs="unbounded" _Nillable_/>
              </xs:sequence>
            </xs:complexType>
            <xs:element name="ListOf_TypeName_" type="tns:ListOf_TypeName_" nillable="true"></xs:element>
            <!--***END***-->
            """;

        /// <summary>
        /// ModelGenerator.cs  line#981
        /// </summary>
        public static string ModelCompiler_Templates_BinarySchema_File_xml =>
            """
            <!--***START***-->
            <opc:TypeDictionary
              xmlns:s0="ListOfNamespaces"
              xmlns:opc="http://opcfoundation.org/BinarySchema/"
              xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
              xmlns:ua="http://opcfoundation.org/UA/"
              xmlns:tns="_DictionaryUri_"
              DefaultByteOrder="LittleEndian"
              TargetNamespace="_DictionaryUri_"
            >
              <!-- Imports -->
              <!-- BuiltInTypes -->
              <!-- ListOfTypes -->

            </opc:TypeDictionary>
            <!--***END***-->
            """;

        /// <summary>
        /// ModelGenerator.cs  line#1003
        /// </summary>
        public static string ModelCompiler_Templates_BinarySchema_BuiltInTypes_bsd =>
            """
            <!-- WARNING - this information is copied from Common\Schema\Binary\BuiltInTypes.bsd -->
            <!-- ***START*** -->
            <opc:Import Namespace="http://opcfoundation.org/BinarySchema/" />

            <opc:StructuredType Name="XmlElement">
              <opc:Documentation>An XML element encoded as a UTF-8 string.</opc:Documentation>
              <opc:Field Name="Length" TypeName="opc:Int32" />
              <opc:Field Name="Value" TypeName="opc:Char" LengthField="Length" />
            </opc:StructuredType>

            <opc:EnumeratedType Name="NodeIdType" LengthInBits="6">
              <opc:Documentation>The possible encodings for a NodeId value.</opc:Documentation>
              <opc:EnumeratedValue Name="TwoByte" Value="0" />
              <opc:EnumeratedValue Name="FourByte" Value="1" />
              <opc:EnumeratedValue Name="Numeric" Value="2" />
              <opc:EnumeratedValue Name="String" Value="3" />
              <opc:EnumeratedValue Name="Guid" Value="4" />
              <opc:EnumeratedValue Name="ByteString" Value="5" />
            </opc:EnumeratedType>

            <opc:StructuredType Name="TwoByteNodeId">
              <opc:Field Name="Identifier" TypeName="opc:Byte" />
            </opc:StructuredType>

            <opc:StructuredType Name="FourByteNodeId">
              <opc:Field Name="NamespaceIndex" TypeName="opc:Byte" />
              <opc:Field Name="Identifier" TypeName="opc:UInt16" />
            </opc:StructuredType>

            <opc:StructuredType Name="NumericNodeId">
              <opc:Field Name="NamespaceIndex" TypeName="opc:UInt16" />
              <opc:Field Name="Identifier" TypeName="opc:UInt32" />
            </opc:StructuredType>

            <opc:StructuredType Name="StringNodeId">
              <opc:Field Name="NamespaceIndex" TypeName="opc:UInt16" />
              <opc:Field Name="Identifier" TypeName="opc:CharArray" />
            </opc:StructuredType>

            <opc:StructuredType Name="GuidNodeId">
              <opc:Field Name="NamespaceIndex" TypeName="opc:UInt16" />
              <opc:Field Name="Identifier" TypeName="opc:Guid" />
            </opc:StructuredType>

            <opc:StructuredType Name="ByteStringNodeId">
              <opc:Field Name="NamespaceIndex" TypeName="opc:UInt16" />
              <opc:Field Name="Identifier" TypeName="opc:ByteString" />
            </opc:StructuredType>

            <opc:StructuredType Name="NodeId">
              <opc:Documentation>An identifier for a node in a UA server address space.</opc:Documentation>
              <opc:Field Name="NodeIdType" TypeName="ua:NodeIdType" />
              <opc:Field Name="Reserved1" TypeName="opc:Bit" Length="2" />
              <opc:Field Name="TwoByte" TypeName="ua:TwoByteNodeId" SwitchField="NodeIdType" SwitchValue="0" />
              <opc:Field Name="FourByte" TypeName="ua:FourByteNodeId" SwitchField="NodeIdType" SwitchValue="1" />
              <opc:Field Name="Numeric" TypeName="ua:NumericNodeId" SwitchField="NodeIdType" SwitchValue="2" />
              <opc:Field Name="String" TypeName="ua:StringNodeId" SwitchField="NodeIdType" SwitchValue="3" />
              <opc:Field Name="Guid" TypeName="ua:GuidNodeId" SwitchField="NodeIdType" SwitchValue="4" />
              <opc:Field Name="ByteString" TypeName="ua:ByteStringNodeId" SwitchField="NodeIdType" SwitchValue="5" />
            </opc:StructuredType>

            <opc:StructuredType Name="ExpandedNodeId">
              <opc:Documentation>An identifier for a node in a UA server address space qualified with a complete namespace string.</opc:Documentation>
              <opc:Field Name="NodeIdType" TypeName="ua:NodeIdType" />
              <opc:Field Name="ServerIndexSpecified" TypeName="opc:Bit" />
              <opc:Field Name="NamespaceURISpecified" TypeName="opc:Bit" />
              <opc:Field Name="TwoByte" TypeName="ua:TwoByteNodeId" SwitchField="NodeIdType" SwitchValue="0" />
              <opc:Field Name="FourByte" TypeName="ua:FourByteNodeId" SwitchField="NodeIdType" SwitchValue="1" />
              <opc:Field Name="Numeric" TypeName="ua:NumericNodeId" SwitchField="NodeIdType" SwitchValue="2" />
              <opc:Field Name="String" TypeName="ua:StringNodeId" SwitchField="NodeIdType" SwitchValue="3" />
              <opc:Field Name="Guid" TypeName="ua:GuidNodeId" SwitchField="NodeIdType" SwitchValue="4" />
              <opc:Field Name="ByteString" TypeName="ua:ByteStringNodeId" SwitchField="NodeIdType" SwitchValue="5" />
              <opc:Field Name="NamespaceURI" TypeName="opc:CharArray" SwitchField="NamespaceURISpecified"/>
              <opc:Field Name="ServerIndex" TypeName="opc:UInt32" SwitchField="ServerIndexSpecified"/>
            </opc:StructuredType>

            <opc:OpaqueType Name="StatusCode" LengthInBits="32" ByteOrderSignificant="true">
              <opc:Documentation>A 32-bit status code value.</opc:Documentation>
            </opc:OpaqueType>

            <opc:StructuredType Name="DiagnosticInfo">
              <opc:Documentation>A recursive structure containing diagnostic information associated with a status code.</opc:Documentation>
              <opc:Field Name="SymbolicIdSpecified" TypeName="opc:Bit" />
              <opc:Field Name="NamespaceURISpecified" TypeName="opc:Bit" />
              <opc:Field Name="LocalizedTextSpecified" TypeName="opc:Bit" />
              <opc:Field Name="LocaleSpecified" TypeName="opc:Bit" />
              <opc:Field Name="AdditionalInfoSpecified" TypeName="opc:Bit" />
              <opc:Field Name="InnerStatusCodeSpecified" TypeName="opc:Bit" />
              <opc:Field Name="InnerDiagnosticInfoSpecified" TypeName="opc:Bit" />
              <opc:Field Name="Reserved1" TypeName="opc:Bit" Length="1" />
              <opc:Field Name="SymbolicId" TypeName="opc:Int32" SwitchField="SymbolicIdSpecified" />
              <opc:Field Name="NamespaceURI" TypeName="opc:Int32" SwitchField="NamespaceURISpecified" />
              <opc:Field Name="Locale" TypeName="opc:Int32" SwitchField="LocaleSpecified" />
              <opc:Field Name="LocalizedText" TypeName="opc:Int32" SwitchField="LocalizedTextSpecified" />
              <opc:Field Name="AdditionalInfo" TypeName="opc:CharArray" SwitchField="AdditionalInfoSpecified" />
              <opc:Field Name="InnerStatusCode" TypeName="ua:StatusCode" SwitchField="InnerStatusCodeSpecified" />
              <opc:Field Name="InnerDiagnosticInfo" TypeName="ua:DiagnosticInfo" SwitchField="InnerDiagnosticInfoSpecified" />
            </opc:StructuredType>

            <opc:StructuredType Name="QualifiedName">
              <opc:Documentation>A string qualified with a namespace index.</opc:Documentation>
              <opc:Field Name="NamespaceIndex" TypeName="opc:UInt16" />
              <opc:Field Name="Name" TypeName="opc:CharArray" />
            </opc:StructuredType>

            <opc:StructuredType Name="LocalizedText">
              <opc:Documentation>A string qualified with a namespace index.</opc:Documentation>
              <opc:Field Name="LocaleSpecified" TypeName="opc:Bit" />
              <opc:Field Name="TextSpecified" TypeName="opc:Bit" />
              <opc:Field Name="Reserved1" TypeName="opc:Bit" Length="6" />
              <opc:Field Name="Locale" TypeName="opc:CharArray" SwitchField="LocaleSpecified" />
              <opc:Field Name="Text" TypeName="opc:CharArray" SwitchField="TextSpecified" />
            </opc:StructuredType>

            <opc:StructuredType Name="DataValue">
              <opc:Documentation>A value with an associated timestamp, and quality.</opc:Documentation>
              <opc:Field Name="ValueSpecified" TypeName="opc:Bit" />
              <opc:Field Name="StatusCodeSpecified" TypeName="opc:Bit" />
              <opc:Field Name="SourceTimestampSpecified" TypeName="opc:Bit" />
              <opc:Field Name="ServerTimestampSpecified" TypeName="opc:Bit" />
              <opc:Field Name="SourcePicosecondsSpecified" TypeName="opc:Bit" />
              <opc:Field Name="ServerPicosecondsSpecified" TypeName="opc:Bit" />
              <opc:Field Name="Reserved1" TypeName="opc:Bit" Length="2" />
              <opc:Field Name="Value" TypeName="ua:Variant" SwitchField="ValueSpecified" />
              <opc:Field Name="StatusCode" TypeName="ua:StatusCode" SwitchField="StatusCodeSpecified" />
              <opc:Field Name="SourceTimestamp" TypeName="opc:DateTime" SwitchField="SourceTimestampSpecified" />
              <opc:Field Name="SourcePicoseconds" TypeName="opc:UInt16" SwitchField="SourcePicosecondsSpecified" />
              <opc:Field Name="ServerTimestamp" TypeName="opc:DateTime" SwitchField="ServerTimestampSpecified" />
              <opc:Field Name="ServerPicoseconds" TypeName="opc:UInt16" SwitchField="ServerPicosecondsSpecified" />
            </opc:StructuredType>

            <opc:StructuredType Name="ExtensionObject">
              <opc:Documentation>A serialized object prefixed with its data type identifier.</opc:Documentation>
              <opc:Field Name="TypeIdSpecified" TypeName="opc:Bit" />
              <opc:Field Name="BinaryBody" TypeName="opc:Bit" />
              <opc:Field Name="XmlBody" TypeName="opc:Bit" />
              <opc:Field Name="Reserved1" TypeName="opc:Bit" Length="5" />
              <opc:Field Name="TypeId" TypeName="ua:ExpandedNodeId" SwitchField="TypeIdSpecified" />
              <opc:Field Name="BodyLength" TypeName="opc:Int32" />
              <opc:Field Name="Body" TypeName="opc:Byte" LengthField="BodyLength" />
            </opc:StructuredType>

            <opc:StructuredType Name="Variant">
              <opc:Documentation>A union of several types.</opc:Documentation>
              <opc:Field Name="VariantType" TypeName="opc:Bit" Length="6" />
              <opc:Field Name="ArrayDimensionsSpecified" TypeName="opc:Bit" Length="1"/>
              <opc:Field Name="ArrayLengthSpecified" TypeName="opc:Bit" Length="1"/>
              <opc:Field Name="ArrayLength" TypeName="opc:Int32" SwitchField="ArrayLengthSpecified" />
              <opc:Field Name="Boolean" TypeName="opc:Boolean" LengthField="ArrayLength" SwitchField="VariantType" SwitchValue="1" />
              <opc:Field Name="SByte" TypeName="opc:SByte" LengthField="ArrayLength" SwitchField="VariantType" SwitchValue="2" />
              <opc:Field Name="Byte" TypeName="opc:Byte" LengthField="ArrayLength" SwitchField="VariantType" SwitchValue="3" />
              <opc:Field Name="Int16" TypeName="opc:Int16" LengthField="ArrayLength" SwitchField="VariantType" SwitchValue="4" />
              <opc:Field Name="UInt16" TypeName="opc:UInt16" LengthField="ArrayLength" SwitchField="VariantType" SwitchValue="5" />
              <opc:Field Name="Int32" TypeName="opc:Int32" LengthField="ArrayLength" SwitchField="VariantType" SwitchValue="6" />
              <opc:Field Name="UInt32" TypeName="opc:UInt32" LengthField="ArrayLength" SwitchField="VariantType" SwitchValue="7" />
              <opc:Field Name="Int64" TypeName="opc:Int64" LengthField="ArrayLength" SwitchField="VariantType" SwitchValue="8" />
              <opc:Field Name="UInt64" TypeName="opc:UInt64" LengthField="ArrayLength" SwitchField="VariantType" SwitchValue="9" />
              <opc:Field Name="Float" TypeName="opc:Float" LengthField="ArrayLength" SwitchField="VariantType" SwitchValue="10" />
              <opc:Field Name="Double" TypeName="opc:Double" LengthField="ArrayLength" SwitchField="VariantType" SwitchValue="11" />
              <opc:Field Name="String" TypeName="opc:CharArray" LengthField="ArrayLength" SwitchField="VariantType" SwitchValue="12" />
              <opc:Field Name="DateTime" TypeName="opc:DateTime" LengthField="ArrayLength" SwitchField="VariantType" SwitchValue="13" />
              <opc:Field Name="Guid" TypeName="opc:Guid" LengthField="ArrayLength" SwitchField="VariantType" SwitchValue="14" />
              <opc:Field Name="ByteString" TypeName="opc:ByteString" LengthField="ArrayLength" SwitchField="VariantType" SwitchValue="15" />
              <opc:Field Name="XmlElement" TypeName="ua:XmlElement" LengthField="ArrayLength" SwitchField="VariantType" SwitchValue="16" />
              <opc:Field Name="NodeId" TypeName="ua:NodeId" LengthField="ArrayLength" SwitchField="VariantType" SwitchValue="17" />
              <opc:Field Name="ExpandedNodeId" TypeName="ua:ExpandedNodeId" LengthField="ArrayLength" SwitchField="VariantType" SwitchValue="18" />
              <opc:Field Name="StatusCode" TypeName="ua:StatusCode" LengthField="ArrayLength" SwitchField="VariantType" SwitchValue="19" />
              <opc:Field Name="QualifiedName" TypeName="ua:QualifiedName" LengthField="ArrayLength" SwitchField="VariantType" SwitchValue="20" />
              <opc:Field Name="LocalizedText" TypeName="ua:LocalizedText" LengthField="ArrayLength" SwitchField="VariantType" SwitchValue="21" />
              <opc:Field Name="ExtensionObject" TypeName="ua:ExtensionObject" LengthField="ArrayLength" SwitchField="VariantType" SwitchValue="22" />
              <opc:Field Name="DataValue" TypeName="ua:DataValue" LengthField="ArrayLength" SwitchField="VariantType" SwitchValue="23" />
              <opc:Field Name="Variant" TypeName="ua:Variant" LengthField="ArrayLength" SwitchField="VariantType" SwitchValue="24" />
              <opc:Field Name="DiagnosticInfo" TypeName="ua:DiagnosticInfo" LengthField="ArrayLength" SwitchField="VariantType" SwitchValue="25" />
              <opc:Field Name="NoOfArrayDimensions" TypeName="opc:Int32" SwitchField="ArrayDimensionsSpecified" />
              <opc:Field Name="ArrayDimensions" TypeName="opc:Int32" LengthField="NoOfArrayDimensions" SwitchField="ArrayDimensionsSpecified" />
            </opc:StructuredType>

            <opc:EnumeratedType Name="NamingRuleType" LengthInBits="32">
              <opc:EnumeratedValue Name="Mandatory" Value="1" />
              <opc:EnumeratedValue Name="Optional" Value="2" />
              <opc:EnumeratedValue Name="Constraint" Value="3" />
            </opc:EnumeratedType>

            <!-- ***END*** -->
            """;

        /// <summary>
        /// ModelGenerator.cs  line#1104
        /// </summary>
        public static string ModelCompiler_Templates_BinarySchema_EnumeratedType_xml =>
            """
            <!--***START***-->
            <opc:EnumeratedType Name="_TypeName_" LengthInBits="_LengthInBits_"_IsOptionSet_>
              <!-- Documentation -->
              <!-- ListOfFields -->
            </opc:EnumeratedType>
            <!--***END***-->
            """;

        /// <summary>
        /// ModelGenerator.cs  line#1108
        /// </summary>
        public static string ModelCompiler_Templates_BinarySchema_ComplexType_xml =>
            """
            <!--***START***-->
            <opc:StructuredType Name="_TypeName_" BaseType="_BaseType_">
              <!-- Documentation -->
              <!-- ListOfFields -->
            </opc:StructuredType>
              <!--***END***-->
            """;

        /// <summary>
        /// ModelGenerator.cs  line#1111
        /// </summary>
        public static string ModelCompiler_Templates_BinarySchema_OpaqueType_xml =>
            """
            <!--***START***-->
            <opc:OpaqueType Name="_TypeName_">
              <!-- Documentation -->
            </opc:OpaqueType>
            <!--***END***-->
            """;

        /// <summary>
        /// ModelGenerator.cs  line#1337
        /// </summary>
        public static string ModelCompiler_Templates_Version2_ConstantsFile_cs =>
            """
            // ***START***
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
            using System.Text;
            using System.Reflection;
            using System.Xml;
            using System.Runtime.Serialization;
            // ListOfImports

            #pragma warning disable 1591

            namespace _Namespace_
            {
                // ListOfIdentifiers

                // ListOfNodeIds

                #region BrowseName Declarations
                [System.CodeDom.Compiler.GeneratedCodeAttribute("Opc.Ua.ModelCompiler", "1.0.0.0")]
                [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverageAttribute()]
                public static partial class BrowseNames
                {
                    // ListOfBrowseNames
                }
                #endregion

                #region Namespace Declarations
                [System.CodeDom.Compiler.GeneratedCodeAttribute("Opc.Ua.ModelCompiler", "1.0.0.0")]
                [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverageAttribute()]
                public static partial class Namespaces
                {
                    // ListOfNamespaceUris
                }
                #endregion
            }
            // ***END***
            """;

        /// <summary>
        /// ModelGenerator.cs  line#1363
        /// </summary>
        public static string ModelCompiler_Templates_Version2_NamespaceUri_cs =>
            """
            // ***START***
            /// <summary>
            /// The URI for the _Name_ namespace (.NET code namespace is '_CodeName_').
            /// </summary>
            public const string _Name_ = "_NamespaceUri_";
            // ***END***
            """;

        /// <summary>
        /// ModelGenerator.cs  line#1372
        /// </summary>
        public static string ModelCompiler_Templates_Version2_BrowseName_cs =>
            """
            // ***START***
            public const string _SymbolicName_ = "_BrowseName_";
            // ***END***
            """;

        /// <summary>
        /// ModelGenerator.cs  line#1381
        /// </summary>
        public static string ModelCompiler_Templates_Version2_IdClass_cs =>
            """
            // ***START***
            #region _NodeClass_ Identifiers
            /// <exclude />
            [System.CodeDom.Compiler.GeneratedCodeAttribute("Opc.Ua.ModelCompiler", "1.0.0.0")]
            [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverageAttribute()]
            public static partial class _NodeClass_s
            {
                // ListOfIdentifiers
            }
            #endregion
            // ***END***
            """;

        /// <summary>
        /// ModelGenerator.cs  line#1388
        /// </summary>
        public static string ModelCompiler_Templates_Version2_NodeIdClass_cs =>
            """
            // ***START***
            #region _NodeClass_ Node Identifiers
            /// <exclude />
            [System.CodeDom.Compiler.GeneratedCodeAttribute("Opc.Ua.ModelCompiler", "1.0.0.0")]
            [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverageAttribute()]
            public static partial class _NodeClass_Ids
            {
                // ListOfIdentifiers
            }
            #endregion
            // ***END***
            """;

        /// <summary>
        /// ModelGenerator.cs  line#1411
        /// ModelGenerator.cs  line#1470
        /// </summary>
        public static string ModelCompiler_Templates_Version2_TypesFile_cs =>
            """
            // ***START***
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
            using System.Text;
            using System.Xml;
            using System.Linq;
            using System.Runtime.Serialization;
            using System.Threading.Tasks;
            using System.Threading;
            // ListOfImports

            #pragma warning disable 1591

            namespace _Namespace_
            {
                // ListOfTypes
            }
            // ***END***
            """;

        /// <summary>
        /// ModelGenerator.cs  line#1447
        /// ModelGenerator.cs  line#1512
        /// </summary>
        public static string ModelCompiler_Templates_Version2_Type_cs =>
            """



            """;

        /// <summary>
        /// ModelGenerator.cs  line#1555
        /// </summary>
        public static string ModelCompiler_Templates_Version2_IdDeclaration_cs =>
            """
            // ***START***
            public const _IdType_ _SymbolicName_ = _Identifier_;
            // ***END***
            """;

        /// <summary>
        /// ModelGenerator.cs  line#1561
        /// </summary>
        public static string ModelCompiler_Templates_Version2_NodeIdDeclarationAbsolute_cs =>
            """
            // ***START***
            public static readonly ExpandedNodeId _SymbolicName_ = new ExpandedNodeId(_NamespacePrefix_._NodeClass_s._SymbolicName_, _NamespaceUri_);
            // ***END***
            """;

        /// <summary>
        /// ModelGenerator.cs  line#1565
        /// </summary>
        public static string ModelCompiler_Templates_Version2_NodeIdDeclaration_cs =>
            """
            // ***START***
            public static readonly NodeId _SymbolicName_ = new NodeId(_NamespacePrefix_._NodeClass_s._SymbolicName_);
            // ***END***
            """;

        /// <summary>
        /// ModelGenerator.cs  line#1708
        /// </summary>
        public static string ModelCompiler_Templates_Version2_DataTypes_Union_cs =>
            """
            // ***START***
            #region _BrowseName_ Class
            #if (!OPCUA_EXCLUDE__BrowseName_)
            /// <exclude />
            public enum _ClassName_Fields : uint
            {
                None = 0,
                // ListOfSwitchFields
            }

            /// <exclude />
            [System.CodeDom.Compiler.GeneratedCodeAttribute("Opc.Ua.ModelCompiler", "1.0.0.0")]
            [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverageAttribute()]
            [DataContract(Namespace = _XmlNamespaceUri_)]
            public partial class _BrowseName_ : IEncodeable, IJsonEncodeable
            {
                #region Constructors
                public _BrowseName_()
                {
                    Initialize();
                }

                [OnDeserializing]
                private void Initialize(StreamingContext context)
                {
                    Initialize();
                }

                private void Initialize()
                {
                    SwitchField = _ClassName_Fields.None;
                    // ListOfFieldInitializers
                }
                #endregion

                #region Public Properties
                [DataMember(Name = "SwitchField", IsRequired = true, Order = 0)]
                public _ClassName_Fields SwitchField { get; set; }

                // ListOfProperties
                #endregion

                #region IEncodeable Members
                /// <summary cref="IEncodeable.TypeId" />
                public virtual ExpandedNodeId TypeId => DataTypeIds._BrowseName_;

                /// <summary cref="IEncodeable.BinaryEncodingId" />
                public virtual ExpandedNodeId BinaryEncodingId => ObjectIds._BrowseName__Encoding_DefaultBinary;

                /// <summary cref="IEncodeable.XmlEncodingId" />
                public virtual ExpandedNodeId XmlEncodingId => ObjectIds._BrowseName__Encoding_DefaultXml;

                /// <summary cref="IJsonEncodeable.JsonEncodingId" />
                public virtual ExpandedNodeId JsonEncodingId => ObjectIds._BrowseName__Encoding_DefaultJson;

                /// <summary cref="IEncodeable.Encode(IEncoder)" />
                public virtual void Encode(IEncoder encoder)
                {
                    encoder.PushNamespace(_XmlNamespaceUri_);
                    encoder.WriteSwitchField((uint)SwitchField, out var fieldName);

                    switch (SwitchField)
                    {
                        default: { break; }
                        // ListOfEncodedFields
                    }

                    encoder.PopNamespace();
                }

                /// <summary cref="IEncodeable.Decode(IDecoder)" />
                public virtual void Decode(IDecoder decoder)
                {
                    decoder.PushNamespace(_XmlNamespaceUri_);

                    SwitchField = (_ClassName_Fields)decoder.ReadSwitchField(m_FieldNames, out var fieldName);

                    switch (SwitchField)
                    {
                        default: { break; }
                        // ListOfDecodedFields
                    }

                    decoder.PopNamespace();
                }

                /// <summary cref="IEncodeable.IsEqual(IEncodeable)" />
                public virtual bool IsEqual(IEncodeable encodeable)
                {
                    if (Object.ReferenceEquals(this, encodeable))
                    {
                        return true;
                    }

                    _BrowseName_ value = encodeable as _BrowseName_;

                    if (value == null)
                    {
                        return false;
                    }

                    if (value.SwitchField != this.SwitchField) return false;

                    switch (SwitchField)
                    {
                        default: { break; }
                        // ListOfComparedFields
                    }

                    return true;
                }

                /// <summary cref="ICloneable.Clone" />
                public virtual object Clone()
                {
                    return (_BrowseName_)this.MemberwiseClone();
                }

                /// <summary cref="Object.MemberwiseClone" />
                public new object MemberwiseClone()
                {
                    _BrowseName_ clone = (_BrowseName_)base.MemberwiseClone();

                    clone.SwitchField = this.SwitchField;

                    switch (SwitchField)
                    {
                        default: { break; }
                        // ListOfClonedFields
                    }

                    return clone;
                }
                #endregion

                #region Private Fields
                // ListOfFields

                private static readonly string[] m_FieldNames = Enum.GetNames(typeof(_ClassName_Fields)).Where(x => x != nameof(_ClassName_Fields.None)).ToArray();
                #endregion
            }
            // CollectionClass
            #endif
            #endregion
            // ***END***
            """;

        /// <summary>
        /// ModelGenerator.cs  line#1715
        /// </summary>
        public static string ModelCompiler_Templates_Version2_DataTypes_DerivedClassWithOptionalFields_cs =>
            """
            // ***START***
            #region _BrowseName_ Class
            #if (!OPCUA_EXCLUDE__BrowseName_)
            /// <exclude />
            [Flags]
            public enum _ClassName_Fields : uint
            {
                None = 0,
                // ListOfEncodingMaskFields
            }

            /// <exclude />
            [System.CodeDom.Compiler.GeneratedCodeAttribute("Opc.Ua.ModelCompiler", "1.0.0.0")]
            [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverageAttribute()]
            [DataContract(Namespace = _XmlNamespaceUri_)]
            public partial class _BrowseName_ : _BaseType_
            {
                #region Constructors
                public _BrowseName_()
                {
                    Initialize();
                }

                [OnDeserializing]
                private void Initialize(StreamingContext context)
                {
                    Initialize();
                }

                private void Initialize()
                {
                    // ListOfFieldInitializers
                }
                #endregion

                #region Public Properties
                // ListOfProperties
                #endregion

                #region IEncodeable Members
                /// <summary cref="IEncodeable.TypeId" />
                public override ExpandedNodeId TypeId => DataTypeIds._BrowseName_;

                /// <summary cref="IEncodeable.BinaryEncodingId" />
                public override ExpandedNodeId BinaryEncodingId => ObjectIds._BrowseName__Encoding_DefaultBinary;

                /// <summary cref="IEncodeable.XmlEncodingId" />
                public override ExpandedNodeId XmlEncodingId => ObjectIds._BrowseName__Encoding_DefaultXml;

                /// <summary cref="IJsonEncodeable.JsonEncodingId" />
                public override ExpandedNodeId JsonEncodingId => ObjectIds._BrowseName__Encoding_DefaultJson;

                /// <summary cref="IEncodeable.Encode(IEncoder)" />
                public override void Encode(IEncoder encoder)
                {
                    base.Encode(encoder);

                    encoder.PushNamespace(_XmlNamespaceUri_);

                    // ListOfEncodedFields

                    encoder.PopNamespace();
                }

                /// <summary cref="IEncodeable.Decode(IDecoder)" />
                public override void Decode(IDecoder decoder)
                {
                    base.Decode(decoder);

                    decoder.PushNamespace(_XmlNamespaceUri_);

                    // ListOfDecodedFields

                    decoder.PopNamespace();
                }

                /// <summary cref="IEncodeable.IsEqual(IEncodeable)" />
                public override bool IsEqual(IEncodeable encodeable)
                {
                    if (Object.ReferenceEquals(this, encodeable))
                    {
                        return true;
                    }

                    _BrowseName_ value = encodeable as _BrowseName_;

                    if (value == null)
                    {
                        return false;
                    }

                    // ListOfComparedFields

                    return base.IsEqual(encodeable);
                }

                /// <summary cref="ICloneable.Clone" />
                public override object Clone()
                {
                    return (_BrowseName_)this.MemberwiseClone();
                }

                /// <summary cref="Object.MemberwiseClone" />
                public new object MemberwiseClone()
                {
                    _BrowseName_ clone = (_BrowseName_)base.MemberwiseClone();

                    // ListOfClonedFields

                    return clone;
                }
                #endregion

                #region Private Fields
                // ListOfFields

                private static readonly string[] m_FieldNames = Enum.GetNames(typeof(_ClassName_Fields)).Where(x => x != nameof(_ClassName_Fields.None)).ToArray();
                #endregion
            }
            // CollectionClass
            #endif
            #endregion
            // ***END***
            """;

        /// <summary>
        /// ModelGenerator.cs  line#1718
        /// </summary>
        public static string ModelCompiler_Templates_Version2_DataTypes_ClassWithOptionalFields_cs =>
            """
            // ***START***
            #region _BrowseName_ Class
            #if (!OPCUA_EXCLUDE__BrowseName_)
            /// <exclude />
            [Flags]
            public enum _ClassName_Fields : uint
            {
                None = 0,
                // ListOfEncodingMaskFields
            }

            /// <exclude />
            [System.CodeDom.Compiler.GeneratedCodeAttribute("Opc.Ua.ModelCompiler", "1.0.0.0")]
            [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverageAttribute()]
            [DataContract(Namespace = _XmlNamespaceUri_)]
            public partial class _BrowseName_ : IEncodeable, IJsonEncodeable
            {
                #region Constructors
                public _BrowseName_()
                {
                    Initialize();
                }

                [OnDeserializing]
                private void Initialize(StreamingContext context)
                {
                    Initialize();
                }

                private void Initialize()
                {
                    EncodingMask = (uint)_ClassName_Fields.None;
                    // ListOfFieldInitializers
                }
                #endregion

                #region Public Properties
                [DataMember(Name = "EncodingMask", IsRequired = true, Order = 0)]
                public virtual uint EncodingMask { get; set; }

                // ListOfProperties
                #endregion

                #region IEncodeable Members
                /// <summary cref="IEncodeable.TypeId" />
                public virtual ExpandedNodeId TypeId => DataTypeIds._BrowseName_;

                /// <summary cref="IEncodeable.BinaryEncodingId" />
                public virtual ExpandedNodeId BinaryEncodingId => ObjectIds._BrowseName__Encoding_DefaultBinary;

                /// <summary cref="IEncodeable.XmlEncodingId" />
                public virtual ExpandedNodeId XmlEncodingId => ObjectIds._BrowseName__Encoding_DefaultXml;

                /// <summary cref="IJsonEncodeable.JsonEncodingId" />
                public virtual ExpandedNodeId JsonEncodingId => ObjectIds._BrowseName__Encoding_DefaultJson;

                /// <summary cref="IEncodeable.Encode(IEncoder)" />
                public virtual void Encode(IEncoder encoder)
                {
                    encoder.PushNamespace(_XmlNamespaceUri_);
                    encoder.WriteEncodingMask((uint)EncodingMask);

                    // ListOfEncodedFields

                    encoder.PopNamespace();
                }

                /// <summary cref="IEncodeable.Decode(IDecoder)" />
                public virtual void Decode(IDecoder decoder)
                {
                    decoder.PushNamespace(_XmlNamespaceUri_);

                    EncodingMask = decoder.ReadEncodingMask(m_FieldNames);

                    // ListOfDecodedFields

                    decoder.PopNamespace();
                }

                /// <summary cref="IEncodeable.IsEqual(IEncodeable)" />
                public virtual bool IsEqual(IEncodeable encodeable)
                {
                    if (Object.ReferenceEquals(this, encodeable))
                    {
                        return true;
                    }

                    _BrowseName_ value = encodeable as _BrowseName_;

                    if (value == null)
                    {
                        return false;
                    }

                    if (value.EncodingMask != this.EncodingMask) return false;

                    // ListOfComparedFields

                    return true;
                }

                /// <summary cref="ICloneable.Clone" />
                public virtual object Clone()
                {
                    return (_BrowseName_)this.MemberwiseClone();
                }

                /// <summary cref="Object.MemberwiseClone" />
                public new object MemberwiseClone()
                {
                    _BrowseName_ clone = (_BrowseName_)base.MemberwiseClone();

                    clone.EncodingMask = this.EncodingMask;

                    // ListOfClonedFields

                    return clone;
                }
                #endregion

                #region Private Fields
                // ListOfFields

                private static readonly string[] m_FieldNames = Enum.GetNames(typeof(_ClassName_Fields)).Where(x => x != nameof(_ClassName_Fields.None)).ToArray();
                #endregion
            }
            // CollectionClass
            #endif
            #endregion
            // ***END***
            """;

        /// <summary>
        /// ModelGenerator.cs  line#1723
        /// </summary>
        public static string ModelCompiler_Templates_Version2_DataTypes_Class_cs =>
            """
            // ***START***
            #region _BrowseName_ Class
            #if (!OPCUA_EXCLUDE__BrowseName_)
            /// <exclude />
            [System.CodeDom.Compiler.GeneratedCodeAttribute("Opc.Ua.ModelCompiler", "1.0.0.0")]
            [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverageAttribute()]
            [DataContract(Namespace = _XmlNamespaceUri_)]
            public _IsAbstract_partial class _BrowseName_ : IEncodeable, IJsonEncodeable
            {
                #region Constructors
                public _BrowseName_()
                {
                    Initialize();
                }

                [OnDeserializing]
                private void Initialize(StreamingContext context)
                {
                    Initialize();
                }

                private void Initialize()
                {
                    // ListOfFieldInitializers
                }
                #endregion

                #region Public Properties
                // ListOfProperties
                #endregion

                #region IEncodeable Members
                /// <summary cref="IEncodeable.TypeId" />
                public virtual ExpandedNodeId TypeId => DataTypeIds._BrowseName_;

                /// <summary cref="IEncodeable.BinaryEncodingId" />
                public virtual ExpandedNodeId BinaryEncodingId => ObjectIds._BrowseName__Encoding_DefaultBinary;

                /// <summary cref="IEncodeable.XmlEncodingId" />
                public virtual ExpandedNodeId XmlEncodingId => ObjectIds._BrowseName__Encoding_DefaultXml;

                /// <summary cref="IJsonEncodeable.JsonEncodingId" />
                public virtual ExpandedNodeId JsonEncodingId => ObjectIds._BrowseName__Encoding_DefaultJson;

                /// <summary cref="IEncodeable.Encode(IEncoder)" />
                public virtual void Encode(IEncoder encoder)
                {
                    encoder.PushNamespace(_XmlNamespaceUri_);

                    // ListOfEncodedFields

                    encoder.PopNamespace();
                }

                /// <summary cref="IEncodeable.Decode(IDecoder)" />
                public virtual void Decode(IDecoder decoder)
                {
                    decoder.PushNamespace(_XmlNamespaceUri_);

                    // ListOfDecodedFields

                    decoder.PopNamespace();
                }

                /// <summary cref="IEncodeable.IsEqual(IEncodeable)" />
                public virtual bool IsEqual(IEncodeable encodeable)
                {
                    if (Object.ReferenceEquals(this, encodeable))
                    {
                        return true;
                    }

                    _BrowseName_ value = encodeable as _BrowseName_;

                    if (value == null)
                    {
                        return false;
                    }

                    // ListOfComparedFields

                    return true;
                }

                /// <summary cref="ICloneable.Clone" />
                public virtual object Clone()
                {
                    return (_BrowseName_)this.MemberwiseClone();
                }

                /// <summary cref="Object.MemberwiseClone" />
                public new object MemberwiseClone()
                {
                    _BrowseName_ clone = (_BrowseName_)base.MemberwiseClone();

                    // ListOfClonedFields

                    return clone;
                }
                #endregion

                #region Private Fields
                // ListOfFields
                #endregion
            }
            // CollectionClass
            #endif
            #endregion
            // ***END***
            """;

        /// <summary>
        /// ModelGenerator.cs  line#1726
        /// ModelGenerator.cs  line#1732
        /// </summary>
        public static string ModelCompiler_Templates_Version2_DataTypes_DerivedClass_cs =>
            """
            // ***START***
            #region _BrowseName_ Class
            #if (!OPCUA_EXCLUDE__BrowseName_)
            /// <exclude />
            [System.CodeDom.Compiler.GeneratedCodeAttribute("Opc.Ua.ModelCompiler", "1.0.0.0")]
            [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverageAttribute()]
            [DataContract(Namespace = _XmlNamespaceUri_)]
            public partial class _BrowseName_ : _BaseType_
            {
                #region Constructors
                public _BrowseName_()
                {
                    Initialize();
                }

                [OnDeserializing]
                private void Initialize(StreamingContext context)
                {
                    Initialize();
                }

                private void Initialize()
                {
                    // ListOfFieldInitializers
                }
                #endregion

                #region Public Properties
                // ListOfProperties
                #endregion

                #region IEncodeable Members
                /// <summary cref="IEncodeable.TypeId" />
                public override ExpandedNodeId TypeId => DataTypeIds._BrowseName_;

                /// <summary cref="IEncodeable.BinaryEncodingId" />
                public override ExpandedNodeId BinaryEncodingId => ObjectIds._BrowseName__Encoding_DefaultBinary;

                /// <summary cref="IEncodeable.XmlEncodingId" />
                public override ExpandedNodeId XmlEncodingId => ObjectIds._BrowseName__Encoding_DefaultXml;

                /// <summary cref="IJsonEncodeable.JsonEncodingId" />
                public override ExpandedNodeId JsonEncodingId => ObjectIds._BrowseName__Encoding_DefaultJson;

                /// <summary cref="IEncodeable.Encode(IEncoder)" />
                public override void Encode(IEncoder encoder)
                {
                    base.Encode(encoder);

                    encoder.PushNamespace(_XmlNamespaceUri_);

                    // ListOfEncodedFields

                    encoder.PopNamespace();
                }

                /// <summary cref="IEncodeable.Decode(IDecoder)" />
                public override void Decode(IDecoder decoder)
                {
                    base.Decode(decoder);

                    decoder.PushNamespace(_XmlNamespaceUri_);

                    // ListOfDecodedFields

                    decoder.PopNamespace();
                }

                /// <summary cref="IEncodeable.IsEqual(IEncodeable)" />
                public override bool IsEqual(IEncodeable encodeable)
                {
                    if (Object.ReferenceEquals(this, encodeable))
                    {
                        return true;
                    }

                    _BrowseName_ value = encodeable as _BrowseName_;

                    if (value == null)
                    {
                        return false;
                    }

                    // ListOfComparedFields

                    return base.IsEqual(encodeable);
                }

                /// <summary cref="ICloneable.Clone" />
                public override object Clone()
                {
                    return (_BrowseName_)this.MemberwiseClone();
                }

                /// <summary cref="Object.MemberwiseClone" />
                public new object MemberwiseClone()
                {
                    _BrowseName_ clone = (_BrowseName_)base.MemberwiseClone();

                    // ListOfClonedFields

                    return clone;
                }
                #endregion

                #region Private Fields
                // ListOfFields
                #endregion
            }
            // CollectionClass
            #endif
            #endregion
            // ***END***
            """;

        /// <summary>
        /// ModelGenerator.cs  line#1735
        /// ModelGenerator.cs  line#1739
        /// </summary>
        public static string ModelCompiler_Templates_Version2_DataTypes_Enumeration_cs =>
            """
            // ***START***
            #region _BrowseName_ Enumeration
            #if (!OPCUA_EXCLUDE__BrowseName_)
            /// <exclude />
            [System.CodeDom.Compiler.GeneratedCodeAttribute("Opc.Ua.ModelCompiler", "1.0.0.0")]
            [DataContract(Namespace = _XmlNamespaceUri_)]
            [Flags]
            public enum _BrowseName_ : _BasicType_
            {
                // ListOfProperties
            }
            // CollectionClass
            #endif
            #endregion
            // ***END***


            """;

        /// <summary>
        /// ModelGenerator.cs  line#1754
        /// </summary>
        public static string ModelCompiler_Templates_Version2_ObjectType_cs =>
            """
            // ***START***
            #region _ClassName_State Class
            #if (!OPCUA_EXCLUDE__ClassName_State)
            /// <exclude />
            [System.CodeDom.Compiler.GeneratedCodeAttribute("Opc.Ua.ModelCompiler", "1.0.0.0")]
            [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverageAttribute()]
            public partial class _ClassName_State : _BaseClassName_State<BaseT>
            {
                #region Constructors
                public _ClassName_State(NodeState parent) : base(parent)
                {
                }

                protected override NodeId GetDefaultTypeDefinitionId(NamespaceTable namespaceUris)
                {
                    return Opc.Ua.NodeId.Create(_NamespacePrefix_.ObjectTypes._TypeName_, _NamespaceUri_, namespaceUris);
                }

                #if (!OPCUA_EXCLUDE_InitializationStrings)
                protected override void Initialize(ISystemContext context)
                {
                    base.Initialize(context);
                    Initialize(context, InitializationString);
                    InitializeOptionalChildren(context);
                }

                protected override void Initialize(ISystemContext context, NodeState source)
                {
                    InitializeOptionalChildren(context);
                    base.Initialize(context, source);
                }

                protected override void InitializeOptionalChildren(ISystemContext context)
                {
                    base.InitializeOptionalChildren(context);
                    // InitializeOptionalChildren
                }

                #region Initialization String
                // InitializationString
                #endregion
                #endif
                #endregion

                #region Public Properties
                // ListOfProperties
                #endregion

                #region Overridden Methods
                // FindChildMethods
                #endregion

                #region Private Fields
                // ListOfFields
                #endregion
            }
            #endif
            #endregion
            // ***END***
            """;

        /// <summary>
        /// ModelGenerator.cs  line#1759
        /// </summary>
        public static string ModelCompiler_Templates_Version2_VariableType_cs =>
            """
            // ***START***
            #region _ClassName_State Class
            #if (!OPCUA_EXCLUDE__ClassName_State)
            /// <exclude />
            [System.CodeDom.Compiler.GeneratedCodeAttribute("Opc.Ua.ModelCompiler", "1.0.0.0")]
            [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverageAttribute()]
            public partial class _ClassName_State : _BaseClassName_State<BaseT>
            {
                #region Constructors
                public _ClassName_State(NodeState parent) : base(parent)
                {
                }

                protected override NodeId GetDefaultTypeDefinitionId(NamespaceTable namespaceUris)
                {
                    return Opc.Ua.NodeId.Create(_NamespacePrefix_.VariableTypes._TypeName_, _NamespaceUri_, namespaceUris);
                }

                protected override NodeId GetDefaultDataTypeId(NamespaceTable namespaceUris)
                {
                    return Opc.Ua.NodeId.Create(_DataTypeNamespacePrefix_.DataTypes._DataType_, _DataTypeNamespaceUri_, namespaceUris);
                }

                protected override int GetDefaultValueRank()
                {
                    return _ValueRank_;
                }

                #if (!OPCUA_EXCLUDE_InitializationStrings)
                protected override void Initialize(ISystemContext context)
                {
                    base.Initialize(context);
                    Initialize(context, InitializationString);
                    InitializeOptionalChildren(context);
                }

                protected override void Initialize(ISystemContext context, NodeState source)
                {
                    InitializeOptionalChildren(context);
                    base.Initialize(context, source);
                }

                protected override void InitializeOptionalChildren(ISystemContext context)
                {
                    base.InitializeOptionalChildren(context);
                    // InitializeOptionalChildren
                }

                #region Initialization String
                // InitializationString
                #endregion
                #endif
                #endregion

                #region Public Properties
                // ListOfProperties
                #endregion

                #region Overridden Methods
                // FindChildMethods
                #endregion

                #region Private Fields
                // ListOfFields
                #endregion
            }
            // TypedVariableType
            // VariableTypeValue
            #endif
            #endregion
            // ***END***
            """;

        /// <summary>
        /// ModelGenerator.cs  line#1764
        /// </summary>
        public static string ModelCompiler_Templates_Version2_MethodType_cs =>
            """
            // ***START***
            #region _ClassName_ Class
            #if (!OPCUA_EXCLUDE__ClassName_)
            /// <exclude />
            [System.CodeDom.Compiler.GeneratedCodeAttribute("Opc.Ua.ModelCompiler", "1.0.0.0")]
            [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverageAttribute()]
            public partial class _ClassName_ : MethodState
            {
                #region Constructors
                public _ClassName_(NodeState parent) : base(parent)
                {
                }

                public new static NodeState Construct(NodeState parent)
                {
                    return new _ClassName_(parent);
                }

                #if (!OPCUA_EXCLUDE_InitializationStrings)
                protected override void Initialize(ISystemContext context)
                {
                    base.Initialize(context);
                    Initialize(context, InitializationString);
                    InitializeOptionalChildren(context);
                }

                protected override void InitializeOptionalChildren(ISystemContext context)
                {
                    base.InitializeOptionalChildren(context);
                    // InitializeOptionalChildren
                }

                #region Initialization String
                // InitializationString
                #endregion
                #endif
                #endregion

                #region Event Callbacks
                public _ClassName_MethodCallHandler OnCall;

                public _ClassName_MethodAsyncCallHandler OnCallAsync;
                #endregion

                #region Public Properties
                // ListOfProperties
                #endregion

                #region Overridden Methods
                protected override ServiceResult Call(
                    ISystemContext _context,
                    NodeId _objectId,
                    IList<object> _inputArguments,
                    IList<object> _outputArguments)
                {
                    if (OnCall == null)
                    {
                        return base.Call(_context, _objectId, _inputArguments, _outputArguments);
                    }

                    ServiceResult _result = null;
                    // ListOfInputArguments
                    // ListOfOutputDeclarations

                    if (OnCall != null)
                    {
                        _result = OnCall(_context);
                    }
                    // ListOfOutputArguments

                    return _result;
                }

                #if (OPCUA_INCLUDE_ASYNC)
                protected override async ValueTask<ServiceResult> CallAsync(
                    ISystemContext _context,
                    NodeId _objectId,
                    IList<object> _inputArguments,
                    IList<object> _outputArguments,
                    CancellationToken cancellationToken = default)
                {
                    if (OnCall == null && OnCallAsync == null)
                    {
                        return await base.CallAsync(_context, _objectId, _inputArguments, _outputArguments, cancellationToken).ConfigureAwait(false);
                    }

                    _ClassName_Result _result = null;
                    // ListOfInputArguments

                    if (OnCallAsync != null)
                    {
                        _result = await OnCallAsync(_context);
                    }
                    else if (OnCall != null)
                    {
                        return Call(_context, _objectId, _inputArguments, _outputArguments);
                    }
                    // ListOfOutputArgumentsFromResult

                    return _result.ServiceResult;
                }
                #endif

                // FindChildMethods
                #endregion

                #region Private Fields
                // ListOfFields
                #endregion
            }

            /// <exclude />
            public delegate ServiceResult _ClassName_MethodCallHandler(
                _ISystemContext context_);

            /// <exclude />
            public partial class _ClassName_Result
            {
                public ServiceResult ServiceResult { get; set; }
                // ListOfResultProperties
            }

            /// <exclude />
            public delegate ValueTask<_ClassName_Result> _ClassName_MethodAsyncCallHandler(
                _ISystemContext context_, CancellationToken cancellationToken);
            #endif
            #endregion
            // ***END***
            """;

        /// <summary>
        /// ModelGenerator.cs  line#2006
        /// </summary>
        public static string ModelCompiler_Templates_Version2_DataTypes_CollectionClass_cs =>
            """
            // ***START***
            #region _BrowseName_Collection Class
            /// <exclude />
            [System.CodeDom.Compiler.GeneratedCodeAttribute("Opc.Ua.ModelCompiler", "1.0.0.0")]
            [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverageAttribute()]
            [CollectionDataContract(Name = "ListOf_BrowseName_", Namespace = _XmlNamespaceUri_, ItemName = "_BrowseName_")]
            public partial class _BrowseName_Collection : List<_BrowseName_>, ICloneable
            {
                #region Constructors
                public _BrowseName_Collection() {}

                public _BrowseName_Collection(int capacity) : base(capacity) {}

                public _BrowseName_Collection(IEnumerable<_BrowseName_> collection) : base(collection) {}
                #endregion

                #region Static Operators
                public static implicit operator _BrowseName_Collection(_BrowseName_[] values)
                {
                    if (values != null)
                    {
                        return new _BrowseName_Collection(values);
                    }

                    return new _BrowseName_Collection();
                }

                public static explicit operator _BrowseName_[](_BrowseName_Collection values)
                {
                    if (values != null)
                    {
                        return values.ToArray();
                    }

                    return null;
                }
                #endregion

                #region ICloneable Methods
                public object Clone()
                {
                    return (_BrowseName_Collection)this.MemberwiseClone();
                }
                #endregion

                /// <summary cref="Object.MemberwiseClone" />
                public new object MemberwiseClone()
                {
                    _BrowseName_Collection clone = new _BrowseName_Collection(this.Count);

                    for (int ii = 0; ii < this.Count; ii++)
                    {
                        clone.Add((_BrowseName_)CoreUtils.Clone(this[ii]));
                    }

                    return clone;
                }
            }
            #endregion
            // ***END***
            """;

        /// <summary>
        /// ModelGenerator.cs  line#2085
        /// </summary>
        public static string ModelCompiler_Templates_Version2_TypedVariableType_cs =>
            """
            // ***START***
            #region _ClassName_State<T> Class
            /// <exclude />
            [System.CodeDom.Compiler.GeneratedCodeAttribute("Opc.Ua.ModelCompiler", "1.0.0.0")]
            [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverageAttribute()]
            public class _ClassName_State<T> : _ClassName_State
            {
                #region Constructors
                public _ClassName_State(NodeState parent) : base(parent)
                {
                    Value = default(T);
                }

                protected override void Initialize(ISystemContext context)
                {
                    base.Initialize(context);

                    Value = default(T);
                    DataType = TypeInfo.GetDataTypeId(typeof(T));
                    ValueRank = TypeInfo.GetValueRank(typeof(T));
                }

                protected override void Initialize(ISystemContext context, NodeState source)
                {
                    InitializeOptionalChildren(context);
                    base.Initialize(context, source);
                }
                #endregion

                #region Public Members
                public new T Value
                {
                    get
                    {
                        return CheckTypeBeforeCast<T>(((BaseVariableState)this).Value, true);
                    }

                    set
                    {
                        ((BaseVariableState)this).Value = value;
                    }
                }
                #endregion
            }
            #endregion
            // ***END***
            """;

        /// <summary>
        /// ModelGenerator.cs  line#2092
        /// </summary>
        public static string ModelCompiler_Templates_Version2_VariableTypeValue_cs =>
            """
            // ***START***
            #region _ClassName_Value Class
            /// <exclude />
            [System.CodeDom.Compiler.GeneratedCodeAttribute("Opc.Ua.ModelCompiler", "1.0.0.0")]
            [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverageAttribute()]
            public class _ClassName_Value : BaseVariableValue
            {
                #region Constructors
                public _ClassName_Value(_ClassName_State variable, _DataType_ value, object dataLock) : base(dataLock)
                {
                    m_value = value;

                    if (m_value == null)
                    {
                        m_value = new _DataType_();
                    }

                    Initialize(variable);
                }
                #endregion

                #region Public Members
                public _ClassName_State Variable
                {
                    get { return m_variable; }
                }

                public _DataType_ Value
                {
                    get { return m_value; }
                    set { m_value = value; }
                }
                #endregion

                #region Private Methods
                private void Initialize(_ClassName_State variable)
                {
                    lock (Lock)
                    {
                        m_variable = variable;

                        variable.Value = m_value;

                        variable.OnReadValue = OnReadValue;
                        variable.OnWriteValue = OnWriteValue;

                        BaseVariableState instance = null;
                        List<BaseInstanceState> updateList = new List<BaseInstanceState>();
                        updateList.Add(variable);

                        // ListOfChildInitializers

                        SetUpdateList(updateList);
                    }
                }

                protected ServiceResult OnReadValue(
                    ISystemContext context,
                    NodeState node,
                    NumericRange indexRange,
                    QualifiedName dataEncoding,
                    ref object value,
                    ref StatusCode statusCode,
                    ref DateTime timestamp)
                {
                    lock (Lock)
                    {
                        DoBeforeReadProcessing(context, node);

                        if (m_value != null)
                        {
                            value = m_value;
                        }

                        return Read(context, node, indexRange, dataEncoding, ref value, ref statusCode, ref timestamp);
                    }
                }

                private ServiceResult OnWriteValue(
                    ISystemContext context,
                    NodeState node,
                    NumericRange indexRange,
                    QualifiedName dataEncoding,
                    ref object value,
                    ref StatusCode statusCode,
                    ref DateTime timestamp)
                {
                    lock (Lock)
                    {
                        _DataType_ newValue;
                        if (value is ExtensionObject extensionObject)
                        {
                            newValue = (_DataType_)extensionObject.Body;
                        }
                        else
                        {
                            newValue = (_DataType_)value;
                        }

                        if (!CoreUtils.IsEqual(m_value, newValue))
                        {
                            UpdateChildrenChangeMasks(context, ref newValue, ref statusCode, ref timestamp);
                            Timestamp = timestamp;
                            m_value = (_DataType_)Write(newValue);
                            m_variable.UpdateChangeMasks(NodeStateChangeMasks.Value);
                        }
                    }

                    return ServiceResult.Good;
                }

                private void UpdateChildrenChangeMasks(ISystemContext context, ref _DataType_ newValue, ref StatusCode statusCode, ref DateTime timestamp)
                {
                    // ListOfUpdateChildrenChangeMasks
                }

                private void UpdateParent(ISystemContext context, ref StatusCode statusCode, ref DateTime timestamp)
                {
                    Timestamp = timestamp;
                    m_variable.UpdateChangeMasks(NodeStateChangeMasks.Value);
                    m_variable.ClearChangeMasks(context, false);
                }

                private void UpdateChildVariableStatus(BaseVariableState child, ref StatusCode statusCode, ref DateTime timestamp)
                {
                    if (child == null) return;
                    child.StatusCode = statusCode;
                    if (timestamp == DateTime.MinValue)
                    {
                        timestamp = DateTime.UtcNow;
                    }
                    child.Timestamp = timestamp;
                }

                // ListOfChildMethods
                #endregion

                #region Private Fields
                private _DataType_ m_value;
                private _ClassName_State m_variable;
                #endregion
            }
            #endregion
            // ***END***
            """;

        /// <summary>
        /// ModelGenerator.cs  line#2107
        /// </summary>
        public static string ModelCompiler_Templates_Version2_InitializeOptionalChild_cs =>
            """
            // ***START***
            if (_ChildName_ != null)
            {
                _ChildName_.Initialize(context, _ChildName__InitializationString);
            }
            // ***END***
            """;

        /// <summary>
        /// ModelGenerator.cs  line#2142
        /// ModelGenerator.cs  line#2149
        /// </summary>
        public static string ModelCompiler_Templates_Version2_Property_cs =>
            """
            // ***START***
            public new _ClassName_ _ChildName_
            {
                get => _FieldName_;

                set
                {
                    if (!Object.ReferenceEquals(_FieldName_, value))
                    {
                        ChangeMasks |= NodeStateChangeMasks.Children;
                    }

                    _FieldName_ = value;
                }
            }
            // ***END***
            """;

        /// <summary>
        /// ModelGenerator.cs  line#2156
        /// ModelGenerator.cs  line#2163
        /// </summary>
        public static string ModelCompiler_Templates_Version2_FindChildMethods_cs =>
            """
            // ***START***
            public override void GetChildren(
                ISystemContext context,
                IList<BaseInstanceState> children)
            {
                // ListOfFindChildren

                base.GetChildren(context, children);
            }

            protected override void RemoveExplicitlyDefinedChild(BaseInstanceState child)
            {
                // ListOfRemoveChild

                base.RemoveExplicitlyDefinedChild(child);
            }

            protected override BaseInstanceState FindChild(
                ISystemContext context,
                QualifiedName browseName,
                bool createOrReplace,
                BaseInstanceState replacement)
            {
                if (QualifiedName.IsNull(browseName))
                {
                    return null;
                }

                BaseInstanceState instance = null;

                switch (browseName.Name)
                {
                    // ListOfFindChildCase
                }

                if (instance != null)
                {
                    return instance;
                }

                return base.FindChild(context, browseName, createOrReplace, replacement);
            }
            // ***END***
            """;

        /// <summary>
        /// ModelGenerator.cs  line#2317
        /// </summary>
        public static string ModelCompiler_Templates_Version2_VariableTypeValueField_cs =>
            """
            // ***START***
            #region _ChildName_ Access Methods
            private ServiceResult OnRead__ChildName_(
                ISystemContext context,
                NodeState node,
                NumericRange indexRange,
                QualifiedName dataEncoding,
                ref object value,
                ref StatusCode statusCode,
                ref DateTime timestamp)
            {
                lock (Lock)
                {
                    DoBeforeReadProcessing(context, node);

                    var childVariable = m_variable?._ChildPath_;
                    if (childVariable != null && StatusCode.IsBad(childVariable.StatusCode))
                    {
                        value = null;
                        statusCode = childVariable.StatusCode;
                        return new ServiceResult(statusCode);
                    }

                    if (m_value != null)
                    {
                        value = m_value._ChildPath_;
                    }

                    var result = Read(context, node, indexRange, dataEncoding, ref value, ref statusCode, ref timestamp);

                    if (childVariable != null && ServiceResult.IsNotBad(result))
                    {
                        timestamp = childVariable.Timestamp;
                        if (statusCode != childVariable.StatusCode)
                        {
                            statusCode = childVariable.StatusCode;
                            result = new ServiceResult(statusCode);
                        }
                    }

                    return result;
                }
            }

            private ServiceResult OnWrite__ChildName_(
                ISystemContext context,
                NodeState node,
                NumericRange indexRange,
                QualifiedName dataEncoding,
                ref object value,
                ref StatusCode statusCode,
                ref DateTime timestamp)
            {
                lock (Lock)
                {
                    UpdateChildVariableStatus(m_variable._ChildPath_, ref statusCode, ref timestamp);
                    m_value._ChildPath_ = (_ChildDataType_)Write(value);
                    UpdateParent(context, ref statusCode, ref timestamp);
                }

                return ServiceResult.Good;
            }
            #endregion
            // ***END***
            """;

        /// <summary>
        /// ModelGenerator.cs  line#3339
        /// ModelGenerator.cs  line#3345
        /// </summary>
        public static string ModelCompiler_Templates_Version2_DataTypes_Property_cs =>
            """
            // ***START***
            [DataMember(Name = "_BrowseName_", IsRequired = _IsRequired_, EmitDefaultValue = _EmitDefaultValue_, Order = _FieldIndex_)]
            public _TypeName_ _BrowseName_
            {
                get { return _FieldName_;  }
                set { _FieldName_ = value; }
            }
            // ***END***
            """;

        /// <summary>
        /// ModelGenerator.cs  line#3342
        /// </summary>
        public static string ModelCompiler_Templates_Version2_DataTypes_ArrayProperty_cs =>
            """
            // ***START***
            /// <remarks />
            [DataMember(Name = "_BrowseName_", IsRequired = _IsRequired_, EmitDefaultValue = _EmitDefaultValue_, Order = _FieldIndex_)]
            public _TypeName_ _BrowseName_
            {
                get
                {
                    return _FieldName_;
                }

                set
                {
                    _FieldName_ = value;

                    if (value == null)
                    {
                        _FieldName_ = _DefaultValue_;
                    }
                }
            }
            // ***END***
            """;

        /// <summary>
        /// ModelGenerator.cs  line#3348
        /// </summary>
        public static string ModelCompiler_Templates_Version2_DataTypes_EnumerationValue_cs =>
            """
            // ***START***
            [EnumMember(Value = "_XmlIdentifier_")]
            _EnumerationName_ = _Identifier_,
            // ***END***
            """;

        /// <summary>
        /// ModelGenerator.cs  line#3379
        /// </summary>
        public static string ModelCompiler_Templates_Version2_PropertyOverride_cs =>
            """
            // ***START***
            public new _ClassName_ _ChildName_
            {
                get { return (_ClassName_)base._ChildName_; }
                set { base._ChildName_ = value; }
            }
            // ***END***
            """;

        /// <summary>
        /// ModelGenerator.cs  line#3579
        /// </summary>
        public static string ModelCompiler_Templates_Version2_FindChildCase_cs =>
            """
            // ***START***
            case _BrowseNameNamespacePrefix_.BrowseNames._ChildName_:
            {
                if (createOrReplace)
                {
                    if (_ChildName_ == null)
                    {
                        if (replacement == null)
                        {
                            _ChildName_ = new _ClassName_(this);
                        }
                        else
                        {
                            _ChildName_ = (_ClassName_)replacement;
                        }
                    }
                }

                instance = _ChildName_;
                break;
            }
            // ***END***
            """;

        /// <summary>
        /// ModelGenerator.cs  line#3611
        /// </summary>
        public static string ModelCompiler_Templates_Version2_FindChildren_cs =>
            """
            // ***START***
            if (_FieldName_ != null)
            {
                children.Add(_FieldName_);
            }
            // ***END***
            """;

        /// <summary>
        /// ModelGenerator.cs  line#3618
        /// </summary>
        public static string ModelCompiler_Templates_Version2_RemoveChild_cs =>
            """
            // ***START***
            if (Object.ReferenceEquals(_FieldName_, child))
            {
                _FieldName_ = null;
                return;
            }
            // ***END***
            """;

        /// <summary>
        /// StackGenerator.cs  line#138
        /// </summary>
        public static string ModelCompiler_StackGenerator_DotNet_Templates_Endpoints_File_cs =>
            """
            // ***START***
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

            #if (!NET_STANDARD)
            using System.Collections.Generic;
            using System.Xml;
            using System.Threading;
            using System.Security.Principal;
            using System.ServiceModel;
            using System.Runtime.Serialization;
            #endif

            #if (NET_STANDARD_ASYNC)
            using System.Threading;
            using System.Threading.Tasks;
            #endif

            namespace _Prefix_
            {
                // _SERVICESETS_
            }
            // ***END***
            """;

        /// <summary>
        /// StackGenerator.cs  line#147
        /// </summary>
        public static string ModelCompiler_StackGenerator_DotNet_Templates_Endpoints_ServiceSet_cs =>
            """
            // ***START***
            #region _ServiceSet_Endpoint Class
            /// <summary>
            /// A endpoint object used by clients to access a UA service.
            /// </summary>
            /// <exclude />
            [System.CodeDom.Compiler.GeneratedCodeAttribute("Opc.Ua.ModelCompiler", "1.0.0.0")]
            [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverageAttribute()]
            #if (!NET_STANDARD)
            [ServiceMessageContextBehavior()]
            [ServiceBehavior(Namespace = Namespaces._ServicesNamespace_, InstanceContextMode=InstanceContextMode.PerSession, ConcurrencyMode=ConcurrencyMode.Multiple)]
            #endif
            public partial class _ServiceSet_Endpoint : EndpointBase, _IEndpoints_
            {
                #region Constructors
                /// <summary>
                /// Initializes the object when it is created by the WCF framework.
                /// </summary>
                public _ServiceSet_Endpoint()
                {
                    this.CreateKnownTypes();
                }

                /// <summary>
                /// Initializes the when it is created directly.
                /// </summary>
                public _ServiceSet_Endpoint(IServiceHostBase host) : base(host)
                {
                    this.CreateKnownTypes();
                }

                /// <summary>
                /// Initializes a new instance of the <see cref="_ServiceSet_Endpoint"/> class.
                /// </summary>
                /// <param name="server">The server.</param>
                public _ServiceSet_Endpoint(ServerBase server) : base(server)
                {
                    this.CreateKnownTypes();
                }
                #endregion

                #region Public Members
                /// <summary>
                /// The UA server instance that the endpoint is connected to.
                /// </summary>
                protected I_ServiceSet_Server ServerInstance
                {
                    get
                    {
                        if (ServiceResult.IsBad(ServerError))
                        {
                            throw new ServiceResultException(ServerError);
                        }

                        return ServerForContext as I_ServiceSet_Server;
                     }
                }
                #endregion

                #region I_ServiceSet_Endpoint Members
                // _MethodList_
                #endregion

                #region Protected Members
                /// <summary>
                /// Populates the known types table.
                /// </summary>
                protected virtual void CreateKnownTypes()
                {
                    // AddKnownType
                }
                #endregion
            }
            #endregion
            // ***END***
            """;

        /// <summary>
        /// StackGenerator.cs  line#193
        /// </summary>
        public static string ModelCompiler_StackGenerator_DotNet_Templates_Endpoints_Method_cs =>
            """
            // ***START***
            #region _NAME_ Service
            #if (!OPCUA_EXCLUDE__NAME_)
            #if (!NET_STANDARD_NO_SYNC && !NET_STANDARD_NO_APM)
            /// <summary>
            /// Invokes the _NAME_ service.
            /// </summary>
            #if (NET_STANDARD_OBSOLETE_SYNC && !OPCUA_EXCLUDE__NAME__ASYNC)
            [Obsolete("Sync methods are deprecated in this version. Use _NAME_Async instead.")]
            #endif
            public IServiceResponse _NAME_(IServiceRequest incoming, SecureChannelContext secureChannelContext)
            {
                _NAME_Response response = null;

                try
                {
                    OnRequestReceived(incoming);

                    _NAME_Request request = (_NAME_Request)incoming;

                    // DeclareResponseParameters

                    response = new _NAME_Response();

                    InvokeService();
                    // SetResponseParameters
                }
                finally
                {
                    OnResponseSent(response);
                }

                return response;
            }

            #if (OPCUA_USE_SYNCHRONOUS_ENDPOINTS)
            /// <summary>
            /// The operation contract for the _NAME_ service.
            /// </summary>
            public virtual _NAME_ResponseMessage _NAME_(_NAME_Message request)
            {
                _NAME_Response response = null;

                try
                {
                    // OnRequestReceived(message._NAME_Request);

                    SetRequestContext(RequestEncoding.Xml);
                    response = (_NAME_Response)_NAME_(request._NAME_Request);

                    // OnResponseSent(response);
                    return new _NAME_ResponseMessage(response);
                }
                catch (Exception e)
                {
                    Exception fault = CreateSoapFault(request._NAME_Request, e);
                    // OnResponseFaultSent(fault);
                    throw fault;
                }
            }
            #else
            /// <summary>
            /// Asynchronously calls the _NAME_ service.
            /// </summary>
            #if NET_STANDARD_OBSOLETE_APM
            [Obsolete("Begin/End methods are deprecated in this version. Use _NAME_Async instead.")]
            #endif
            public virtual IAsyncResult Begin_NAME_(_NAME_Message message, AsyncCallback callback, object callbackData)
            {
                try
                {
                    // check for bad data.
                    if (message == null) throw new ArgumentNullException(nameof(message));

                    OnRequestReceived(message._NAME_Request);

                    // set the request context.
                    SetRequestContext(RequestEncoding.Xml);

                    // create handler.
                    ProcessRequestAsyncResult result = new ProcessRequestAsyncResult(this, callback, callbackData, 0);
                    return result.BeginProcessRequest(SecureChannelContext.Current, message._NAME_Request);
                }
                catch (Exception e)
                {
                    Exception fault = CreateSoapFault(message._NAME_Request, e);
                    OnResponseFaultSent(fault);
                    throw fault;
                }
            }

            /// <summary>
            /// Waits for an asynchronous call to the _NAME_ service to complete.
            /// </summary>
            #if NET_STANDARD_OBSOLETE_APM
            [Obsolete("Begin/End methods are deprecated in this version. Use _NAME_Async instead.")]
            #endif
            public virtual _NAME_ResponseMessage End_NAME_(IAsyncResult ar)
            {
                try
                {
                    IServiceResponse response = ProcessRequestAsyncResult.WaitForComplete(ar, true);
                    OnResponseSent(response);
                    return new _NAME_ResponseMessage((_NAME_Response)response);
                }
                catch (Exception e)
                {
                    Exception fault = CreateSoapFault(ProcessRequestAsyncResult.GetRequest(ar), e);
                    OnResponseFaultSent(fault);
                    throw fault;
                }
            }
            #endif
            #endif

            #if (!OPCUA_EXCLUDE__NAME__ASYNC)
            /// <summary>
            /// Invokes the _NAME_ service.
            /// </summary>
            public async Task<IServiceResponse> _NAME_Async(IServiceRequest incoming, SecureChannelContext secureChannelContext, CancellationToken cancellationToken = default)
            {
                _NAME_Response response = null;

                try
                {
                    OnRequestReceived(incoming);

                    _NAME_Request request = (_NAME_Request)incoming;

                    InvokeServiceAsync();
                }
                finally
                {
                    OnResponseSent(response);
                }

                return response;
            }
            #endif
            #endif
            #endregion
            // ***END***
            """;

        /// <summary>
        /// StackGenerator.cs  line#405
        /// </summary>
        public static string ModelCompiler_StackGenerator_DotNet_Templates_ServerApi_File_cs =>
            """
            // ***START***
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
            using System.Threading;
            using System.Threading.Tasks;

            namespace _Prefix_
            {
                // _SERVICESETS_
            }
            // ***END***
            """;

        /// <summary>
        /// StackGenerator.cs  line#413
        /// </summary>
        public static string ModelCompiler_StackGenerator_DotNet_Templates_ServerApi_ServiceSet_cs =>
            """
            // ***START***
            #region I_ServiceSet_Server Interface
            /// <summary>
            /// An interface to a UA server implementation.
            /// </summary>
            /// <exclude />
            [System.CodeDom.Compiler.GeneratedCodeAttribute("Opc.Ua.ModelCompiler", "1.0.0.0")]
            public interface I_ServiceSet_Server : IServerBase
            {
                // _ServerApi_
            }
            #endregion

            #region _ServiceSet_ServerBase Class
            /// <summary>
            /// A basic implementation of the UA server.
            /// </summary>
            /// <exclude />
            [System.CodeDom.Compiler.GeneratedCodeAttribute("Opc.Ua.ModelCompiler", "1.0.0.0")]
            [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverageAttribute()]
            public partial class _ServiceSet_ServerBase : ServerBase, I_ServiceSet_Server
            {
                // _ServerStubs_
            }
            #endregion
            // ***END***
            """;

        /// <summary>
        /// StackGenerator.cs  line#447
        /// </summary>
        public static string ModelCompiler_StackGenerator_DotNet_Templates_ServerApi_InterfaceMethod_cs =>
            """
            // ***START***
            #if (!OPCUA_EXCLUDE__NAME_)
            /// <summary>
            /// Invokes the _NAME_ service.
            /// </summary>
            #if (NET_STANDARD_OBSOLETE_SYNC && !OPCUA_EXCLUDE__NAME__ASYNC)
            [Obsolete("Sync methods are deprecated in this version. Use _NAME_Async instead.")]
            #endif
            void Interface();

            #if (!OPCUA_EXCLUDE__NAME__ASYNC)
            /// <summary>
            /// Invokes the _NAME_ service using async Task based request.
            /// </summary>
            void InterfaceAsync();
            #endif
            #endif
            // ***END***
            """;

        /// <summary>
        /// StackGenerator.cs  line#454
        /// </summary>
        public static string ModelCompiler_StackGenerator_DotNet_Templates_ServerApi_Method_cs =>
            """
            // ***START***
            #if (!OPCUA_EXCLUDE__NAME_)
            /// <summary>
            /// Invokes the _NAME_ service.
            /// </summary>
            #if (NET_STANDARD_OBSOLETE_SYNC && !OPCUA_EXCLUDE__NAME__ASYNC)
            [Obsolete("Sync methods are deprecated in this version. Use _NAME_Async instead.")]
            #endif
            void Stub()
            {
                // ResponseParameters

                ValidateRequest(requestHeader);

                // Insert implementation.

                return CreateResponse(requestHeader, StatusCodes.BadServiceUnsupported);
            }

            #if (!OPCUA_EXCLUDE__NAME__ASYNC)
            /// <summary>
            /// Invokes the _NAME_ service using async Task based request.
            /// </summary>
            void StubAsync()
            {
                ValidateRequest(requestHeader);

                // Insert implementation.
                await Task.CompletedTask;

                throw new ServiceResultException(StatusCodes.BadServiceUnsupported);
            }
            #endif
            #endif
            // ***END***
            }
            """;

        /// <summary>
        /// StackGenerator.cs  line#591
        /// </summary>
        public static string ModelCompiler_StackGenerator_DotNet_Templates_ClientApi_File_cs =>
            """
            // ***START***
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

            #if (NET_STANDARD_ASYNC)
            using System.Threading;
            using System.Threading.Tasks;
            #endif

            namespace _Prefix_
            {
                // _SERVICESETS_
            }
            // ***END***
            """;

        /// <summary>
        /// StackGenerator.cs  line#599
        /// </summary>
        public static string ModelCompiler_StackGenerator_DotNet_Templates_ClientApi_ServiceSet_cs =>
            """
            // ***START***
            #region I_ServiceSet_ClientMethods Interface
            /// <summary>
            /// An interface used by by clients to access a UA server.
            /// </summary>
            /// <exclude />
            [System.CodeDom.Compiler.GeneratedCodeAttribute("Opc.Ua.ModelCompiler", "1.0.0.0")]
            public interface I_ServiceSet_ClientMethods
            {
                #region Client Interface
                // _ClientInterface_
                #endregion
            }
            #endregion

            /// <summary>
            /// The client side interface for a UA server.
            /// </summary>
            /// <exclude />
            [System.CodeDom.Compiler.GeneratedCodeAttribute("Opc.Ua.ModelCompiler", "1.0.0.0")]
            [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverageAttribute()]
            public partial class _ServiceSet_Client : ClientBase, I_ServiceSet_ClientMethods
            {
                #region Constructors
                /// <summary>
                /// Intializes the object with a channel and a message context.
                /// </summary>
                public _ServiceSet_Client(ITransportChannel channel)
                :
                    base(channel)
                {
                }
                #endregion

                #region Public Properties
                /// <summary>
                /// The component  contains classes  object use to communicate with the server.
                /// </summary>
                public new I_ServiceSet_Channel InnerChannel
                {
                    get { return (I_ServiceSet_Channel)base.InnerChannel; }
                }
                #endregion

                #region Client API
                // _ClientApi_
                #endregion
            }
            // ***END***
            """;

        /// <summary>
        /// StackGenerator.cs  line#634
        /// </summary>
        public static string ModelCompiler_StackGenerator_DotNet_Templates_ClientApi_Interface_cs =>
            """
            // ***START***
            #region _NAME_ Methods
            #if (!OPCUA_EXCLUDE__NAME_)
            #if (!NET_STANDARD_NO_SYNC && !NET_STANDARD_NO_APM)
            /// <summary>
            /// Invokes the _NAME_ service.
            /// </summary>
            #if (NET_STANDARD_OBSOLETE_SYNC && NET_STANDARD_ASYNC)
            [Obsolete("Sync methods are deprecated in this version. Use _NAME_Async instead.")]
            #endif
            void SyncCall();
            #endif

            #if (!NET_STANDARD_NO_APM)
            /// <summary>
            /// Begins an asynchronous invocation of the _NAME_ service.
            /// </summary>
            #if (NET_STANDARD_OBSOLETE_APM && NET_STANDARD_ASYNC)
            [Obsolete("Begin/End methods are deprecated in this version. Use _NAME_Async instead.")]
            #endif
            void BeginAsyncCall();

            /// <summary>
            /// Finishes an asynchronous invocation of the _NAME_ service.
            /// </summary>
            #if (NET_STANDARD_OBSOLETE_APM && NET_STANDARD_ASYNC)
            [Obsolete("Begin/End methods are deprecated in this version. Use _NAME_Async instead.")]
            #endif
            void EndAsyncCall();
            #endif

            #if (NET_STANDARD_ASYNC)
            /// <summary>
            /// Invokes the _NAME_ service using async Task based request.
            /// </summary>
            void AsyncCall();
            #endif
            #endif
            #endregion
            // ***END***
            """;

        /// <summary>
        /// StackGenerator.cs  line#641
        /// </summary>
        public static string ModelCompiler_StackGenerator_DotNet_Templates_ClientApi_Method_cs =>
            """
            // ***START***
            #region _NAME_ Methods
            #if (!OPCUA_EXCLUDE__NAME_)
            #if (!NET_STANDARD)
            /// <summary>
            /// Invokes the _NAME_ service.
            /// </summary>
            void SyncCall()
            {
                _NAME_Request request = new _NAME_Request();
                _NAME_Response response = null;

                // RequestParameters

                UpdateRequestHeader(request, requestHeader == null, "_NAME_");

                try
                {
                    if (UseTransportChannel)
                    {
                        IServiceResponse genericResponse = TransportChannel.SendRequest(request);

                        if (genericResponse == null)
                        {
                            throw new ServiceResultException(StatusCodes.BadUnknownResponse);
                        }

                        ValidateResponse(genericResponse.ResponseHeader);
                        response = (_NAME_Response)genericResponse;
                    }
                    else
                    {
                        _NAME_ResponseMessage responseMessage = InnerChannel._NAME_(new _NAME_Message(request));

                        if (responseMessage == null || responseMessage._NAME_Response == null)
                        {
                            throw new ServiceResultException(StatusCodes.BadUnknownResponse);
                        }

                        response = responseMessage._NAME_Response;
                        ValidateResponse(response.ResponseHeader);
                    }

                    // ResponseParameters
                }
                finally
                {
                    RequestCompleted(request, response, "_NAME_");
                }

                return response.ResponseHeader;
            }

            /// <summary>
            /// Begins an asynchronous invocation of the _NAME_ service.
            /// </summary>
            void BeginAsyncCall()
            {
                _NAME_Request request = new _NAME_Request();

                // RequestParameters

                UpdateRequestHeader(request, requestHeader == null, "_NAME_");

                if (UseTransportChannel)
                {
                    return TransportChannel.BeginSendRequest(request, callback, asyncState);
                }

                return InnerChannel.Begin_NAME_(new _NAME_Message(request), callback, asyncState);
            }

            /// <summary>
            /// Finishes an asynchronous invocation of the _NAME_ service.
            /// </summary>
            void EndAsyncCall()
            {
                _NAME_Response response = null;

                try
                {
                    if (UseTransportChannel)
                    {
                        IServiceResponse genericResponse = TransportChannel.EndSendRequest(result);

                        if (genericResponse == null)
                        {
                            throw new ServiceResultException(StatusCodes.BadUnknownResponse);
                        }

                        ValidateResponse(genericResponse.ResponseHeader);
                        response = (_NAME_Response)genericResponse;
                    }
                    else
                    {
                        _NAME_ResponseMessage responseMessage = InnerChannel.End_NAME_(result);

                        if (responseMessage == null || responseMessage._NAME_Response == null)
                        {
                            throw new ServiceResultException(StatusCodes.BadUnknownResponse);
                        }

                        response = responseMessage._NAME_Response;
                        ValidateResponse(response.ResponseHeader);
                    }

                    // ResponseParameters
                }
                finally
                {
                    RequestCompleted(null, response, "_NAME_");
                }

                return response.ResponseHeader;
            }
            #else  // NET_STANDARD
            #if (!NET_STANDARD_NO_SYNC && !NET_STANDARD_NO_APM)
            /// <summary>
            /// Invokes the _NAME_ service.
            /// </summary>
            #if (NET_STANDARD_OBSOLETE_SYNC && NET_STANDARD_ASYNC)
            [Obsolete("Sync methods are deprecated in this version. Use _NAME_Async instead.")]
            #endif
            void SyncCall()
            {
                _NAME_Request request = new _NAME_Request();
                _NAME_Response response = null;

                // RequestParameters

                UpdateRequestHeader(request, requestHeader == null, "_NAME_");

                try
                {
                    IServiceResponse genericResponse = TransportChannel.SendRequest(request);

                    if (genericResponse == null)
                    {
                        throw new ServiceResultException(StatusCodes.BadUnknownResponse);
                    }

                    ValidateResponse(genericResponse.ResponseHeader);
                    response = (_NAME_Response)genericResponse;

                    // ResponseParameters
                }
                finally
                {
                    RequestCompleted(request, response, "_NAME_");
                }

                return response.ResponseHeader;
            }
            #endif

            #if (!NET_STANDARD_NO_APM)
            /// <summary>
            /// Begins an asynchronous invocation of the _NAME_ service.
            /// </summary>
            #if (NET_STANDARD_OBSOLETE_APM && NET_STANDARD_ASYNC)
            [Obsolete("Begin/End methods are deprecated in this version. Use _NAME_Async instead.")]
            #endif
            void BeginAsyncCall()
            {
                _NAME_Request request = new _NAME_Request();

                // RequestParameters

                UpdateRequestHeader(request, requestHeader == null, "_NAME_");

                return TransportChannel.BeginSendRequest(request, callback, asyncState);
            }

            /// <summary>
            /// Finishes an asynchronous invocation of the _NAME_ service.
            /// </summary>
            #if (NET_STANDARD_OBSOLETE_APM && NET_STANDARD_ASYNC)
            [Obsolete("Begin/End methods are deprecated in this version. Use _NAME_Async instead.")]
            #endif
            void EndAsyncCall()
            {
                _NAME_Response response = null;

                try
                {
                    IServiceResponse genericResponse = TransportChannel.EndSendRequest(result);

                    if (genericResponse == null)
                    {
                        throw new ServiceResultException(StatusCodes.BadUnknownResponse);
                    }

                    ValidateResponse(genericResponse.ResponseHeader);
                    response = (_NAME_Response)genericResponse;

                    // ResponseParameters
                }
                finally
                {
                    RequestCompleted(null, response, "_NAME_");
                }

                return response.ResponseHeader;
            }
            #endif
            #endif

            #if (NET_STANDARD_ASYNC)
            /// <summary>
            /// Invokes the _NAME_ service using async Task based request.
            /// </summary>
            void AsyncCall()
            {
                _NAME_Request request = new _NAME_Request();
                _NAME_Response response = null;

                // RequestParameters

                UpdateRequestHeader(request, requestHeader == null, "_NAME_");

                try
                {
                    IServiceResponse genericResponse = await TransportChannel.SendRequestAsync(request, ct).ConfigureAwait(false);

                    if (genericResponse == null)
                    {
                        throw new ServiceResultException(StatusCodes.BadUnknownResponse);
                    }

                    ValidateResponse(genericResponse.ResponseHeader);
                    response = (_NAME_Response)genericResponse;
                }
                finally
                {
                    RequestCompleted(request, response, "_NAME_");
                }

                return response;
            }
            #endif
            #endif
            #endregion
            // ***END***
            """;

        /// <summary>
        /// StackGenerator.cs  line#1043
        /// </summary>
        public static string ModelCompiler_StackGenerator_DotNet_Templates_Interfaces_File_cs =>
            """
            // ***START***
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

            #if (!NET_STANDARD)
            using System.Collections.Generic;
            using System.Xml;
            using System.ServiceModel;
            using System.Runtime.Serialization;
            #endif

            #if (NET_STANDARD_ASYNC)
            using System.Threading.Tasks;
            using System.Threading;
            #endif

            namespace _Prefix_
            {
                // _SERVICESETS_
            }
            // ***END***
            """;

        /// <summary>
        /// StackGenerator.cs  line#1050
        /// </summary>
        public static string ModelCompiler_StackGenerator_DotNet_Templates_Interfaces_ServiceSet_cs =>
            """
            using System;
            using System.Collections.Generic;
            using System.Xml;
            using System.ServiceModel;
            using System.Runtime.Serialization;

            namespace _Prefix_
            {
            // ***START***
            #region I_ServiceSet_Endpoint Interface
            #if OPCUA_USE_SYNCHRONOUS_ENDPOINTS
            /// <summary>
            /// The service contract which must be implemented by all UA servers.
            /// </summary>
            /// <exclude />
            [System.CodeDom.Compiler.GeneratedCodeAttribute("Opc.Ua.ModelCompiler", "1.0.0.0")]
            [ServiceContract(Namespace = Namespaces._ServicesNamespace_)]
            public interface I_ServiceSet_Endpoint : IEndpointBase
            {
                // _OPERATIONLIST_
            }
            #else
            /// <summary>
            /// The asynchronous service contract which must be implemented by UA servers.
            /// </summary>
            /// <exclude />
            [System.CodeDom.Compiler.GeneratedCodeAttribute("Opc.Ua.ModelCompiler", "1.0.0.0")]
            #if (!NET_STANDARD)
            [ServiceContract(Namespace = Namespaces._ServicesNamespace_)]
            #endif
            public interface I_ServiceSet_Endpoint : IEndpointBase
            {
                // _ASYNCENDPOINTOPERATIONLIST_
            }
            #endif
            #endregion

            #region I_ServiceSet_Channel Interface
            /// <summary>
            /// An interface used by by clients to access a UA server.
            /// </summary>
            /// <exclude />
            [System.CodeDom.Compiler.GeneratedCodeAttribute("Opc.Ua.ModelCompiler", "1.0.0.0")]
            #if (!NET_STANDARD)
            [ServiceContract(Namespace = Namespaces._ServicesNamespace_)]
            #endif
            public interface I_ServiceSet_Channel : IChannelBase
            {
                // _ASYNCOPERATIONLIST_
            }
            #endregion
            // ***END***
            }


            """;

        /// <summary>
        /// StackGenerator.cs  line#1086
        /// </summary>
        public static string ModelCompiler_StackGenerator_DotNet_Templates_Interfaces_Operation_cs =>
            """
            // ***START***
            #if (!OPCUA_EXCLUDE__NAME_)
            /// <summary>
            /// The operation contract for the _NAME_ service.
            /// </summary>
            [OperationContract(Action = Namespaces._ServicesNamespace_ + "/_NAME_", ReplyAction = Namespaces._ServicesNamespace_ + "/_NAME_Response")]
            [FaultContract(typeof(ServiceFault), Action = Namespaces._ServicesNamespace_ + "/_NAME_Fault", Name="ServiceFault", Namespace=Namespaces._TypesNamespace_)]
            _NAME_ResponseMessage _NAME_(_NAME_Message request);
            #endif
            // ***END***
            """;

        /// <summary>
        /// StackGenerator.cs  line#1093
        /// </summary>
        public static string ModelCompiler_StackGenerator_DotNet_Templates_Interfaces_OperationAsyncEndpoint_cs =>
            """
            // ***START***
            #if (!OPCUA_EXCLUDE__NAME_)
            #if (!NET_STANDARD_NO_APM)
            /// <summary>
            /// The operation contract for the _NAME_ service.
            /// </summary>
            #if (!NET_STANDARD)
            [OperationContractAttribute(AsyncPattern=true, Action=Namespaces._ServicesNamespace_ + "/_NAME_", ReplyAction = Namespaces._ServicesNamespace_ + "/_NAME_Response")]
            [FaultContract(typeof(ServiceFault), Action = Namespaces._ServicesNamespace_ + "/_NAME_Fault", Name = "ServiceFault", Namespace = Namespaces._TypesNamespace_)]
            #endif
            #if (NET_STANDARD_OBSOLETE_APM && NET_STANDARD_ASYNC)
            [Obsolete("Begin/End methods are deprecated in this version. Use _NAME_Async instead.")]
            #endif
            IAsyncResult Begin_NAME_(_NAME_Message request, AsyncCallback callback, object asyncState);

            /// <summary>
            /// The method used to retrieve the results of a _NAME_ service request.
            /// </summary>
            #if (NET_STANDARD_OBSOLETE_APM && NET_STANDARD_ASYNC)
            [Obsolete("Begin/End methods are deprecated in this version. Use _NAME_Async instead.")]
            #endif
            _NAME_ResponseMessage End_NAME_(IAsyncResult result);
            #endif

            #if (NET_STANDARD_ASYNC && !OPCUA_EXCLUDE__NAME__ASYNC)
            /// <summary>
            /// The async operation contract for the _NAME_ service.
            /// </summary>
            Task<IServiceResponse> _NAME_Async(IServiceRequest incoming, SecureChannelContext secureChannelContext, CancellationToken cancellationToken = default);
            #endif
            #endif
            // ***END***
            """;

        /// <summary>
        /// StackGenerator.cs  line#1100
        /// </summary>
        public static string ModelCompiler_StackGenerator_DotNet_Templates_Interfaces_OperationAsync_cs =>
            """
            // ***START***
            #if (!OPCUA_EXCLUDE__NAME_)
            /// <summary>
            /// The operation contract for the _NAME_ service.
            /// </summary>
            #if (!NET_STANDARD_NO_SYNC && !NET_STANDARD_NO_APM)
            #if (!NET_STANDARD)
            [OperationContract(Action = Namespaces._ServicesNamespace_ + "/_NAME_", ReplyAction = Namespaces._ServicesNamespace_ + "/_NAME_Response")]
            [FaultContract(typeof(ServiceFault), Action = Namespaces._ServicesNamespace_ + "/_NAME_Fault", Name="ServiceFault", Namespace=Namespaces._TypesNamespace_)]
            #endif
            #if (NET_STANDARD_OBSOLETE_SYNC && NET_STANDARD_ASYNC)
            [Obsolete("Sync methods are deprecated in this version. Use _NAME_Async instead.")]
            #endif
            _NAME_ResponseMessage _NAME_(_NAME_Message request);
            #endif

            /// <summary>
            /// The operation contract for the _NAME_ service.
            /// </summary>
            #if (!NET_STANDARD_NO_APM)
            #if (!NET_STANDARD)
            [OperationContractAttribute(AsyncPattern=true, Action=Namespaces._ServicesNamespace_ + "/_NAME_", ReplyAction = Namespaces._ServicesNamespace_ + "/_NAME_Response")]
            #endif
            #if (NET_STANDARD_OBSOLETE_APM && NET_STANDARD_ASYNC)
            [Obsolete("Begin/End methods are deprecated in this version. Use _NAME_Async instead.")]
            #endif
            IAsyncResult Begin_NAME_(_NAME_Message request, AsyncCallback callback, object asyncState);

            /// <summary>
            /// The method used to retrieve the results of a _NAME_ service request.
            /// </summary>
            #if (NET_STANDARD_OBSOLETE_APM && NET_STANDARD_ASYNC)
            [Obsolete("Begin/End methods are deprecated in this version. Use _NAME_Async instead.")]
            #endif
            _NAME_ResponseMessage End_NAME_(IAsyncResult result);
            #endif

            #if (NET_STANDARD_ASYNC)
            /// <summary>
            /// The async operation contract for the _NAME_ service.
            /// </summary>
            Task<_NAME_ResponseMessage> _NAME_Async(_NAME_Message request);
            #endif
            #endif
            // ***END***
            """;

        /// <summary>
        /// StackGenerator.cs  line#1124
        /// </summary>
        public static string ModelCompiler_StackGenerator_DotNet_Templates_Channels_File_cs =>
            """
            // ***START***
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

            #if (!NET_STANDARD)
            using System.Collections.Generic;
            using System.Xml;
            using System.ServiceModel;
            using System.ServiceModel.Channels;
            using System.Runtime.Serialization;
            #endif

            #if (NET_STANDARD_ASYNC)
            using System.Threading.Tasks;
            #endif

            namespace _Prefix_
            {
                // _SERVICESETS_
            }
            // ***END***
            """;

        /// <summary>
        /// StackGenerator.cs  line#1133
        /// </summary>
        public static string ModelCompiler_StackGenerator_DotNet_Templates_Channels_ServiceSet_cs =>
            """
            // ***START***
            #region _ServiceSet_Channel Class
            /// <summary>
            /// A channel object used by clients to access a UA service.
            /// </summary>
            /// <exclude />
            [System.CodeDom.Compiler.GeneratedCodeAttribute("Opc.Ua.ModelCompiler", "1.0.0.0")]
            [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverageAttribute()]
            #if (!NET_STANDARD)
            public partial class _ServiceSet_Channel : WcfChannelBase<I_ServiceSet_Channel>, I_ServiceSet_Channel
            #else
            public partial class _ServiceSet_Channel : UaChannelBase<I_ServiceSet_Channel>, I_ServiceSet_Channel
            #endif
            {
                /// <summary>
                /// Initializes the object with the endpoint address.
                /// </summary>
                internal _ServiceSet_Channel()
                {
                }

                // _XmlChannelAsyncMethodList_
            }
            #endregion
            // ***END***
            """;

        /// <summary>
        /// StackGenerator.cs  line#1168
        /// </summary>
        public static string ModelCompiler_StackGenerator_DotNet_Templates_Channels_XmlMethod_cs =>
            """



            """;

        /// <summary>
        /// StackGenerator.cs  line#1175
        /// </summary>
        public static string ModelCompiler_StackGenerator_DotNet_Templates_Channels_BinaryMethod_cs =>
            """



            """;

        /// <summary>
        /// StackGenerator.cs  line#1182
        /// </summary>
        public static string ModelCompiler_StackGenerator_DotNet_Templates_Channels_XmlMethodAsync_cs =>
            """
            // ***START***
            #if (!OPCUA_EXCLUDE__NAME_)
            #if (!NET_STANDARD)
            /// <summary>
            /// The client side implementation of the _NAME_ service contract.
            /// </summary>
            public _NAME_ResponseMessage _NAME_(_NAME_Message request)
            {
                try
                {
                    IAsyncResult result = null;

                    lock (this.Channel)
                    {
                        result = this.Channel.Begin_NAME_(request, null, null);
                    }

                    return this.Channel.End_NAME_(result);
                }
                catch (FaultException<ServiceFault> e)
                {
                    throw HandleSoapFault(e);
                }
            }

            /// <summary>
            /// The client side implementation of the Begin_NAME_ service contract.
            /// </summary>
            public IAsyncResult Begin_NAME_(_NAME_Message request, AsyncCallback callback, object asyncState)
            {
                WcfChannelAsyncResult asyncResult = new WcfChannelAsyncResult(Channel, callback, asyncState);

                lock (asyncResult.Lock)
                {
                    asyncResult.InnerResult = asyncResult.Channel.Begin_NAME_(request, asyncResult.OnOperationCompleted, null);
                }

                return asyncResult;
            }

            /// <summary>
            /// The client side implementation of the End_NAME_ service contract.
            /// </summary>
            public _NAME_ResponseMessage End_NAME_(IAsyncResult result)
            {
                try
                {
                    WcfChannelAsyncResult asyncResult = WcfChannelAsyncResult.WaitForComplete(result);
                    return asyncResult.Channel.End_NAME_(asyncResult.InnerResult);
                }
                catch (FaultException<ServiceFault> e)
                {
                    throw HandleSoapFault(e);
                }
            }
            #else  // NET_STANDARD
            #if (!NET_STANDARD_NO_SYNC && !NET_STANDARD_NO_APM)
            /// <summary>
            /// The client side implementation of the _NAME_ service contract.
            /// </summary>
            #if (NET_STANDARD_OBSOLETE_SYNC && NET_STANDARD_ASYNC)
            [Obsolete("Sync methods are deprecated in this version. Use _NAME_Async instead.")]
            #endif
            public _NAME_ResponseMessage _NAME_(_NAME_Message request)
            {
                IAsyncResult result = null;

                lock (this.Channel)
                {
                    result = this.Channel.Begin_NAME_(request, null, null);
                }

                return this.Channel.End_NAME_(result);
            }
            #endif
            #if (!NET_STANDARD_NO_APM)
            /// <summary>
            /// The client side implementation of the Begin_NAME_ service contract.
            /// </summary>
            #if (NET_STANDARD_OBSOLETE_APM && NET_STANDARD_ASYNC)
            [Obsolete("Begin/End methods are deprecated in this version. Use _NAME_Async instead.")]
            #endif
            public IAsyncResult Begin_NAME_(_NAME_Message request, AsyncCallback callback, object asyncState)
            {
                UaChannelAsyncResult asyncResult = new UaChannelAsyncResult(Channel, callback, asyncState);

                lock (asyncResult.Lock)
                {
                    asyncResult.InnerResult = asyncResult.Channel.Begin_NAME_(request, asyncResult.OnOperationCompleted, null);
                }

                return asyncResult;
            }

            /// <summary>
            /// The client side implementation of the End_NAME_ service contract.
            /// </summary>
            #if (NET_STANDARD_OBSOLETE_APM && NET_STANDARD_ASYNC)
            [Obsolete("Begin/End methods are deprecated in this version. Use _NAME_Async instead.")]
            #endif
            public _NAME_ResponseMessage End_NAME_(IAsyncResult result)
            {
                UaChannelAsyncResult asyncResult = UaChannelAsyncResult.WaitForComplete(result);
                return asyncResult.Channel.End_NAME_(asyncResult.InnerResult);
            }
            #endif
            #endif

            #if (NET_STANDARD_ASYNC)
            /// <summary>
            /// The async client side implementation of the _NAME_ service contract.
            /// </summary>
            public Task<_NAME_ResponseMessage> _NAME_Async(_NAME_Message request)
            {
                return this.Channel._NAME_Async(request);
            }
            #endif
            #endif
            // ***END***
            """;

        /// <summary>
        /// StackGenerator.cs  line#1189
        /// </summary>
        public static string ModelCompiler_StackGenerator_DotNet_Templates_Channels_BinaryMethodAsync_cs =>
            """
            // ***START***
            #if (!OPCUA_EXCLUDE__NAME_)
            /// <summary>
            /// Invokes the _NAME_ service.
            /// </summary>
            public _NAME_Response _NAME_(_NAME_Request request)
            {
                BinaryMessageContext context = CreateContext();
                byte[] buffer = BinaryEncoder.EncodeMessage(request, context);

                InvokeServiceResponseMessage response = null;

                try
                {
                    response = Channel.InvokeService(new InvokeServiceMessage(buffer));
                }
                catch (FaultException<ServiceFault> e)
                {
                    throw HandleSoapFault(e);
                }

                CheckForFault(response);

                return (_NAME_Response)BinaryDecoder.DecodeMessage(response.InvokeServiceResponse, typeof(_NAME_Response), context);
            }

            /// <summary>
            /// The client side implementation of the _NAME_ service contract.
            /// </summary>
            _NAME_ResponseMessage I_ServiceSet_Endpoint._NAME_(_NAME_Message request)
            {
                _NAME_Response response = _NAME_(request._NAME_Request);
                return new _NAME_ResponseMessage(response);
            }

            /// <summary>
            /// Invokes the _NAME_ service.
            /// </summary>
            public IAsyncResult Begin_NAME_(_NAME_Request request, AsyncCallback callback, object asyncState)
            {
                byte[] buffer = BinaryEncoder.EncodeMessage(request, CreateContext());
                return Channel.BeginInvokeService(new InvokeServiceMessage(buffer), callback, asyncState);
            }

            /// <summary>
            /// The client side implementation of the Begin_NAME_ service contract.
            /// </summary>
            IAsyncResult I_ServiceSet_Channel.Begin_NAME_(_NAME_Message request, AsyncCallback callback, object asyncState)
            {
                return Begin_NAME_(request._NAME_Request, callback, asyncState);
            }

            /// <summary>
            /// The client side implementation of the End_NAME_ service contract.
            /// </summary>
            _NAME_ResponseMessage I_ServiceSet_Channel.End_NAME_(IAsyncResult result)
            {
                _NAME_Response response = End_NAME_(result);
                return new _NAME_ResponseMessage(response);
            }

            /// <summary>
            /// Completes the _NAME_ service.
            /// </summary>
            public _NAME_Response End_NAME_(IAsyncResult result)
            {
                InvokeServiceResponseMessage response = null;

                try
                {
                    response = Channel.EndInvokeService(result);
                }
                catch (FaultException<ServiceFault> e)
                {
                    throw HandleSoapFault(e);
                }

                CheckForFault(response);

                return (_NAME_Response)BinaryDecoder.DecodeMessage(response.InvokeServiceResponse, typeof(_NAME_Response), CreateContext());
            }
            #endif
            // ***END***
            """;

        /// <summary>
        /// StackGenerator.cs  line#1247
        /// </summary>
        public static string ModelCompiler_StackGenerator_DotNet_Templates_Classes_File_cs =>
            """
            // ***START***
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
            #if (!NET_STANDARD)
            using System.Xml;
            using System.ServiceModel;
            using System.Runtime.Serialization;
            #endif

            namespace _Prefix_
            {
                // _TypeList_
            }
            // ***END***
            """;

        /// <summary>
        /// StackGenerator.cs  line#1286
        /// </summary>
        public static string ModelCompiler_StackGenerator_DotNet_Templates_Classes_Enumeration_cs =>
            """
            // ***START***
            #region _NAME_ Enumeration
            #if (!OPCUA_EXCLUDE__NAME_)
            /// <summary>
            /// The _NAME_ enumeration.
            /// </summary>
            /// <exclude />
            // _XMLTYPE_
            [System.CodeDom.Compiler.GeneratedCodeAttribute("Opc.Ua.ModelCompiler", "1.0.0.0")]
            public enum _NAME_
            {
                // _VALUELIST_
            }
            // _ENUMCOLLECTIONCLASS_
            #endif
            #endregion
            // ***END***
            """;

        /// <summary>
        /// StackGenerator.cs  line#1291
        /// </summary>
        public static string ModelCompiler_StackGenerator_DotNet_Templates_Classes_Service_cs =>
            """
            // ***START***
            #region _NAME_ Service Messages
            #if (!OPCUA_EXCLUDE__NAME_)
            public partial class _NAME_Request : IServiceRequest
            {
            }

            public partial class _NAME_Response : IServiceResponse
            {
            }

            /// <summary>
            /// The message contract for the _NAME_ service.
            /// </summary>
            /// <exclude />
            [System.CodeDom.Compiler.GeneratedCodeAttribute("Opc.Ua.ModelCompiler", "1.0.0.0")]
            [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverageAttribute()]
            #if (!NET_STANDARD)
            [MessageContract(IsWrapped=false)]
            #endif
            public class _NAME_Message : IServiceMessage
            {
                /// <summary>
                /// The body of the message.
                /// </summary>
                #if (!NET_STANDARD)
                [MessageBodyMember(Namespace = Namespaces._TypesNamespace_, Order = 0)]
                #endif
                public _NAME_Request _NAME_Request;

                /// <summary>
                /// Initializes an empty message.
                /// </summary>
                public _NAME_Message()
                {
                }

                /// <summary>
                /// Initializes the message with the body.
                /// </summary>
                public _NAME_Message(_NAME_Request _NAME_Request)
                {
                    this._NAME_Request = _NAME_Request;
                }

                #region IServiceMessage Members
                /// <summary cref="IServiceMessage.GetRequest" />
                public IServiceRequest GetRequest()
                {
                    return _NAME_Request;
                }

                /// <summary cref="IServiceMessage.CreateResponse" />
                public object CreateResponse(IServiceResponse response)
                {
                    _NAME_Response body = response as _NAME_Response;

                    if (body == null)
                    {
                        body = new _NAME_Response();
                        body.ResponseHeader = ((ServiceFault)response).ResponseHeader;
                    }

                    return new _NAME_ResponseMessage(body);
                }
                #endregion
            }

            /// <summary>
            /// The message contract for the _NAME_ service response.
            /// </summary>
            /// <exclude />
            [System.CodeDom.Compiler.GeneratedCodeAttribute("Opc.Ua.ModelCompiler", "1.0.0.0")]
            [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverageAttribute()]
            #if (!NET_STANDARD)
            [MessageContract(IsWrapped=false)]
            #endif
            public class _NAME_ResponseMessage
            {
                /// <summary>
                /// The body of the message.
                /// </summary>
                #if (!NET_STANDARD)
                [MessageBodyMember(Namespace=Namespaces._TypesNamespace_, Order=0)]
                #endif
                public _NAME_Response _NAME_Response;

                /// <summary>
                /// Initializes an empty message.
                /// </summary>
                public _NAME_ResponseMessage()
                {
                }

                /// <summary>
                /// Initializes the message with the body.
                /// </summary>
                public _NAME_ResponseMessage(_NAME_Response _NAME_Response)
                {
                    this._NAME_Response = _NAME_Response;
                }

                /// <summary>
                /// Initializes the message with a service fault.
                /// </summary>
                public _NAME_ResponseMessage(ServiceFault ServiceFault)
                {
                    this._NAME_Response = new _NAME_Response();

                    if (ServiceFault != null)
                    {
                        this._NAME_Response.ResponseHeader = ServiceFault.ResponseHeader;
                    }
                }
            }
            #endif
            #endregion
            // ***END***
            """;

        /// <summary>
        /// StackGenerator.cs  line#1317
        /// </summary>
        public static string ModelCompiler_StackGenerator_DotNet_Templates_Classes_ClassCollection_cs =>
            """
            // ***START***

            #region _NAME_Collection Class
            /// <summary>
            /// A collection of _NAME_ objects.
            /// </summary>
            /// <exclude />
            // _XMLARRAYTYPE_
            [System.CodeDom.Compiler.GeneratedCodeAttribute("Opc.Ua.ModelCompiler", "1.0.0.0")]
            [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverageAttribute()]
            public partial class _NAME_Collection : List<_NAME_>, ICloneable
            {
                #region Constructors
                /// <summary>
                /// Initializes the collection with default values.
                /// </summary>
                public _NAME_Collection() {}

                /// <summary>
                /// Initializes the collection with an initial capacity.
                /// </summary>
                public _NAME_Collection(int capacity) : base(capacity) {}

                /// <summary>
                /// Initializes the collection with another collection.
                /// </summary>
                public _NAME_Collection(IEnumerable<_NAME_> collection) : base(collection) {}
                #endregion

                #region Static Operators
                /// <summary>
                /// Converts an array to a collection.
                /// </summary>
                public static implicit operator _NAME_Collection(_NAME_[] values)
                {
                    if (values != null)
                    {
                        return new _NAME_Collection(values);
                    }

                    return new _NAME_Collection();
                }

                /// <summary>
                /// Converts an array to a collection.
                /// </summary>
                public static _NAME_Collection To_NAME_Collection(_NAME_[] values)
                {
                    if (values != null)
                    {
                        return new _NAME_Collection(values);
                    }

                    return new _NAME_Collection();
                }

                /// <summary>
                /// Converts a collection to an array.
                /// </summary>
                public static explicit operator _NAME_[](_NAME_Collection values)
                {
                    if (values != null)
                    {
                        return values.ToArray();
                    }

                    return null;
                }

                /// <summary>
                /// Converts a collection to an array.
                /// </summary>
                public static _NAME_[] From_NAME_Collection(_NAME_Collection values)
                {
                    if (values != null)
                    {
                        return values.ToArray();
                    }

                    return null;
                }
                #endregion

                #region ICloneable Methods
                /// <summary>
                /// Creates a deep copy of the collection.
                /// </summary>
                public object Clone()
                {
                    _NAME_Collection clone = new _NAME_Collection(this.Count);

                    foreach (_NAME_ element in this)
                    {
                        if (element != null)
                        {
                            clone.Add((_NAME_)element.Clone());
                        }
                        else
                        {
                            clone.Add(null);
                        }
                    }

                    return clone;
                }
                #endregion
            }
            #endregion
            // ***END***
            """;

        /// <summary>
        /// StackGenerator.cs  line#1324
        /// </summary>
        public static string ModelCompiler_StackGenerator_DotNet_Templates_Classes_EnumerationCollection_cs =>
            """
            // ***START***

            #region _NAME_Collection Class
            /// <summary>
            /// A collection of _NAME_ objects.
            /// </summary>
            /// <exclude />
            // _XMLARRAYTYPE_
            public partial class _NAME_Collection : List<_NAME_>, ICloneable
            {
                #region Constructors
                /// <summary>
                /// Initializes the collection with default values.
                /// </summary>
                public _NAME_Collection() {}

                /// <summary>
                /// Initializes the collection with an initial capacity.
                /// </summary>
                public _NAME_Collection(int capacity) : base(capacity) {}

                /// <summary>
                /// Initializes the collection with another collection.
                /// </summary>
                public _NAME_Collection(IEnumerable<_NAME_> collection) : base(collection) {}
                #endregion

                #region Static Operators
                /// <summary>
                /// Converts an array to a collection.
                /// </summary>
                public static implicit operator _NAME_Collection(_NAME_[] values)
                {
                    if (values != null)
                    {
                        return new _NAME_Collection(values);
                    }

                    return new _NAME_Collection();
                }

                /// <summary>
                /// Converts an array to a collection.
                /// </summary>
                public static _NAME_Collection To_NAME_Collection(_NAME_[] values)
                {
                    if (values != null)
                    {
                        return new _NAME_Collection(values);
                    }

                    return new _NAME_Collection();
                }

                /// <summary>
                /// Converts a collection to an array.
                /// </summary>
                public static explicit operator _NAME_[](_NAME_Collection values)
                {
                    if (values != null)
                    {
                        return values.ToArray();
                    }

                    return null;
                }

                /// <summary>
                /// Converts a collection to an array.
                /// </summary>
                public static _NAME_[] From_NAME_Collection(_NAME_Collection values)
                {
                    if (values != null)
                    {
                        return values.ToArray();
                    }

                    return null;
                }
                #endregion

                #region ICloneable Methods
                /// <summary>
                /// Creates a deep copy of the collection.
                /// </summary>
                public object Clone()
                {
                    return new _NAME_Collection(this);
                }
                #endregion
            }
            #endregion
            // ***END***
            """;

        /// <summary>
        /// StackGenerator.cs  line#1376
        /// StackGenerator.cs  line#1529
        /// </summary>
        public static string ModelCompiler_StackGenerator_DotNet_Templates_Classes_Property_cs =>
            """
            // ***START***
            /// <summary>
            /// The _EXTERNALNAME_ property.
            /// </summary>
            // _XMLTYPE_
            public _TYPE_ _EXTERNALNAME_
            {
                get { return m__INTERNALNAME_;  }
                set { m__INTERNALNAME_ = value; }
            }
            // ***END***
            """;

        /// <summary>
        /// StackGenerator.cs  line#1445
        /// </summary>
        public static string ModelCompiler_StackGenerator_DotNet_Templates_Classes_EnumerationValue_cs =>
            """
            // ***START***
            /// <summary>
            /// _NAME_ = _VALUE_
            /// </summary>
            // _XMLTYPE_
            _NAME_ = _VALUE_
            // ***END***
            """;

        /// <summary>
        /// StackGenerator.cs  line#1281
        /// StackGenerator.cs  line#1464
        /// StackGenerator.cs  line#1480
        /// </summary>
        public static string ModelCompiler_StackGenerator_DotNet_Templates_Classes_Class_cs =>
            """
            // ***START***
            #region _NAME_ Class
            #if (!OPCUA_EXCLUDE__NAME_)
            /// <summary>
            /// The _NAME_ class.
            /// </summary>
            /// <exclude />
            // _XMLTYPE_
            [System.CodeDom.Compiler.GeneratedCodeAttribute("Opc.Ua.ModelCompiler", "1.0.0.0")]
            [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverageAttribute()]
            public partial class _NAME_ : _BASETYPE_
            {
                #region Constructors
                /// <summary>
                /// The default constructor.
                /// </summary>
                public _NAME_()
                {
                    Initialize();
                }

                /// <summary>
                /// Called by the .NET framework during deserialization.
                /// </summary>
                [OnDeserializing]
                private void Initialize(StreamingContext context)
                {
                    Initialize();
                }

                /// <summary>
                /// Sets private members to default values.
                /// </summary>
                private void Initialize()
                {
                    // _DEFAULTLIST_
                }
                #endregion

                #region Public Properties
                // _PROPERTYLIST_
                #endregion

                #region IEncodeable Members
                /// <summary cref="IEncodeable.TypeId" />
                public override ExpandedNodeId TypeId => DataTypeIds._NAME_;

                /// <summary cref="IEncodeable.BinaryEncodingId" />
                public override ExpandedNodeId BinaryEncodingId => ObjectIds._NAME__Encoding_DefaultBinary;

                /// <summary cref="IEncodeable.XmlEncodingId" />
                public override ExpandedNodeId XmlEncodingId => ObjectIds._NAME__Encoding_DefaultXml;

                /// <summary cref="IJsonEncodeable.JsonEncodingId" />
                public override ExpandedNodeId JsonEncodingId => ObjectIds._NAME__Encoding_DefaultJson;

                /// <summary cref="IEncodeable.Encode(IEncoder)" />
                public override void Encode(IEncoder encoder)
                {
                    base.Encode(encoder);

                    encoder.PushNamespace(Namespaces._TypesNamespace_);
                    // _ENCODELIST_
                    encoder.PopNamespace();
                }

                /// <summary cref="IEncodeable.Decode(IDecoder)" />
                public override void Decode(IDecoder decoder)
                {
                    base.Decode(decoder);

                    decoder.PushNamespace(Namespaces._TypesNamespace_);
                    // _DECODELIST_
                    decoder.PopNamespace();
                }

                /// <summary cref="IEncodeable.IsEqual(IEncodeable)" />
                public override bool IsEqual(IEncodeable encodeable)
                {
                    if (Object.ReferenceEquals(this, encodeable))
                    {
                        return true;
                    }

                    _NAME_ value = encodeable as _NAME_;

                    if (value == null)
                    {
                        return false;
                    }

                    if (typeof(_NAME_).BaseType != typeof(object))
                    {
                        if (!base.IsEqual(encodeable))
                        {
                            return false;
                        }
                    }

                    // _ISEQUALLIST_

                    return true;
                }

                /// <summary cref="ICloneable.Clone" />
                public override object Clone()
                {
                    _NAME_ clone = (_NAME_)base.Clone();
                    // _CLONELIST_
                    return clone;
                }
                #endregion

                #region Private Fields
                // _MEMBERLIST_
                #endregion
            }
            // _COLLECTIONCLASS_
            #endif
            #endregion
            // ***END***
            """;

        /// <summary>
        /// StackGenerator.cs  line#1521
        /// StackGenerator.cs  line#1526
        /// </summary>
        public static string ModelCompiler_StackGenerator_DotNet_Templates_Classes_PropertyArray_cs =>
            """
            // ***START***
            /// <summary>
            /// The _EXTERNALNAME_ property.
            /// </summary>
            // _XMLTYPE_
            public _TYPE_ _EXTERNALNAME_
            {
                get { return m__INTERNALNAME_;  }

                set
                {
                    if (value != null)
                    {
                        m__INTERNALNAME_ = value;
                    }
                    else
                    {
                        m__INTERNALNAME_ = new _TYPE_();
                    }
                }
            }
            // ***END***
            """;

        /// <summary>
        /// XmlSchemaGenerator.cs  line#102
        /// </summary>
        public static string ModelCompiler_StackGenerator_DataTypes_Templates_XmlSchema_Endpoint_wsdl =>
            """
            <!--***START***-->
            <?xml version="1.0" encoding="utf-8"?>
            <wsdl:definitions
              name="UAEndpoints"
              targetNamespace="_EndpointsNamespace_"
              xmlns:tns="_EndpointsNamespace_"
              xmlns:s0="_ServicesNamespace_"
              xmlns:s1="http://localhost.org/UA/SampleServer"
              xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/"
              xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/"
              xmlns:soap12="http://schemas.xmlsoap.org/wsdl/soap12/"
              xmlns:wsa10="http://www.w3.org/2005/08/addressing"
            >
              <wsdl:import namespace="_ServicesNamespace_" location="_ServicesNamespace_" />
              <wsdl:types />

              <wsdl:binding name="UaSoapXmlBinding_ISessionEndpoint" type="s0:ISessionEndpoint">
                <soap12:binding transport="http://schemas.xmlsoap.org/soap/http"/>

                <wsdl:operation name="InvokeService">
                  <soap12:operation soapAction="_Namespace_/InvokeService" style="document"/>
                  <wsdl:input name="InvokeServiceMessage">
                    <soap12:body use="literal"/>
                  </wsdl:input>
                  <wsdl:output name="InvokeServiceResponseMessage">
                    <soap12:body use="literal"/>
                  </wsdl:output>
                  <wsdl:fault name="InvokeServiceFaultMessage">
                    <soap12:fault name="InvokeServiceFaultMessage" use="literal" />
                  </wsdl:fault>
                </wsdl:operation>

                <!-- Session Binding List -->

              </wsdl:binding>

              <wsdl:binding name="UaSoapXmlBinding_IDiscoveryEndpoint" type="s0:IDiscoveryEndpoint">
                <soap12:binding transport="http://schemas.xmlsoap.org/soap/http"/>

                <wsdl:operation name="InvokeService">
                  <soap12:operation soapAction="_Namespace_/InvokeService" style="document"/>
                  <wsdl:input name="InvokeServiceMessage">
                    <soap12:body use="literal"/>
                  </wsdl:input>
                  <wsdl:output name="InvokeServiceResponseMessage">
                    <soap12:body use="literal"/>
                  </wsdl:output>
                  <wsdl:fault name="InvokeServiceFaultMessage">
                    <soap12:fault name="InvokeServiceFaultMessage" use="literal" />
                  </wsdl:fault>
                </wsdl:operation>

                <!-- Discovery Binding List -->

              </wsdl:binding>

              <wsdl:binding name="UaSoapXmlBinding_IRegistrationEndpoint" type="s0:IRegistrationEndpoint">
                <soap12:binding transport="http://schemas.xmlsoap.org/soap/http"/>

                <wsdl:operation name="InvokeService">
                  <soap12:operation soapAction="_ServicesNamespace_/InvokeService" style="document"/>
                  <wsdl:input name="InvokeServiceMessage">
                    <soap12:body use="literal"/>
                  </wsdl:input>
                  <wsdl:output name="InvokeServiceResponseMessage">
                    <soap12:body use="literal"/>
                  </wsdl:output>
                  <wsdl:fault name="InvokeServiceFaultMessage">
                    <soap12:fault name="InvokeServiceFaultMessage" use="literal" />
                  </wsdl:fault>
                </wsdl:operation>

                <!-- Registration Binding List -->

              </wsdl:binding>

              <wsdl:service name="UAService">
                <wsdl:port name="UaSoapXmlBinding_ISessionEndpoint" binding="tns:UaSoapXmlBinding_ISessionEndpoint">
                  <soap12:address location="http://localhost/UAService"/>
                </wsdl:port>
                <wsdl:port name="UaSoapXmlBinding_IDiscoveryEndpoint" binding="tns:UaSoapXmlBinding_IDiscoveryEndpoint">
                  <soap12:address location="http://localhost/UAService/discovery"/>
                </wsdl:port>
              </wsdl:service>

              <wsdl:service name="UADiscoveryService">
                <wsdl:port name="UaSoapXmlBinding_IDiscoveryEndpoint" binding="tns:UaSoapXmlBinding_IDiscoveryEndpoint">
                  <soap12:address location="http://localhost:52601/UADiscovery"/>
                </wsdl:port>
                <wsdl:port name="UaSoapXmlBinding_IRegistrationEndpoint" binding="tns:UaSoapXmlBinding_IRegistrationEndpoint">
                  <soap12:address location="http://localhost:52601/UADiscovery/registration"/>
                </wsdl:port>
              </wsdl:service>

            </wsdl:definitions>
            <!--***END***-->
            """;

        /// <summary>
        /// XmlSchemaGenerator.cs  line#119
        /// XmlSchemaGenerator.cs  line#127
        /// XmlSchemaGenerator.cs  line#135
        /// </summary>
        public static string ModelCompiler_StackGenerator_DataTypes_Templates_XmlSchema_Binding_wsdl =>
            """
            <!--***START***-->
            <wsdl:operation name="_NAME_">
              <soap12:operation soapAction="_ServicesNamespace_/_NAME_" style="document"/>
              <wsdl:input name="_NAME_Message">
                <soap12:body use="literal"/>
              </wsdl:input>
              <wsdl:output name="_NAME_ResponseMessage">
                <soap12:body use="literal"/>
              </wsdl:output>
              <wsdl:fault name="_NAME_FaultMessage">
                <soap12:fault name="_NAME_FaultMessage" use="literal" />
              </wsdl:fault>
            </wsdl:operation>
            <!--***END***-->
            """;

        /// <summary>
        /// XmlSchemaGenerator.cs  line#163
        /// </summary>
        public static string ModelCompiler_StackGenerator_DataTypes_Templates_XmlSchema_Services_wsdl =>
            """
            <!--***START***-->
            <?xml version="1.0" encoding="utf-8"?>
            <wsdl:definitions
              targetNamespace="_ServicesNamespace_"
              xmlns:tns="_ServicesNamespace_"
              xmlns:s0="_TypesNamespace_"
              xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/"
              xmlns:wsaw="http://www.w3.org/2006/05/addressing/wsdl"
              xmlns:xsd="http://www.w3.org/2001/XMLSchema"
            >
              <wsdl:types>
                <xsd:schema targetNamespace="_Namespace_/Imports">
                  <xsd:import schemaLocation="_TypesNamespace_" namespace="_TypesNamespace_"/>
                </xsd:schema>
              </wsdl:types>

              <wsdl:message name="InvokeServiceMessage">
                <wsdl:part name="input" element="s0:InvokeServiceRequest"/>
              </wsdl:message>
              <wsdl:message name="InvokeServiceResponseMessage">
                <wsdl:part name="output" element="s0:InvokeServiceResponse"/>
              </wsdl:message>
              <wsdl:message name="InvokeServiceFaultMessage">
                <wsdl:part name="detail" element="s0:ServiceFault" />
              </wsdl:message>

              <!-- Message List -->

              <wsdl:portType name="ISessionEndpoint">

                <wsdl:operation name="InvokeService">
                  <wsdl:input wsaw:Action="_ServicesNamespace_/InvokeService" name="InvokeServiceMessage" message="tns:InvokeServiceMessage"/>
                  <wsdl:output wsaw:Action="_ServicesNamespace_/InvokeServiceResponse" name="InvokeServiceResponseMessage" message="tns:InvokeServiceResponseMessage"/>
                  <wsdl:fault wsaw:Action="_ServicesNamespace_/InvokeServiceFault" name="InvokeServiceFaultMessage" message="tns:InvokeServiceFaultMessage" />
                </wsdl:operation>

                <!-- Session Operation List -->

              </wsdl:portType>

              <wsdl:portType name="IDiscoveryEndpoint">

                <wsdl:operation name="InvokeService">
                  <wsdl:input wsaw:Action="_ServicesNamespace_/InvokeService" name="InvokeServiceMessage" message="tns:InvokeServiceMessage"/>
                  <wsdl:output wsaw:Action="_ServicesNamespace_/InvokeServiceResponse" name="InvokeServiceResponseMessage" message="tns:InvokeServiceResponseMessage"/>
                  <wsdl:fault wsaw:Action="_ServicesNamespace_/InvokeServiceFault" name="InvokeServiceFaultMessage" message="tns:InvokeServiceFaultMessage" />
                </wsdl:operation>

                <!-- Discovery Operation List -->

              </wsdl:portType>

              <wsdl:portType name="IRegistrationEndpoint">

                <wsdl:operation name="InvokeService">
                  <wsdl:input wsaw:Action="_ServicesNamespace_/InvokeService" name="InvokeServiceMessage" message="tns:InvokeServiceMessage"/>
                  <wsdl:output wsaw:Action="_ServicesNamespace_/InvokeServiceResponse" name="InvokeServiceResponseMessage" message="tns:InvokeServiceResponseMessage"/>
                  <wsdl:fault wsaw:Action="_ServicesNamespace_/InvokeServiceFault" name="InvokeServiceFaultMessage" message="tns:InvokeServiceFaultMessage" />
                </wsdl:operation>

                <!-- Registration Operation List -->

              </wsdl:portType>

            </wsdl:definitions>
            <!--***END***-->
            """;

        /// <summary>
        /// XmlSchemaGenerator.cs  line#189
        /// XmlSchemaGenerator.cs  line#197
        /// XmlSchemaGenerator.cs  line#205
        /// </summary>
        public static string ModelCompiler_StackGenerator_DataTypes_Templates_XmlSchema_PortType_wsdl =>
            """
            <!--***START***-->
            <wsdl:operation name="_NAME_">
              <wsdl:input wsaw:Action="_ServicesNamespace_/_NAME_" name="_NAME_Message" message="tns:_NAME_Message"/>
              <wsdl:output wsaw:Action="_ServicesNamespace_/_NAME_Response" name="_NAME_ResponseMessage" message="tns:_NAME_ResponseMessage"/>
              <wsdl:fault wsaw:Action="_ServicesNamespace_/_NAME_Fault" name="_NAME_FaultMessage" message="tns:_NAME__FaultMessage" />
            </wsdl:operation>
            <!--***END***-->
            """;

        /// <summary>
        /// XmlSchemaGenerator.cs  line#272
        /// </summary>
        public static string ModelCompiler_StackGenerator_DataTypes_Templates_XmlSchema_File_xml =>
            """
            <!--***START***-->
            <xs:schema
              xmlns:s0="ListOfNamespaces"
              xmlns:xs="http://www.w3.org/2001/XMLSchema"
              xmlns:ua="http://opcfoundation.org/UA/BuiltInTypes/"
              targetNamespace="_Namespace_"
              elementFormDefault="qualified"
            >
              <!-- Imports -->

              <!-- ListOfTypes -->

            </xs:schema>
            <!--***END***-->
            """;

        /// <summary>
        /// XmlSchemaGenerator.cs  line#327
        /// </summary>
        public static string ModelCompiler_StackGenerator_DataTypes_Templates_XmlSchema_OpaqueType_xml =>
            """



            """;

        /// <summary>
        /// XmlSchemaGenerator.cs  line#410
        /// </summary>
        public static string ModelCompiler_StackGenerator_DataTypes_Templates_XmlSchema_DerivedType_xml =>
            """
            <!--***START***-->
            <xs:complexType name="_TypeName_">
              <xs:annotation>
                <xs:documentation>_Description_</xs:documentation>
              </xs:annotation>
              <xs:complexContent mixed="false">
                <xs:extension base="_BaseType_">
                  <xs:sequence>
                    <!-- ListOfFields -->
                  </xs:sequence>
                </xs:extension>
              </xs:complexContent>
            </xs:complexType>
            <xs:element name="_TypeName_" type="tns:_TypeName_" />
            <!-- ArrayDeclaration -->
            <!--***END***-->
            """;

        /// <summary>
        /// XmlSchemaGenerator.cs  line#413
        /// </summary>
        public static string ModelCompiler_StackGenerator_DataTypes_Templates_XmlSchema_ComplexType_xml =>
            """
            <!--***START***-->
            <xs:complexType name="_TypeName_">
              <xs:annotation>
                <xs:documentation>_Description_</xs:documentation>
              </xs:annotation>
              <xs:sequence>
                <!-- ListOfFields -->
              </xs:sequence>
            </xs:complexType>
            <xs:element name="_TypeName_" type="tns:_TypeName_" />
            <!-- ArrayDeclaration -->
            <!--***END***-->
            """;

        /// <summary>
        /// XmlSchemaGenerator.cs  line#418
        /// </summary>
        public static string ModelCompiler_StackGenerator_DataTypes_Templates_XmlSchema_EnumeratedType_xml =>
            """
            <!--***START***-->
            <xs:simpleType  name="_TypeName_">
              <xs:annotation>
                <xs:documentation>_Description_</xs:documentation>
              </xs:annotation>
              <xs:restriction base="xs:string">
                <!-- ListOfValues -->
              </xs:restriction>
            </xs:simpleType>
            <xs:element name="_TypeName_" type="tns:_TypeName_" />
            <!-- ArrayDeclaration -->
            <!--***END***-->
            """;

        /// <summary>
        /// XmlSchemaGenerator.cs  line#423
        /// </summary>
        public static string ModelCompiler_StackGenerator_DataTypes_Templates_XmlSchema_ServiceType_xml =>
            """
            <!--***START***-->
            <xs:complexType name="_TypeName_Request">
              <xs:annotation>
                <xs:documentation>_Description_</xs:documentation>
              </xs:annotation>
              <xs:sequence>
                <!-- ListOfRequestParameters -->
              </xs:sequence>
            </xs:complexType>
            <xs:element name="_TypeName_Request" type="tns:_TypeName_Request" />

            <xs:complexType name="_TypeName_Response">
              <xs:sequence>
                <!-- ListOfResponseParameters -->
              </xs:sequence>
            </xs:complexType>
            <xs:element name="_TypeName_Response" type="tns:_TypeName_Response" />
            <!--***END***-->
            """;

        /// <summary>
        /// XmlSchemaGenerator.cs  line#447
        /// </summary>
        public static string ModelCompiler_StackGenerator_DataTypes_Templates_XmlSchema_Array_xml =>
            """
            <!--***START***-->
            <xs:complexType name="ListOf_TypeName_">
              <xs:sequence>
                <xs:element name="_TypeName_" type="tns:_TypeName_" minOccurs="0" maxOccurs="unbounded" nillable="true" />
              </xs:sequence>
            </xs:complexType>
            <xs:element name="ListOf_TypeName_" type="tns:ListOf_TypeName_" nillable="true"></xs:element>
            <!--***END***-->
            """;

        /// <summary>
        /// XmlSchemaGenerator.cs  line#499
        /// </summary>
        public static string ModelCompiler_StackGenerator_DataTypes_Templates_XmlSchema_EnumeratedValue_xml => null;

        /// <summary>
        /// XmlSchemaGenerator.cs  line#478
        /// XmlSchemaGenerator.cs  line#510
        /// XmlSchemaGenerator.cs  line#518
        /// </summary>
        public static string ModelCompiler_StackGenerator_DataTypes_Templates_XmlSchema_Field_xml => null;
    }
}
