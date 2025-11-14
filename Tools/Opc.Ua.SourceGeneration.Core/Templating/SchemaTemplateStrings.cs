namespace Opc.Ua.SourceGeneration
{
    /// <summary>
    /// Template strings
    /// </summary>
    internal static class SchemaTemplateStrings
    {
        /// <summary>
        /// BinarySchemaGenerator.cs line#81
        /// </summary>
        public static string Stack_BinarySchema_File_xml =>
            $$"""
            <opc:TypeDictionary
              xmlns:s0="ListOfNamespaces"
              xmlns:opc="http://opcfoundation.org/BinarySchema/"
              xmlns:ua="http://opcfoundation.org/UA/"
              xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
              DefaultByteOrder="LittleEndian"
              TargetNamespace="{{Tokens.DictionaryUri}}"
            >
              {{Tokens.Imports}}

              {{Tokens.ListOfTypes}}

            </opc:TypeDictionary>
            """;

        /// <summary>
        /// BinarySchemaGenerator.cs line#125
        /// </summary>
        public static string Stack_BinarySchema_OpaqueType_xml =>
            $$"""
            <opc:OpaqueType Name="{{Tokens.TypeName}}">
              <opc:Documentation>{{Tokens.Description}}</opc:Documentation>
            </opc:OpaqueType>
            """;

        /// <summary>
        /// BinarySchemaGenerator.cs line#185
        /// </summary>
        public static string Stack_BinarySchema_BuiltInTypes_bsd =>
            """
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

            """;

        /// <summary>
        /// BinarySchemaGenerator.cs line#209
        /// </summary>
        public static string Stack_BinarySchema_ComplexType_xml =>
            $$"""
            <opc:StructuredType Name="{{Tokens.TypeName}}"  BaseType="{{Tokens.BaseType}}">
              <opc:Documentation>{{Tokens.Description}}</opc:Documentation>
              {{Tokens.ListOfFields}}
            </opc:StructuredType>
            """;

        /// <summary>
        /// BinarySchemaGenerator.cs line#214
        /// </summary>
        public static string Stack_BinarySchema_EnumeratedType_xml =>
            $$"""
            <opc:EnumeratedType Name="{{Tokens.TypeName}}" LengthInBits="{{Tokens.LengthInBits}}"{{Tokens.IsOptionSet}}>
              <opc:Documentation>{{Tokens.Description}}</opc:Documentation>
              {{Tokens.ListOfValues}}
            </opc:EnumeratedType>
            """;

        /// <summary>
        /// BinarySchemaGenerator.cs line#219
        /// </summary>
        public static string Stack_BinarySchema_ServiceType_xml =>
            $$"""
            <opc:StructuredType Name="{{Tokens.TypeName}}Request">
              <opc:Documentation>{{Tokens.Description}}</opc:Documentation>
              {{Tokens.ListOfRequestParameters}}
            </opc:StructuredType>

            <opc:StructuredType Name="{{Tokens.TypeName}}Response">
              <opc:Documentation>{{Tokens.Description}}</opc:Documentation>
              {{Tokens.ListOfResponseParameters}}
            </opc:StructuredType>
            """;

        /// <summary>
        /// ModelGenerator.cs line#559
        /// </summary>
        public static string XmlSchema_File_xml =>
            $$"""
            <xs:schema
              xmlns:s0="ListOfNamespaces"
              xmlns:xs="http://www.w3.org/2001/XMLSchema"
              xmlns:ua="http://opcfoundation.org/UA/2008/02/Types.xsd"
              xmlns:tns="{{Tokens.Namespace}}"
              targetNamespace="{{Tokens.Namespace}}"
              elementFormDefault="qualified"
            >
              <xs:annotation>
                <xs:appinfo>
                  <ua:Model ModelUri="{{Tokens.ModelUri}}" Version="{{Tokens.TargetVersion}}" PublicationDate="{{Tokens.TargetPublicationDate}}" />
                </xs:appinfo>
              </xs:annotation>

              {{Tokens.Imports}}
              {{Tokens.BuiltInTypes}}
              {{Tokens.ListOfTypes}}

            </xs:schema>
            """;

        /// <summary>
        /// ModelGenerator.cs line#590
        /// XmlSchemaGenerator.cs line#392
        /// </summary>
        public static string Stack_XmlSchema_BuiltInTypes_xsd =>
            """
              <!-- WARNING - this information is copied from Common\Schema\Xml\BuiltInTypes.xsd -->
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
            """;

        /// <summary>
        /// ModelGenerator.cs line#692
        /// ModelGenerator.cs line#709
        /// </summary>
        public static string XmlSchema_DerivedType_xml =>
            $$"""
            <xs:complexType name="{{Tokens.TypeName}}">
              {{Tokens.Documentation}}
              <xs:complexContent mixed="false">
                <xs:extension base="{{Tokens.BaseType}}">
                  <xs:sequence>
                    {{Tokens.ListOfFields}}
                  </xs:sequence>
                </xs:extension>
              </xs:complexContent>
            </xs:complexType>
            <xs:element name="{{Tokens.TypeName}}" type="tns:{{Tokens.TypeName}}" />
            {{Tokens.CollectionType}}
            """;

        /// <summary>
        /// ModelGenerator.cs line#695
        /// </summary>
        public static string XmlSchema_EnumeratedType_xml =>
            $$"""
            <xs:simpleType name="{{Tokens.TypeName}}">
              {{Tokens.Documentation}}
              <xs:restriction base="{{Tokens.XsRestrictionBaseType}}">
                {{Tokens.ListOfFields}}
              </xs:restriction>
            </xs:simpleType>
            <xs:element name="{{Tokens.TypeName}}" type="tns:{{Tokens.TypeName}}" />
            {{Tokens.CollectionType}}
            """;

        /// <summary>
        /// ModelGenerator.cs line#701
        /// </summary>
        public static string XmlSchema_Union_xml =>
            $$"""
            <xs:complexType name="{{Tokens.TypeName}}">
              {{Tokens.Documentation}}
              <xs:sequence>
                <xs:element name="SwitchField" type="xs:unsignedInt" minOccurs="0" />
                <xs:choice>
                  {{Tokens.ListOfFields}}
                </xs:choice>
              </xs:sequence>
            </xs:complexType>
            <xs:element name="{{Tokens.TypeName}}" type="tns:{{Tokens.TypeName}}" />
            {{Tokens.CollectionType}}
            """;

        /// <summary>
        /// ModelGenerator.cs line#705
        /// </summary>
        public static string XmlSchema_ComplexType_xml =>
            $$"""
            <xs:complexType name="{{Tokens.TypeName}}">
              {{Tokens.Documentation}}
              <xs:sequence>
                {{Tokens.ListOfFields}}
              </xs:sequence>
            </xs:complexType>
            <xs:element name="{{Tokens.TypeName}}" type="tns:{{Tokens.TypeName}}" />
            {{Tokens.CollectionType}}
            """;

        /// <summary>
        /// ModelGenerator.cs line#713
        /// </summary>
        public static string XmlSchema_SimpleType_xml =>
            $$"""
            <xs:element name="{{Tokens.TypeName}}" type="{{Tokens.BaseType}}" />
            """;

        /// <summary>
        /// ModelGenerator.cs line#762
        /// </summary>
        public static string XmlSchema_Documentation_xml =>
            $$"""
            <xs:annotation>
              <xs:documentation>{{Tokens.Description}}</xs:documentation>
            </xs:annotation>
            """;

        /// <summary>
        /// ModelGenerator.cs line#769
        /// </summary>
        public static string XmlSchema_CollectionType_xml =>
            $$"""
            <xs:complexType name="ListOf{{Tokens.TypeName}}">
              <xs:sequence>
                <xs:element name="{{Tokens.TypeName}}" type="tns:{{Tokens.TypeName}}" minOccurs="0" maxOccurs="unbounded" {{Tokens.Nillable}}/>
              </xs:sequence>
            </xs:complexType>
            <xs:element name="ListOf{{Tokens.TypeName}}" type="tns:ListOf{{Tokens.TypeName}}" nillable="true"></xs:element>
            """;

        /// <summary>
        /// ModelGenerator.cs line#981
        /// </summary>
        public static string BinarySchema_File_xml =>
            $$"""
            <opc:TypeDictionary
              xmlns:s0="ListOfNamespaces"
              xmlns:opc="http://opcfoundation.org/BinarySchema/"
              xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
              xmlns:ua="http://opcfoundation.org/UA/"
              xmlns:tns="{{Tokens.DictionaryUri}}"
              DefaultByteOrder="LittleEndian"
              TargetNamespace="{{Tokens.DictionaryUri}}"
            >
              {{Tokens.Imports}}
              {{Tokens.BuiltInTypes}}
              {{Tokens.ListOfTypes}}

            </opc:TypeDictionary>
            """;

        /// <summary>
        /// ModelGenerator.cs line#1003
        /// </summary>
        public static string BinarySchema_BuiltInTypes_bsd =>
            """
            <!-- WARNING - this information is copied from Common\Schema\Binary\BuiltInTypes.bsd -->
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

            """;

        /// <summary>
        /// ModelGenerator.cs line#1104
        /// </summary>
        public static string BinarySchema_EnumeratedType_xml =>
            $$"""
            <opc:EnumeratedType Name="{{Tokens.TypeName}}" LengthInBits="{{Tokens.LengthInBits}}"{{Tokens.IsOptionSet}}>
              {{Tokens.Documentation}}
              {{Tokens.ListOfFields}}
            </opc:EnumeratedType>
            """;

        /// <summary>
        /// ModelGenerator.cs line#1108
        /// </summary>
        public static string BinarySchema_ComplexType_xml =>
            $$"""
            <opc:StructuredType Name="{{Tokens.TypeName}}" BaseType="{{Tokens.BaseType}}">
              {{Tokens.Documentation}}
              {{Tokens.ListOfFields}}
            </opc:StructuredType>
            """;

        /// <summary>
        /// ModelGenerator.cs line#1111
        /// </summary>
        public static string BinarySchema_OpaqueType_xml =>
            $$"""
            <opc:OpaqueType Name="{{Tokens.TypeName}}">
              {{Tokens.Documentation}}
            </opc:OpaqueType>
            """;

        /// <summary>
        /// XmlSchemaGenerator.cs line#272
        /// </summary>
        public static string Stack_XmlSchema_File_xml =>
            $$"""
            <xs:schema
              xmlns:s0="ListOfNamespaces"
              xmlns:xs="http://www.w3.org/2001/XMLSchema"
              xmlns:ua="http://opcfoundation.org/UA/BuiltInTypes/"
              targetNamespace="{{Tokens.Namespace}}"
              elementFormDefault="qualified"
            >
              {{Tokens.Imports}}

              {{Tokens.ListOfTypes}}

            </xs:schema>
            """;

        /// <summary>
        /// XmlSchemaGenerator.cs line#410
        /// </summary>
        public static string Stack_XmlSchema_DerivedType_xml =>
            $$"""
            <xs:complexType name="{{Tokens.TypeName}}">
              <xs:annotation>
                <xs:documentation>{{Tokens.Description}}</xs:documentation>
              </xs:annotation>
              <xs:complexContent mixed="false">
                <xs:extension base="{{Tokens.BaseType}}">
                  <xs:sequence>
                    {{Tokens.ListOfFields}}
                  </xs:sequence>
                </xs:extension>
              </xs:complexContent>
            </xs:complexType>
            <xs:element name="{{Tokens.TypeName}}" type="tns:{{Tokens.TypeName}}" />
            {{Tokens.ArrayDeclaration}}
            """;

        /// <summary>
        /// XmlSchemaGenerator.cs line#413
        /// </summary>
        public static string Stack_XmlSchema_ComplexType_xml =>
            $$"""
            <xs:complexType name="{{Tokens.TypeName}}">
              <xs:annotation>
                <xs:documentation>{{Tokens.Description}}</xs:documentation>
              </xs:annotation>
              <xs:sequence>
                {{Tokens.ListOfFields}}
              </xs:sequence>
            </xs:complexType>
            <xs:element name="{{Tokens.TypeName}}" type="tns:{{Tokens.TypeName}}" />
            {{Tokens.ArrayDeclaration}}
            """;

        /// <summary>
        /// XmlSchemaGenerator.cs line#418
        /// </summary>
        public static string Stack_XmlSchema_EnumeratedType_xml =>
            $$"""
            <xs:simpleType  name="{{Tokens.TypeName}}">
              <xs:annotation>
                <xs:documentation>{{Tokens.Description}}</xs:documentation>
              </xs:annotation>
              <xs:restriction base="xs:string">
                {{Tokens.ListOfValues}}
              </xs:restriction>
            </xs:simpleType>
            <xs:element name="{{Tokens.TypeName}}" type="tns:{{Tokens.TypeName}}" />
            {{Tokens.ArrayDeclaration}}
            """;

        /// <summary>
        /// XmlSchemaGenerator.cs line#423
        /// </summary>
        public static string Stack_XmlSchema_ServiceType_xml =>
            $$"""
            <xs:complexType name="{{Tokens.TypeName}}Request">
              <xs:annotation>
                <xs:documentation>{{Tokens.Description}}</xs:documentation>
              </xs:annotation>
              <xs:sequence>
                {{Tokens.ListOfRequestParameters}}
              </xs:sequence>
            </xs:complexType>
            <xs:element name="{{Tokens.TypeName}}Request" type="tns:{{Tokens.TypeName}}Request" />

            <xs:complexType name="{{Tokens.TypeName}}Response">
              <xs:sequence>
                {{Tokens.ListOfResponseParameters}}
              </xs:sequence>
            </xs:complexType>
            <xs:element name="{{Tokens.TypeName}}Response" type="tns:{{Tokens.TypeName}}Response" />
            """;

        /// <summary>
        /// XmlSchemaGenerator.cs line#447
        /// </summary>
        public static string Stack_XmlSchema_Array_xml =>
            $$"""
            <xs:complexType name="ListOf{{Tokens.TypeName}}">
              <xs:sequence>
                <xs:element name="{{Tokens.TypeName}}" type="tns:{{Tokens.TypeName}}" minOccurs="0" maxOccurs="unbounded" nillable="true" />
              </xs:sequence>
            </xs:complexType>
            <xs:element name="ListOf{{Tokens.TypeName}}" type="tns:ListOf{{Tokens.TypeName}}" nillable="true"></xs:element>
            """;
    }
}
