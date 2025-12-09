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

namespace Opc.Ua.SourceGeneration
{
    internal static class Tokens
    {
        public static string AccessLevel => nameof(AccessLevel);
        public static string ArrayDeclaration => nameof(ArrayDeclaration);
        public static string ArrayDimensions => nameof(ArrayDimensions);
        public static string BaseClassName => nameof(BaseClassName);
        public static string BaseType => nameof(BaseType);
        public static string BaseTypeNamespacePrefix => nameof(BaseTypeNamespacePrefix);
        public static string BaseTypeNamespaceUri => nameof(BaseTypeNamespaceUri);
        public static string BinaryEncodingId => nameof(BinaryEncodingId);
        public static string BrowseName => nameof(BrowseName);
        public static string BrowseNameNamespacePrefix => nameof(BrowseNameNamespacePrefix);
        public static string BrowseNameNamespaceUri => nameof(BrowseNameNamespaceUri);
        public static string BuiltInTypes => nameof(BuiltInTypes);
        public static string ChildDataType => nameof(ChildDataType);
        public static string ChildName => nameof(ChildName);
        public static string ChildPath => nameof(ChildPath);
        public static string ClassName => nameof(ClassName);
        public static string ClientApi => nameof(ClientApi);
        public static string ClientMethod => nameof(ClientMethod);
        public static string CodeName => nameof(CodeName);
        public static string CollectionClass => nameof(CollectionClass);
        public static string CollectionType => nameof(CollectionType);
        public static string DataType => nameof(DataType);
        public static string DataTypeNamespacePrefix => nameof(DataTypeNamespacePrefix);
        public static string DataTypeNamespaceUri => nameof(DataTypeNamespaceUri);
        public static string DefaultValue => nameof(DefaultValue);
        public static string Description => nameof(Description);
        public static string DictionaryUri => nameof(DictionaryUri);
        public static string Documentation => nameof(Documentation);
        public static string EmitDefaultValue => nameof(EmitDefaultValue);
        public static string EnumerationName => nameof(EnumerationName);
        public static string EventNotifier => nameof(EventNotifier);
        public static string FieldIndex => nameof(FieldIndex);
        public static string FieldName => nameof(FieldName);
        public static string FindChildMethods => nameof(FindChildMethods);
        public static string FindChildMethodsForType => nameof(FindChildMethodsForType);
        public static string Historizing => nameof(Historizing);
        public static string Identifier => nameof(Identifier);
        public static string IdType => nameof(IdType);
        public static string Imports => nameof(Imports);
        public static string InitializeOptionalChildren => nameof(InitializeOptionalChildren);
        public static string InvokeServiceAsync => nameof(InvokeServiceAsync);
        public static string IsAbstract => nameof(IsAbstract);
        public static string IsOptionSet => nameof(IsOptionSet);
        public static string IsRequired => nameof(IsRequired);
        public static string LengthInBits => nameof(LengthInBits);
        public static string ListOfBrowseNames => nameof(ListOfBrowseNames);
        public static string ListOfChildInitializers => nameof(ListOfChildInitializers);
        public static string ListOfChildMethods => nameof(ListOfChildMethods);
        public static string ListOfClonedFields => nameof(ListOfClonedFields);
        public static string ListOfComparedFields => nameof(ListOfComparedFields);
        public static string ListOfDecodedFields => nameof(ListOfDecodedFields);
        public static string ListOfEncodedFields => nameof(ListOfEncodedFields);
        public static string ListOfEncodingMaskFields => nameof(ListOfEncodingMaskFields);
        public static string ListOfEncodings => nameof(ListOfEncodings);
        public static string ListOfFieldInitializers => nameof(ListOfFieldInitializers);
        public static string ListOfFields => nameof(ListOfFields);
        public static string ListOfSwitchFieldNames => nameof(ListOfSwitchFieldNames);
        public static string ListOfEncodingMaskFieldNames => nameof(ListOfEncodingMaskFieldNames);
        public static string ListOfFieldsForType => nameof(ListOfFieldsForType);
        public static string ListOfFindChildCase => nameof(ListOfFindChildCase);
        public static string ListOfFindChildren => nameof(ListOfFindChildren);
        public static string ListOfIdentifiers => nameof(ListOfIdentifiers);
        public static string ListOfIdentifersToNames => nameof(ListOfIdentifersToNames);
        public static string ListOfNamesToIdentifiers => nameof(ListOfNamesToIdentifiers);
        public static string ListOfImports => nameof(ListOfImports);
        public static string ListOfInputArguments => nameof(ListOfInputArguments);
        public static string ListOfNamespaceUris => nameof(ListOfNamespaceUris);
        public static string ListOfNodeIds => nameof(ListOfNodeIds);
        public static string ListOfOutputArguments => nameof(ListOfOutputArguments);
        public static string ListOfOutputArgumentsFromResult => nameof(ListOfOutputArgumentsFromResult);
        public static string ListOfOutputDeclarations => nameof(ListOfOutputDeclarations);
        public static string ListOfProperties => nameof(ListOfProperties);
        public static string ListOfPropertiesForType => nameof(ListOfPropertiesForType);
        public static string ListOfRemoveChild => nameof(ListOfRemoveChild);
        public static string ListOfRequestParameters => nameof(ListOfRequestParameters);
        public static string ListOfResponseParameters => nameof(ListOfResponseParameters);
        public static string ListOfResultProperties => nameof(ListOfResultProperties);
        public static string ListOfSwitchFields => nameof(ListOfSwitchFields);
        public static string ListOfTypes => nameof(ListOfTypes);
        public static string ListOfUpdateChildrenChangeMasks => nameof(ListOfUpdateChildrenChangeMasks);
        public static string ListOfValues => nameof(ListOfValues);
        public static string MethodList => nameof(MethodList);
        public static string MinimumSamplingInterval => nameof(MinimumSamplingInterval);
        public static string Name => nameof(Name);
        public static string Namespace => nameof(Namespace);
        public static string NamespacePrefix => nameof(NamespacePrefix);
        public static string NamespaceUri => nameof(NamespaceUri);
        public static string Nillable => nameof(Nillable);
        public static string NodeClass => nameof(NodeClass);
        public static string OnCallAsyncDeclaration => nameof(OnCallAsyncDeclaration);
        public static string OnCallAsyncImplementation => nameof(OnCallAsyncImplementation);
        public static string OnCallDeclaration => nameof(OnCallDeclaration);
        public static string OnCallImplementation => nameof(OnCallImplementation);
        public static string Prefix => nameof(Prefix);
        public static string RequestParameters => nameof(RequestParameters);
        public static string ResponseParameters => nameof(ResponseParameters);
        public static string ServerApi => nameof(ServerApi);
        public static string ServerStubs => nameof(ServerStubs);
        public static string ServiceSet => nameof(ServiceSet);
        public static string ServiceSets => nameof(ServiceSets);
        public static string SymbolicId => nameof(SymbolicId);
        public static string SymbolicName => nameof(SymbolicName);
        public static string TypedVariableType => nameof(TypedVariableType);
        public static string TypeName => nameof(TypeName);
        public static string TypesNamespace => nameof(TypesNamespace);
        public static string ValueRank => nameof(ValueRank);
        public static string VariableTypeValue => nameof(VariableTypeValue);
        public static string Version => nameof(Version);
        public static string Tool => nameof(Tool);
        public static string XmlEncodingId => nameof(XmlEncodingId);
        public static string XmlIdentifier => nameof(XmlIdentifier);
        public static string XmlNamespaceUri => nameof(XmlNamespaceUri);
        public static string XmlnsS0ListOfNamespaces => nameof(XmlnsS0ListOfNamespaces);
        public static string TypeList => nameof(TypeList);
        public static string BasicType => nameof(BasicType);
        public static string Flags => nameof(Flags);
        public static string Encoding => nameof(Encoding);
        public static string AddKnownType => nameof(AddKnownType);
        public static string ModelUri => nameof(ModelUri);
        public static string TargetPublicationDate => nameof(TargetPublicationDate);
        public static string TargetVersion => nameof(TargetVersion);
        public static string BaseT => nameof(BaseT);
        public static string XsRestrictionBaseType => nameof(XsRestrictionBaseType);
        public static string PropertyAccessor => nameof(PropertyAccessor);
        public static string JsonEncodingId => nameof(JsonEncodingId);
        public static string ServerMethodAsync => nameof(ServerMethodAsync);
        public static string ClientMethodAsync => nameof(ClientMethodAsync);
        public static string ClientMethodSync => nameof(ClientMethodSync);
        public static string ClientMethodBegin => nameof(ClientMethodBegin);
        public static string ClientMethodEnd => nameof(ClientMethodEnd);
        public static string Header => nameof(Header);
        public static string ResourceName => nameof(ResourceName);
        public static string Resource => nameof(Resource);
        public static string ListOfResourceGroups => nameof(ListOfResourceGroups);
        public static string ListOfResourceDeclarations => nameof(ListOfResourceDeclarations);
        public static string AccessModifier => nameof(AccessModifier);
        public static string IdentifierReflection => nameof(IdentifierReflection);
        public static string EqualityComparer => nameof(EqualityComparer);
    }
}
