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
using System.IO;
using System.Text;
using System.Xml;
using Opc.Ua.Schema.Types;

namespace Opc.Ua.SourceGeneration
{
    /// <summary>
    /// Generates code based on a UA Type Dictionary.
    /// </summary>
    public class ConstantsGenerator
    {
        /// <summary>
        /// Generates the code from the contents of the address space.
        /// </summary>
        public ConstantsGenerator(
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

            // save output directory.
            OutputDirectory = outputDirectory;
            Exclusions = exclusions;
            m_fileSystem = fileSystem;
        }

        /// <summary>
        /// The validator used to verify the type dictionary.
        /// </summary>
        protected TypeDictionaryValidator Validator { get; }

        /// <summary>
        /// The dictionary being processed.
        /// </summary>
        protected TypeDictionary Dictionary => Validator.Dictionary;

        /// <summary>
        /// The directory used to place any output files.
        /// </summary>
        protected string OutputDirectory { get; }

        /// <summary>
        /// The types to exclude.
        /// </summary>
        protected IReadOnlyList<string> Exclusions { get; set; }

        /// <summary>
        /// Generates the datatype files.
        /// </summary>
        public virtual void Generate(
            string namespacePrefix,
            string className,
            string identifiersFile)
        {
            List<DataType> datatypes = GetDataTypeList();

            LoadIdentifiers(identifiersFile, datatypes);

            WriteTemplate_Constants(namespacePrefix, className, datatypes);
        }

        /// <summary>
        /// Writes the address space declaration file.
        /// </summary>
        private void WriteTemplate_Constants(
            string namespacePrefix,
            string className,
            List<DataType> datatypes)
        {
            m_className = className;

            // assign identifiers.
            foreach (DataType datatype in datatypes)
            {
                if (datatype is Constant constant)
                {
                    if (constant.Name.StartsWith(nameof(Severity.Bad), StringComparison.Ordinal))
                    {
                        constant.Severity = Severity.Bad;
                    }

                    if (constant.Name.StartsWith(nameof(Severity.Good), StringComparison.Ordinal))
                    {
                        constant.Severity = Severity.Good;
                    }

                    if (constant.Name.StartsWith(nameof(Severity.Uncertain), StringComparison.Ordinal))
                    {
                        constant.Severity = Severity.Uncertain;
                    }
                }
            }

            string fileName = Path.Combine(OutputDirectory,
                CoreUtils.Format("{0}.{1}.g.cs", namespacePrefix, className));
            using TextWriter writer = m_fileSystem.CreateTextWriter(fileName);
            string templatePath = CodeTemplateStrings.Constants_File_cs;

            if (className == "Identifiers")
            {
                templatePath = CodeTemplateStrings.Constants_DataTypes_cs;
            }

            var template = new Template(writer, templatePath);

            template.AddReplacement(Tokens.Date, DateTime.Now);
            template.AddReplacement(Tokens.Prefix, namespacePrefix);
            template.AddReplacement(Tokens.ClassName, className);
            template.AddReplacement(Tokens.FileName, namespacePrefix + '_' + className);

            template.AddTemplate(
                Tokens.ListOfIdentifiers,
                CodeTemplateStrings.Constants_Constant_cs,
                datatypes,
                LoadTemplate_Constant,
                WriteTemplate_Constant);

            template.AddTemplate(
                Tokens.ListOfEncodings,
                CodeTemplateStrings.Constants_Constant_cs,
                datatypes,
                LoadTemplate_Constant,
                WriteTemplate_Constant);

            template.AddReplacement(Tokens.StatusCodeHelpers, string.Empty);

            var context = new Context();
            template.WriteTemplate(context);
        }

        /// <summary>
        /// Writes the default value for a field.
        /// </summary>
        private string LoadTemplate_Constant(Template template, Context context)
        {
            if (context.Target is not DataType datatype)
            {
                return null;
            }

            if (context.Token == Tokens.ListOfEncodings)
            {
                if (datatype is ComplexType)
                {
                    // Add encodings during load phase.
                    return string.Empty;
                }

                return null;
            }

            return context.TemplateString;
        }

        /// <summary>
        /// Writes a constant.
        /// </summary>
        private bool WriteTemplate_Constant(Template template, Context context)
        {
            if (context.Target is not DataType datatype)
            {
                return false;
            }

            var constant = context.Target as Constant;

            if (constant != null)
            {
                if (!string.IsNullOrEmpty(constant.Value))
                {
                    template.AddReplacement(Tokens.IdType, "string");
                    template.AddReplacement(Tokens.Identifier, CoreUtils.Format("\"{0}\"", constant.Value));
                    template.AddReplacement(Tokens.ClassName, "_" + m_className);
                }
                else
                {
                    context.BlankLine = true;

                    if (constant.Severity != Severity.None)
                    {
                        uint id = Convert.ToUInt32(constant.Identifier, CultureInfo.InvariantCulture);
                        id <<= 16;

                        switch (constant.Severity)
                        {
                            case Severity.Bad:
                                id += 0x80000000;
                                break;
                            case Severity.Uncertain:
                                id += 0x40000000;
                                break;
                        }

                        template.AddReplacement(Tokens.IdType, "uint");
                        template.AddReplacement(Tokens.Identifier, CoreUtils.Format("0x{0:X8}", id));
                        template.AddReplacement(Tokens.ClassName, string.Empty);
                    }
                    else
                    {
                        template.AddReplacement(Tokens.IdType, "uint");
                        template.AddReplacement(Tokens.Identifier, constant.Identifier);
                        template.AddReplacement(Tokens.ClassName, "_" + m_className);
                    }
                }
            }

            string symbolicId = datatype.Name;

            if (constant != null)
            {
                if (constant.Severity != Severity.None && constant.Identifier != 0)
                {
                    string name = datatype.Name;

                    int index = name.IndexOf('_', StringComparison.Ordinal);

                    if (index != -1)
                    {
                        name = name[(index + 1)..];
                    }

                    symbolicId = CoreUtils.Format("{0}{1}", constant.Severity, name);
                }
            }
            else
            {
                template.AddReplacement(Tokens.IdType, "uint");
                template.AddReplacement(Tokens.Identifier, datatype.Identifier);
                template.AddReplacement(Tokens.ClassName, "Id");
            }

            template.AddReplacement(Tokens.SymbolicId, symbolicId);

            string description = datatype.Documentation.GetDescription();

            if (string.IsNullOrEmpty(description))
            {
                description = CoreUtils.Format("The identifier for the {0} datatype.", symbolicId);
            }

            template.AddReplacement(Tokens.Description, description);

            if (context.Target is ComplexType complexType)
            {
                template.AddReplacement(Tokens.XmlEncodingId, complexType.XmlEncodingId);
                template.AddReplacement(Tokens.BinaryEncodingId, complexType.BinaryEncodingId);
            }

            return template.WriteTemplate(context);
        }

        /// <summary>
        /// Returns the list of datatypes to process.
        /// </summary>
        protected List<DataType> GetDataTypeList()
        {
            // collect datatypes with the specified type.
            List<DataType> datatypes = [];

            // include identifiers from the target dictionary.
            foreach (DataType datatype in Dictionary.Items)
            {
                if (TypeDictionaryValidator.IsExcluded(Exclusions, datatype))
                {
                    continue;
                }

                if (datatype is not ServiceType serviceType)
                {
                    datatypes.Add(datatype);
                    continue;
                }

                if (serviceType.Request != null)
                {
                    var requestType = new ComplexType
                    {
                        Name = CoreUtils.Format("{0}Request", serviceType.Name),
                        Field = serviceType.Request
                    };
                    requestType.QName = new XmlQualifiedName(
                        requestType.Name,
                        serviceType.QName.Namespace);

                    datatypes.Add(requestType);
                }

                if (serviceType.Response != null)
                {
                    var responseType = new ComplexType
                    {
                        Name = CoreUtils.Format("{0}Response", serviceType.Name),
                        Field = serviceType.Response
                    };
                    responseType.QName = new XmlQualifiedName(
                        responseType.Name,
                        serviceType.QName.Namespace);

                    datatypes.Add(responseType);
                }
            }

            return datatypes;
        }

        /// <summary>
        /// Loads the identifiers from a CSV file.
        /// </summary>
        /// <exception cref="InvalidOperationException"></exception>
        private void LoadIdentifiers(string identifiersFile, List<DataType> datatypes)
        {
            Dictionary<string, int> identifiers = [];
            SortedDictionary<int, string> assignedIdentifiers = [];

            int maxId = 1;

            using TextReader reader = m_fileSystem.CreateTextReader(identifiersFile);
            while (true)
            {
                string line = reader.ReadLine();
                if (line == null)
                {
                    break;
                }

                if (string.IsNullOrWhiteSpace(line))
                {
                    continue;
                }

                int index = line.IndexOf(',', StringComparison.Ordinal);

                if (index == -1)
                {
                    continue;
                }

                // remove the node class if it is present.
                int lastIndex = line.LastIndexOf(',');

                if (lastIndex != -1 && index != lastIndex)
                {
                    line = line[..lastIndex];
                }

                try
                {
                    string name = line[..index].Trim();

                    int uid = Convert.ToInt32(
                        line[(index + 1)..].Trim(),
                        CultureInfo.InvariantCulture);

                    if (maxId <= uid)
                    {
                        maxId = uid + 1;
                    }

                    identifiers[name] = uid;
                    assignedIdentifiers[uid] = name;
                }
                catch (Exception)
                {
                    continue;
                }
            }

            SortedDictionary<int, string> uniqueIdentifiers = [];
            Dictionary<string, int> duplicateIdentifiers = [];

            foreach (DataType datatype in datatypes)
            {
                // using existing id or assign a new one.
                if (!identifiers.TryGetValue(datatype.Name, out int value))
                {
                    int nextId = 200;
                    while (assignedIdentifiers.ContainsKey(nextId))
                    {
                        nextId++;
                    }

                    datatype.Identifier = nextId;
                    datatype.IdentifierSpecified = true;
                    assignedIdentifiers.Add(nextId, datatype.Name);
                }
                else
                {
                    datatype.Identifier = value;
                    datatype.IdentifierSpecified = true;
                }

                // check for duplicates.
                if (uniqueIdentifiers.ContainsKey(datatype.Identifier))
                {
                    duplicateIdentifiers.Add(datatype.Name, datatype.Identifier);
                }
                else
                {
                    uniqueIdentifiers.Add(datatype.Identifier, datatype.Name);
                }

                // find identifiers for data type encodings.

                if (datatype is ComplexType complexType)
                {
                    string name = CoreUtils.Format("{0}_Encoding_DefaultXml", datatype.Name);

                    if (!identifiers.TryGetValue(name, out int value1))
                    {
                        complexType.XmlEncodingId = maxId++;
                    }
                    else
                    {
                        complexType.XmlEncodingId = value1;
                    }

                    // check for duplicates.
                    if (uniqueIdentifiers.ContainsKey(complexType.XmlEncodingId))
                    {
                        duplicateIdentifiers.Add(name, complexType.XmlEncodingId);
                    }
                    else
                    {
                        uniqueIdentifiers.Add(complexType.XmlEncodingId, name);
                    }

                    name = CoreUtils.Format("{0}_Encoding_DefaultBinary", datatype.Name);

                    if (!identifiers.TryGetValue(name, out int value2))
                    {
                        complexType.BinaryEncodingId = maxId++;
                    }
                    else
                    {
                        complexType.BinaryEncodingId = value2;
                    }

                    // check for duplicates.
                    if (uniqueIdentifiers.ContainsKey(complexType.BinaryEncodingId))
                    {
                        duplicateIdentifiers.Add(name, complexType.BinaryEncodingId);
                    }
                    else
                    {
                        uniqueIdentifiers.Add(complexType.BinaryEncodingId, name);
                    }
                }
            }

            // check for duplicate datatypes.
            if (duplicateIdentifiers.Count > 0)
            {
                var buffer = new StringBuilder();

                buffer.Append("Duplicate identifiers for these datatypes:\r\n");

                foreach (KeyValuePair<string, int> current in duplicateIdentifiers)
                {
                    buffer.AppendFormat(
                        CultureInfo.InvariantCulture,
                        "{0},0x{1:X8}\r\n",
                        current.Key,
                        current.Value);
                }

                throw new InvalidOperationException(buffer.ToString());
            }
        }

        private string m_className;
        private readonly IFileSystem m_fileSystem;
    }
}
