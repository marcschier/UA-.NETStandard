/* Copyright (c) 1996-2022 The OPC Foundation. All rights reserved.
   The source code in this file is covered under a dual-license scenario:
     - RCL: for OPC Foundation Corporate Members in good-standing
     - GPL V2: everybody else
   RCL license terms accompanied with this source code. See http://opcfoundation.org/License/RCL/1.00/
   GNU General Public License as published by the Free Software Foundation;
   version 2 of the License are accompanied with this source code. See http://opcfoundation.org/License/GPLv2
   This source code is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
*/

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Xml;
using System.Xml.Schema;
using Microsoft.Extensions.Logging;

namespace Opc.Ua.Schema.Xml
{
    /// <summary>
    /// Generates files used to describe data types.
    /// </summary>
    public class XmlSchemaValidator : SchemaValidator
    {
        /// <summary>
        /// Well known xml schema files to namespace mappings.
        /// </summary>
        public static readonly IReadOnlyDictionary<string, string> WellKnown =
            new Dictionary<string, string>
            {
                // [Namespaces.OpcUaBuiltInTypes] = "BuiltInTypes.xsd",
                // [Namespaces.OpcUaXsd] = "Opc.Ua.Types.xsd",
                [Namespaces.OpcUa] = "Opc.Ua.Types.xsd"
            };

        /// <summary>
        /// Intializes the object with default values.
        /// </summary>
        public XmlSchemaValidator(
            IFileSystem fileSystem = null,
            IDictionary<string, string> knownFiles = null)
            : base(fileSystem, knownFiles, null)
        {
            AddWellKnownFiles(WellKnown);
        }

        /// <summary>
        /// Intializes the object with a import table.
        /// </summary>
        public XmlSchemaValidator(IReadOnlyDictionary<string, byte[]> importTable)
            : base(null, null, importTable)
        {
            AddWellKnownFiles(WellKnown);
        }

        /// <summary>
        /// The schema set that was validated.
        /// </summary>
        public XmlSchemaSet SchemaSet { get; private set; }

        /// <summary>
        /// The schema that was validated.
        /// </summary>
        public XmlSchema TargetSchema { get; private set; }

        /// <summary>
        /// Generates the code from the contents of the address space.
        /// </summary>
        public void Validate(string inputPath, ILogger logger)
        {
            using Stream istrm = FileSystem.OpenRead(inputPath);
            Validate(istrm, logger);
        }

        /// <summary>
        /// Generates the code from the contents of the address space.
        /// </summary>
        public void Validate(Stream stream, ILogger logger)
        {
            var handler = new ValidationEventHandler((_, e) => OnValidate(e, logger));
            TargetSchema = Load(stream, handler);

            foreach (XmlSchemaImport import in TargetSchema.Includes.OfType<XmlSchemaImport>())
            {
                import.Schema = Load(import.SchemaLocation, import.Namespace, handler);
            }

            SchemaSet = new XmlSchemaSet();
            SchemaSet.Add(TargetSchema);
            SchemaSet.Compile();
        }

        /// <summary>
        /// Returns the schema for the specified type (returns the entire schema if null).
        /// </summary>
        public override string GetSchema(string typeName)
        {
            XmlWriterSettings settings = CoreUtils.DefaultXmlWriterSettings();

            var ostrm = new MemoryStream();
            var writer = XmlWriter.Create(ostrm, settings);

            try
            {
                if (typeName == null || TargetSchema.Elements.Values.Count == 0)
                {
                    TargetSchema.Write(writer);
                }
                else
                {
                    foreach (XmlSchemaObject current in TargetSchema.Elements.Values)
                    {
                        if (current is XmlSchemaElement element && element.Name == typeName)
                        {
                            var schema = new XmlSchema();
                            schema.Items.Add(element.ElementSchemaType);
                            schema.Items.Add(element);
                            schema.Write(writer);
                            break;
                        }
                    }
                }
            }
            finally
            {
                writer.Flush();
                writer.Dispose();
            }

            return Encoding.UTF8.GetString(ostrm.ToArray());
        }

        /// <summary>
        /// Handles a validation error.
        /// </summary>
        /// <exception cref="InvalidOperationException"></exception>
        private static void OnValidate(ValidationEventArgs args, ILogger logger)
        {
            logger.LogError("Error in XML schema validation: {Message}", args.Message);
            throw new InvalidOperationException(args.Message, args.Exception);
        }
    }
}
