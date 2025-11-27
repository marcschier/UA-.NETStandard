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

using System.Collections;

namespace Opc.Ua.SourceGeneration
{
    /// <summary>
    /// Stores the information that describes how to initialize and process a template.
    /// </summary>
    internal sealed class TemplateDefinition
    {
        /// <summary>
        /// The template composite string
        /// </summary>
        public TemplateString TemplateString { get; set; }

        /// <summary>
        /// The targets that the template should be applied to.
        /// </summary>
        public ICollection Targets { get; set; }

        /// <summary>
        /// The callback to call when loading the template.
        /// </summary>
        public LoadTemplateEventHandler OnTemplateLoad { get; set; }

        /// <summary>
        /// The callback to call when writing the template.
        /// </summary>
        public WriteTemplateEventHandler OnTemplateWrite { get; set; }

        /// <summary>
        /// Loads the template.
        /// </summary>
        public TemplateString Load(Template template, Context context)
        {
            // check for override.
            if (OnTemplateLoad != null)
            {
                return OnTemplateLoad(template, context);
            }

            // use the default function to write the template.
            return context.TemplateString;
        }

        /// <summary>
        /// Writes the template.
        /// </summary>
        public bool Write(Template template, Context context)
        {
            // check for override.
            if (OnTemplateWrite != null)
            {
                return OnTemplateWrite(template, context);
            }

            // use the default function to write the template.
            return template.WriteTemplate(context);
        }
    }

    /// <summary>
    /// A delegate handle events associated with template.
    /// </summary>
    internal delegate TemplateString LoadTemplateEventHandler(Template template, Context context);

    /// <summary>
    /// A delegate handle events associated with template.
    /// </summary>
    internal delegate bool WriteTemplateEventHandler(Template template, Context context);
}
