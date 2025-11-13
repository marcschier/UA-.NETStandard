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
    public class TemplateDefinition
    {
        /// <summary>
        /// The template composite string
        /// </summary>
        public string TemplateString { get; set; }

        /// <summary>
        /// The targets that the template should be applied to.
        /// </summary>
        public ICollection Targets { get; set; }

        /// <summary>
        /// The callback to call when loading the template.
        /// </summary>
        public event LoadTemplateEventHandler OnTemplateLoad
        {
            add => m_LoadTemplate += value;
            remove => m_LoadTemplate -= value;
        }

        /// <summary>
        /// The callback to call when writing the template.
        /// </summary>
        public event WriteTemplateEventHandler OnTemplateWrite
        {
            add => m_WriteTemplate += value;
            remove => m_WriteTemplate -= value;
        }

        /// <summary>
        /// Loads the template.
        /// </summary>
        public string Load(Template template, Context context)
        {
            // check for override.
            if (m_LoadTemplate != null)
            {
                return m_LoadTemplate(template, context);
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
            if (m_WriteTemplate != null)
            {
                return m_WriteTemplate(template, context);
            }

            // use the default function to write the template.
            return template.WriteTemplate(context);
        }

        private event LoadTemplateEventHandler m_LoadTemplate;
        private event WriteTemplateEventHandler m_WriteTemplate;
    }
}
