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
using System.Collections;
using Opc.Ua.SourceGeneration;

namespace Opc.Ua
{
    internal static class TemplateExtensions
    {
        /// <summary>
        /// Initializes a template to use for substitution.
        /// </summary>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="template"/> is <c>null</c>.
        /// </exception>
        public static void AddTemplate(
            this Template template,
            string replacement,
            string templatePath,
            IEnumerable targets,
            LoadTemplateEventHandler onLoad,
            WriteTemplateEventHandler onWrite)
        {
            if (template == null)
            {
                throw new ArgumentNullException(nameof(template));
            }
            template.Replacements.Add(replacement, null);

            // create a collection of targets.
            var targetList = new ArrayList();

            if (targets != null)
            {
                foreach (object target in targets)
                {
                    targetList.Add(target);
                }
            }

            var definition = new TemplateDefinition
            {
                TemplateString = templatePath,
                Targets = targetList
            };

            if (onLoad != null)
            {
                definition.OnTemplateLoad += onLoad;
            }

            if (onWrite != null)
            {
                definition.OnTemplateWrite += onWrite;
            }

            template.Templates.Add(replacement, definition);
        }
    }
}
