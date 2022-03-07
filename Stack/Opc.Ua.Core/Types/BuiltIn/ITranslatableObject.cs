/* Copyright (c) 1996-2020 The OPC Foundation. All rights reserved.
   The source code in this file is covered under a dual-license scenario:
     - RCL: for OPC Foundation members in good-standing
     - GPL V2: everybody else
   RCL license terms accompanied with this source code. See http://opcfoundation.org/License/RCL/1.00/
   GNU General Public License as published by the Free Software Foundation;
   version 2 of the License are accompanied with this source code. See http://opcfoundation.org/License/GPLv2
   This source code is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
*/

using System.Collections.Generic;

namespace Opc.Ua
{

    /// <summary>
    /// An interface to a object that provides translations.
    /// </summary>
    public interface ITranslationManager
    {

        /// <summary>
        /// Translates the LocalizedText using the information in the TranslationInfo property.
        /// </summary>
        LocalizedText Translate(IList<string> preferredLocales, LocalizedText text);

        /// <summary>
        /// Translates a service result.
        /// </summary>
        /// <param name="preferredLocales">The preferred locales.</param>
        /// <param name="result">The result.</param>
        /// <returns>The result with all localized text translated.</returns>
        /// <remarks>Recusively translates text in inner results.</remarks>
        ServiceResult Translate(IList<string> preferredLocales, ServiceResult result);
    }

    /// <summary>
    /// Stores the information requires to translate a string.
    /// </summary>
    public class TranslationInfo
    {

        /// <summary>
        /// Creates an empty object.
        /// </summary>
        public TranslationInfo()
        {
        }

        /// <summary>
        /// Creates an object from a key and a LocalizedText.
        /// </summary>
        public TranslationInfo(string key, LocalizedText text)
        {
            m_key = key;

            if (text != null)
            {
                m_text = text.Text;
                m_locale = text.Locale;
            }
        }

        /// <summary>
        /// Stores the arguments for uses with a SymbolicId that is used to look up default text.
        /// </summary>
        public TranslationInfo(System.Xml.XmlQualifiedName symbolicId, params object[] args)
        {
            m_key = symbolicId.ToString();
            m_locale = string.Empty;
            m_text = string.Empty;
            m_args = args;
        }

        /// <summary>
        /// Creates an object from a key and a text.
        /// </summary>
        public TranslationInfo(string key, string locale, string text)
        {
            m_key = key;
            m_locale = locale;
            m_text = text;
        }

        /// <summary>
        /// Creates an object from a key with text and format arguements.
        /// </summary>
        public TranslationInfo(string key, string locale, string format, params object[] args)
        {
            m_key = key;
            m_locale = locale;
            m_text = format;
            m_args = args;
        }



        /// <summary>
        /// The key used to look up translations.
        /// </summary>
        public string Key
        {
            get => m_key;
            set => m_key = value;
        }

        /// <summary>
        /// The default locale for the text.
        /// </summary>
        public string Locale
        {
            get => m_locale;
            set => m_locale = value;
        }

        /// <summary>
        /// The text to translate.
        /// </summary>
        public string Text
        {
            get => m_text;
            set => m_text = value;
        }

        /// <summary>
        /// The arguments that are used when formatting the text after translation.
        /// </summary>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1819:PropertiesShouldNotReturnArrays")]
        public object[] Args
        {
            get => m_args;
            set => m_args = value;
        }



        private string m_key;
        private string m_locale;
        private string m_text;
        private object[] m_args;

    }

}
