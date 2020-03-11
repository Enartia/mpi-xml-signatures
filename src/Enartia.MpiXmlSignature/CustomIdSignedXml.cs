using System.Security.Cryptography.Xml;
using System.Xml;

namespace Enartia.MpiXmlSignature
{
    public sealed class CustomIdSignedXml : SignedXml
    {
        public CustomIdSignedXml(XmlDocument doc) : base(doc) { }

        public override XmlElement GetIdElement(XmlDocument doc, string id) => 
            base.GetIdElement(doc, id) ?? doc.SelectSingleNode($"//*[@messageId=\"{id}\"]") as XmlElement;
    }
}