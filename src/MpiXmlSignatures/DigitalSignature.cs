using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;


namespace MpiXmlSignatures
{
    public class DigitalSignature
    {
        public string SignatureMethod { get; set; } = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
        public string DigestMethod { get; set; } = "http://www.w3.org/2001/04/xmlenc#sha256";
        string ns2 = "http://www.w3.org/2000/09/xmldsig#";
        public string CustomPrefix { get; set; } = "ds";
        public string MessageElementName {get;set;}="Message";
        public string SignatureElementName {get;set;}="Signature";
        public string SignatureValueElementName {get;set;}="SignatureValue";
        public DigitalSignature()
        {

        }
        public DigitalSignature(string _SignatureMethod, string _DigestMethod)
        {
            SignatureMethod = _SignatureMethod;
            DigestMethod = _DigestMethod;
        }
        public string SignXmlFile(XmlDocument doc, X509Certificate2 cert, string ns)
        {
            KeyInfo keyInfo = new KeyInfo();
            keyInfo.AddClause(new KeyInfoX509Data(cert));

            RSA privateKeyProvider = cert.GetRSAPrivateKey();
            //load xml to SignedXml object
            SignedXml signedXml = new CustomIdSignedXml(doc);
            //set signing params
            signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigC14NTransformUrl;
            signedXml.SignedInfo.SignatureMethod = this.SignatureMethod;
            signedXml.SigningKey = privateKeyProvider;
            Reference reference = new Reference
            {
                DigestMethod = this.DigestMethod
            };
            //set namespaxes
            XmlNamespaceManager nsmgr = new XmlNamespaceManager(doc.NameTable);
            nsmgr.AddNamespace("ns", ns);
            nsmgr.AddNamespace("ns2", this.ns2);
            //select message node for signing
            reference.Uri = "#" + doc.SelectSingleNode("//ns:"+this.MessageElementName, nsmgr).Attributes[CustomIdSignedXml.idAttr].Value;
            XmlDsigEnvelopedSignatureTransform env = new XmlDsigEnvelopedSignatureTransform();
            signedXml.AddReference(reference);
            //set signing key and sign xml data
            signedXml.KeyInfo = keyInfo;
            signedXml.ComputeSignature();
            //get signature
            XmlElement xmlDigitalSignature = signedXml.GetXml();
            //assign ds prefix
            AssignNameSpacePrefixToElementTree(xmlDigitalSignature, this.CustomPrefix);
            //load SignedInfo and compute final signature based on correct SignedInfo
            signedXml.LoadXml(xmlDigitalSignature);
            signedXml.SignedInfo.References.Clear();
            signedXml.ComputeSignature();
            //convert to base64
            string recomputedSignature = Convert.ToBase64String(signedXml.SignatureValue);
            //replace it 
            ReplaceSignature(xmlDigitalSignature, recomputedSignature);
            //append it to xml doc
            doc.DocumentElement.AppendChild(doc.ImportNode(xmlDigitalSignature, true));
            using (StringWriter sw = new StringWriter())
            {
                using (XmlTextWriter tx = new XmlTextWriter(sw))
                {
                    doc.WriteTo(tx);
                    tx.Flush();
                    string strXmlText = sw.ToString();
                    return strXmlText;
                }
            }
        }
        public Boolean VerifyXmlFile(string xml)
        {
            XmlDocument xmldoc = new XmlDocument
            {
                PreserveWhitespace = true
            };
            xmldoc.LoadXml(xml);
            return VerifyXmlFile(xmldoc);
        }
        public Boolean VerifyXmlFile(XmlDocument xmlDocument)
        {
            SignedXml signedXml = new CustomIdSignedXml(xmlDocument);
            XmlNodeList nodeList = xmlDocument.GetElementsByTagName(this.SignatureElementName, this.ns2);
            XmlElement xmlDigitalSignature = (XmlElement)nodeList[0];
            if (xmlDigitalSignature == null)
            {
                return true;
            }
            signedXml.LoadXml(xmlDigitalSignature);

            // Check the signature and return the result.
            return signedXml.CheckSignature();
        }
        private void AssignNameSpacePrefixToElementTree(XmlElement element, string prefix)
        {
            element.Prefix = prefix;
            foreach (var child in element.ChildNodes)
            {
                if (child is XmlElement)
                    AssignNameSpacePrefixToElementTree(child as XmlElement, prefix);
            }
        }
        private void ReplaceSignature(XmlElement signature, string newValue)
        {
            if (signature == null) throw new ArgumentNullException(nameof(signature));
            if (signature.OwnerDocument == null) throw new ArgumentException("No owner document", nameof(signature));

            XmlNamespaceManager nsm = new XmlNamespaceManager(signature.OwnerDocument.NameTable);
            nsm.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);
            string signatureValueNodeName = this.CustomPrefix+":"+this.SignatureValueElementName;
            XmlNode signatureValue = signature.SelectSingleNode(signatureValueNodeName, nsm);
            if (signatureValue == null)
                throw new Exception("Signature does not contain "+signatureValueNodeName);

            signatureValue.InnerXml = newValue;
        }       
    }
    class CustomIdSignedXml : SignedXml
    {
        public static readonly string idAttr = "messageId";

        public CustomIdSignedXml(XmlDocument doc) : base(doc)
        {
            return;
        }

        public override XmlElement GetIdElement(XmlDocument doc, string id)
        {
            // check to see if it's a standard ID reference
            XmlElement idElem = base.GetIdElement(doc, id);
            if (idElem != null)
                return idElem;

            idElem = doc.SelectSingleNode("//*[@" + idAttr + "=\"" + id + "\"]") as XmlElement;

            return idElem;
        }
    }
}
