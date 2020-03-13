using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace Enartia.MpiXmlSignature
{
    public sealed class DigitalSignature
    {
        private const string NS2 = "http://www.w3.org/2000/09/xmldsig#";
        public string SignatureMethod { get; set; } = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
        public string DigestMethod { get; set; } = "http://www.w3.org/2001/04/xmlenc#sha256";
        public string CustomPrefix { get; set; } = "ds";
        public string MessageElementName {get; set; } = "Message";
        public string SignatureElementName {get; set; } = "Signature";
        public string SignatureValueElementName {get; set; } = "SignatureValue";

        public string SignXmlFile(XmlDocument xmlDocument, X509Certificate2 certificate, string xmlSignatureSyntax)
        {
            if (xmlDocument == null) 
            {
                throw new ArgumentException($"{nameof(xmlDocument)} cannot be null. Please supply a valid xml document");
            }
            if (certificate == null)
            {
                throw new ArgumentException($"{nameof(certificate)} cannot be null. Please supply a valid certificate");
            }
            if (string.IsNullOrWhiteSpace(xmlSignatureSyntax))
            {
                throw new ArgumentException($"{nameof(xmlSignatureSyntax)} cannot be null. Please supply a valid XmlSignatureSyntax");
            }

            // Load xml and set signing parameters
            var signedXml = new CustomIdSignedXml(xmlDocument);
            signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigC14NTransformUrl;
            signedXml.SignedInfo.SignatureMethod = SignatureMethod;
            signedXml.SigningKey = certificate.GetRSAPrivateKey(); ;

            // Set the namespases
            var nsmgr = new XmlNamespaceManager(xmlDocument.NameTable);
            nsmgr.AddNamespace("ns", xmlSignatureSyntax);
            nsmgr.AddNamespace("ns2", NS2);

            // Select message node for signing
            var reference = new Reference();
            reference.DigestMethod = DigestMethod;
            reference.Uri = "#" + xmlDocument.SelectSingleNode($"//ns:{MessageElementName}", nsmgr)
                .Attributes["messageId"].Value;
            signedXml.AddReference(reference);
            
            // Set signing key and sign xml data
            var keyInfo = new KeyInfo();
            keyInfo.AddClause(new KeyInfoX509Data(certificate));
            signedXml.KeyInfo = keyInfo;
            signedXml.ComputeSignature();
            
            // Get signature
            var xmlDigitalSignature = signedXml.GetXml();
            
            // Assign ds prefix
            AssignNameSpacePrefixToElementTree(xmlDigitalSignature, CustomPrefix);
            
            //load SignedInfo and compute final signature based on correct SignedInfo
            signedXml.LoadXml(xmlDigitalSignature);
            signedXml.SignedInfo.References.Clear();
            signedXml.ComputeSignature();
            
            // Replace signature
            ReplaceSignature(xmlDigitalSignature, Convert.ToBase64String(signedXml.SignatureValue));

            // Append signature to the xml doc
            xmlDocument.DocumentElement.AppendChild(xmlDocument.ImportNode(xmlDigitalSignature, true));
            
            using var stringWriter = new StringWriter();
            using var xmlTextWriter = new XmlTextWriter(stringWriter);
            xmlDocument.WriteTo(xmlTextWriter);
            xmlTextWriter.Flush();
            return stringWriter.ToString();
        }

        public bool VerifyXmlFile(string xmlDocument)
        {
            if (string.IsNullOrWhiteSpace(xmlDocument))
            {
                throw new ArgumentException($"{nameof(xmlDocument)} cannot be null. Please supply a valid xml document");
            }

            var xmldoc = new XmlDocument();
            xmldoc.PreserveWhitespace = true;
            xmldoc.LoadXml(xmlDocument);
            return VerifyXmlFile(xmldoc);
        }

        public bool VerifyXmlFile(XmlDocument xmlDocument)
        {
            if (xmlDocument == null)
            {
                throw new ArgumentException($"{nameof(xmlDocument)} cannot be null. Please supply a valid xml document");
            }

            var signedXml = new CustomIdSignedXml(xmlDocument);
            var nodeList = xmlDocument.GetElementsByTagName(SignatureElementName, NS2);
            var xmlDigitalSignature = (XmlElement)nodeList[0];

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
                {
                    AssignNameSpacePrefixToElementTree((XmlElement)child, prefix);
                }
            }
        }

        private void ReplaceSignature(XmlElement signature, string newValue)
        {
            if (signature == null)
            {
                throw new ArgumentNullException(nameof(signature));
            }
            if (signature.OwnerDocument == null)
            {
                throw new ArgumentException("No document owner", nameof(signature));
            } 

            var nsm = new XmlNamespaceManager(signature.OwnerDocument.NameTable);
            nsm.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);
            
            var signatureValueNodeName = $"{CustomPrefix}:{SignatureValueElementName}";
            var signatureValue = signature.SelectSingleNode(signatureValueNodeName, nsm);
            
            if (signatureValue == null)
            {
                throw new Exception($"Signature does not contain {signatureValueNodeName}");
            }

            signatureValue.InnerXml = newValue;
        }       
    }
}
