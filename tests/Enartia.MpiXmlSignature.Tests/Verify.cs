using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using Xunit;

namespace Enartia.MpiXmlSignature.Tests
{
    public sealed class Verify
    {
        [Fact]
        public void Should_CorrectlyVerify_WhenXmlIsValid()
        {
            // Arrrange
            var inputXML = "<?xml version=\"1.0\"?><VPOS xmlns:ns2=\"http://www.w3.org/2000/09/xmldsig#\" " +
                "xmlns=\"http://www.modirum.com/schemas/vposxmlapi41\"><Message version=\"4.1\" messageId=\"M158" +
                "2725020764\" timeStamp=\"2020-02-26T15:50:20.7647754+02:00\"><TokenizationRequest id=\"TReq1582" +
                "725020764\"><Authentication><Mid>0020877775</Mid></Authentication><Card ref=\"TRef1582725020764\" " +
                "pan=\"4016001000027\" exp=\"2023-07-31\" chn=\"fdgdsgfdg\" /></TokenizationRequest></Message></VPOS>";

            var digitalSignature = new DigitalSignature();
            var xmlDocument = new XmlDocument();
            xmlDocument.LoadXml(inputXML);
            var certificate = new X509Certificate2(Path.Combine(Directory.GetCurrentDirectory(), "signingkey.pfx"), "0lqlt67mu4itvr4sj92k");
            var xmlSignatureSyntax = "http://www.modirum.com/schemas/vposxmlapi41";

            // Act
            var result = digitalSignature.SignXmlFile(xmlDocument, certificate, xmlSignatureSyntax);

            // Assert
            Assert.True(digitalSignature.VerifyXmlFile(result));
        }

        [Fact]
        public void Should_ThrowException_WhenXmlDocumentIsNull()
        {
            // Arrrange
            var digitalSignature = new DigitalSignature();
            var xmlDocument = default(XmlDocument);
            
            // Act / Assert
            var exception = Record.Exception(() => digitalSignature.VerifyXmlFile(xmlDocument));
            Assert.NotNull(exception);
            Assert.IsType<ArgumentException>(exception);
            Assert.Contains(exception.Message, "xmlDocument cannot be null. Please supply a valid xml document");
        }

        [Fact]
        public void Should_ThrowException_WhenXmlDocumentIsStringEmpty()
        {
            // Arrrange
            var digitalSignature = new DigitalSignature();
            var xmlDocument = string.Empty;

            // Act / Assert
            var exception = Record.Exception(() => digitalSignature.VerifyXmlFile(xmlDocument));
            Assert.NotNull(exception);
            Assert.IsType<ArgumentException>(exception);
            Assert.Contains(exception.Message, "xmlDocument cannot be null. Please supply a valid xml document");
        }
    }
}
