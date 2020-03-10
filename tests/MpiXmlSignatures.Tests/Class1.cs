using System;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using Xunit;

namespace MpiXmlSignatures.Tests
{
    public class Class1
    {
        [Fact]
        public void Should_CorrectlyParseXml()
        {

            string inputXML = "<?xml version=\"1.0\"?><VPOS xmlns:ns2=\"http://www.w3.org/2000/09/xmldsig#\" xmlns=\"http://www.modirum.com/schemas/vposxmlapi41\"><Message version=\"4.1\" messageId=\"M1582725020764\" timeStamp=\"2020-02-26T15:50:20.7647754+02:00\"><TokenizationRequest id=\"TReq1582725020764\"><Authentication><Mid>0020877775</Mid></Authentication><Card ref=\"TRef1582725020764\" pan=\"4016001000027\" exp=\"2023-07-31\" chn=\"fdgdsgfdg\" /></TokenizationRequest></Message></VPOS>";

            DigitalSignature digitalSignature = new DigitalSignature();
            XmlDocument doc = new XmlDocument();
            doc.LoadXml(inputXML);           
            var cert = new X509Certificate2(System.IO.Directory.GetCurrentDirectory() + "\\signingkey.pfx", "0lqlt67mu4itvr4sj92k");
            var result = digitalSignature.SignXmlFile(doc, cert, "http://www.modirum.com/schemas/vposxmlapi41");
            var expectedSigned = "<?xml version=\"1.0\"?><VPOS xmlns:ns2=\"http://www.w3.org/2000/09/xmldsig#\" xmlns=\"http://www.modirum.com/schemas/vposxmlapi41\"><Message version=\"4.1\" messageId=\"M1582725020764\" timeStamp=\"2020-02-26T15:50:20.7647754+02:00\"><TokenizationRequest id=\"TReq1582725020764\"><Authentication><Mid>0020877775</Mid></Authentication><Card ref=\"TRef1582725020764\" pan=\"4016001000027\" exp=\"2023-07-31\" chn=\"fdgdsgfdg\" /></TokenizationRequest></Message><ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\" /><ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\" /><ds:Reference URI=\"#M1582725020764\"><ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\" /><ds:DigestValue>CIKt5+8T5Hm0weJNrpprT1/7czI1SYGrrd+vRtjYj3s=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>KfngJ/JqOnCPXBEtVVoR/r8bbxwV/L2LWEcE36rdebJxr1cYxIMBvhum/9XUvzQN9ZMNMzYfy0t+hJZx5RdpVHSxuvFFAyzL1clsPUQ8MbdmZpwk9Q5o+1HEyX1UFE4t3KYibFfLEO1IG7k69SqQgAuCS6+Hx5KGfqIqafCw333b+6Cbl5aDIXR5KX9dTGnOREV0bEQTDCZLsPSCN+RT5syqcVqJ0Dp8CL7CM1g8ulp7SjPXumuN9ap7rnaH4YUMzpUDE/SFOf46fzm7fg9X+0r47TLFyHqw9SgER49DZhx+6aiwr6KUKIcoIbLwMH308II3ChBUBxSmUihsnS3N/w==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDwzCCAqugAwIBAgIUT3t3LqjrAR6e2oJm1Oj+wCKnEaowDQYJKoZIhvcNAQELBQAwcTELMAkGA1UEBhMCR1IxDjAMBgNVBAgMBUNyZXRlMRIwEAYDVQQHDAlIZXJha2xpb24xDzANBgNVBAoMBlBhcGFraTEUMBIGA1UECwwLRW5naW5lZXJpbmcxFzAVBgNVBAMMDnd3dy5wYXBha2kuY29tMB4XDTIwMDMxMDA3MDkxNFoXDTI0MDMwOTA3MDkxNFowcTELMAkGA1UEBhMCR1IxDjAMBgNVBAgMBUNyZXRlMRIwEAYDVQQHDAlIZXJha2xpb24xDzANBgNVBAoMBlBhcGFraTEUMBIGA1UECwwLRW5naW5lZXJpbmcxFzAVBgNVBAMMDnd3dy5wYXBha2kuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3oTdIJBlEZne04q4MLL7fKYvY9CNC3SleZk4W/jij1mYB9fhpHUa5r2sOhAAuKmSCYdp2Ul6T3ZQm2zgtJLEc88uqqzdpfFec0m3SeKAhFa7dlmFz+UPv3NTRzM9QRa/+v8HsrwBTwuPU9bhbOVSzLL7mC4jjN8kjCwxufR3d8eZjDxJ20qOEfyjbK4ApMB6mFUDrOqg5CeZ1YPXffDVfCCGUH7CUXZAHF3TgLZ9ZiMf3uJFG9E9kX1ddhRNRcCrP6s238XL7vqo1DZFnVZlYMd0R46y0t6kEWloOA7Mc/8S5+7g1QKtP72im8Z7APWxCYAikGLf5h4fnBcOvkWahQIDAQABo1MwUTAdBgNVHQ4EFgQUCIUI2j0VkbL0VuRiMqgH1GMFXWMwHwYDVR0jBBgwFoAUCIUI2j0VkbL0VuRiMqgH1GMFXWMwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEABtJgjKdnWQWTw1Xl5AdOq86m4CZ2DBdCwUBAXnYxlvK5VrpKcfsIECLNgZTXjXzrBFmuis9VotiZKhZWltHPZQltYbjr27iP4sdN15qDkSyBAQ03eCpE3megpx7fb/qzU1IgCfkwxR2iSfp/+0TX6xdTw7Yq+uJQJH9Um0olhiuq0+iPfEEWh+zniNjSoZjk+I/gha7l22O5OzTDSJvbB3QzqjC4KiviSol/8m7V7BI57zlCYJOqHJnkuHH8JpXwcQ37kdrSBb3utMoSoMEI2e4A9KWcpWJVoGRI0DkKJaExSH+kWzCg2u7PJc0V6w5M1INtqyF6K8bWRgE7OCI1Ag==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature></VPOS>";
            Assert.Equal(result, expectedSigned);
        }


    }
}
