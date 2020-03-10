# mpi-xml-signatures
XML digital signing library, adhering to ModirumMPI specifications. 

### Prerequisites

Runs on C# .NET Core 3.1

### Installing

tba

### Usage

```
DigitalSignature digitalSignature = new DigitalSignature();
XmlDocument doc = new XmlDocument();
doc.LoadXml(inputXML);           
var cert = new X509Certificate2(<signing key path>, <signing key password>);
var result = digitalSignature.SignXmlFile(doc, cert, "http://www.modirum.com/schemas/vposxmlapi41");
```            

## Running the tests

Navigate to tests folder and run dotnet test for each project.

## Authors

* **George Georgopoulos** - [Enartia](https://github.com/Enartia)

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details