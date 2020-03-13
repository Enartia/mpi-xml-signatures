# mpi-xml-signatures
XML digital signing library, adhering to ModirumMPI specifications. 

### Prerequisites

Requires .NET Core 3.1

### Usage

#### Create
```
var digitalSignature = new DigitalSignature();
var result = digitalSignature.SignXmlFile(xmlDocument, certificate, xmlSignatureSyntax);
```            
#### Verify

```
var digitalSignature = new DigitalSignature();
var result = digitalSignature.VerifyXmlFile(xmlDocument);
``` 

## Running the tests

Navigate to tests folder and run dotnet test.

## Author

[Enartia](https://github.com/Enartia)

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details