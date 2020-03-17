# mpi-xml-signatures
XML digital signing library, adhering to ModirumMPI specifications. 

### Prerequisites

Requires .NET Core 3.1

### Usage

#### General

MPI signature calculation is a multi step process. Basically the signature is calculated twice. The steps are:
1. Select Message attribute in xml document
2. Calculate Signature of Message data
3. Add Signature as a new node in original xml
4. Recalculate Signature of final xml
5. Append new signature in place of first one

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