# Nintendo Device Certificate Validator

This tool allows the identification and validation of a Device Certificate for Wii, 3DS, and Wii U.

## Installation

Compile using CMake:

```bash
mkdir build
cd build
cmake ..
make
```

## Usage
`./devicecert-validator cert.bin`

```
This is a 3DS certificate.

Signature type: ECDSA/SHA-256
Issuer ID:      Nintendo CA - G3_NintendoCTR2prod
Key type:       ECDSA
Key ID:         CTXXXXXXXX-00
Valid?          Yes
```

## To Do
- Add DSi support.

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to test against valid device certificates!
