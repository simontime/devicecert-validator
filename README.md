# Nintendo Device Cert Validator

This tool can identify and validate a Wii, Wii U, or 3DS Device Certificate.

On all devices, these certs are used by the relevant shop channels (Wii Shop, or eShop) to sign tickets (and TMDs? maybe not) uniquely to your device, making it impossible to install on other device.

On WiiU/3DS, these certs are also sent as part of the console-unique data to account.nintendo.net

On Wii, these certificates are used to sign save-games so that only valid Wii saves can be installed on others' consoles (savezelda etc gets around this by using a shared cert)

Usage: `./devicecert-validator cert.bin`

Build with CMake - `mkdir build && cd build && cmake .. && make`

```
This is a 3DS certificate.

Signature type: ECDSA/SHA-256
Issuer ID:      Nintendo CA - G3_NintendoCTR2prod
Key type:       ECDSA
Key ID:         CTXXXXXXXX-00
Valid?          Yes
```

```
This is a Wii U certificate.

Signature type: ECDSA/SHA-256
Issuer ID:      Root-CA00000003-MS00000012
Key type:       ECDSA
Key ID:         NGXXXXXXXX
Valid?          Yes
```
