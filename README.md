# Device Cert Validator
This tool prints info and validates a Device Certificate for either a 3DS CTCert or Wii U NG Cert. These certificates are sent to account.nintendo.net for user-verification.

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
