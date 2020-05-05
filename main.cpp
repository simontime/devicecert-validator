#include <array>
#include <cstdio>

#include "picosha2.h"
#include "TinySHA1.hpp"

extern "C"
{
#include "ec.h"
}

constexpr const int CertLength = 0x180;

constexpr const u8 Q_3DS[] = 
{
    0x00, 0x4e, 0x3b, 0xb7, 0x4d, 0x5d, 0x95, 0x9e, 0x68, 0xce,
    0x90, 0x04, 0x34, 0xfe, 0x9e, 0x4a, 0x3f, 0x09, 0x4a, 0x33,
    0x77, 0x1f, 0xa7, 0xc0, 0xe4, 0xb0, 0x23, 0x26, 0x4d, 0x98,
    0x01, 0x4c, 0xa1, 0xfc, 0x79, 0x9d, 0x3f, 0xa5, 0x21, 0x71,
    0xd5, 0xf9, 0xbd, 0x5b, 0x17, 0x77, 0xec, 0x0f, 0xef, 0x7a,
    0x38, 0xd1, 0x66, 0x9b, 0xbf, 0x83, 0x03, 0x25, 0x84, 0x3a
};

// Wii shares its public key with Wii U.
constexpr const u8 Q_WiiU[] =
{
    0x00, 0xfd, 0x56, 0x04, 0x18, 0x2c, 0xf1, 0x75, 0x09, 0x21,
    0x00, 0xc3, 0x08, 0xae, 0x48, 0x39, 0x91, 0x1b, 0x6f, 0x9f,
    0xa1, 0xd5, 0x3a, 0x95, 0xaf, 0x08, 0x33, 0x49, 0x47, 0x2b,
    0x00, 0x01, 0x71, 0x31, 0x69, 0xb5, 0x91, 0xff, 0xd3, 0x0c,
    0xbf, 0x73, 0xda, 0x76, 0x64, 0xba, 0x8d, 0x0d, 0xf9, 0x5b,
    0x4d, 0x11, 0x04, 0x44, 0x64, 0x35, 0xc0, 0xed, 0xa4, 0x2f
};

constexpr const char *signatureTypes[] = 
{
    "RSA-4096/SHA-1",
    "RSA-2048/SHA-1",
    "ECDSA/SHA-1",
    "RSA-4096/SHA-256",
    "RSA-2048/SHA-256",
    "ECDSA/SHA-256"
};

constexpr const char *keyTypes[] = 
{
    "RSA-4096",
    "RSA-2048",
    "ECDSA"
};

constexpr const char *console3DS  = "3DS";
constexpr const char *consoleWii  = "Wii";
constexpr const char *consoleWiiU = "Wii U";

const char *getConsoleName(const char *issuer)
{
    if (!strcmp(issuer, "Nintendo CA - G3_NintendoCTR2prod"))
        return console3DS;
    else if (!strcmp(issuer, "Root-CA00000001-MS00000002"))
        return consoleWii;
    else if (!strcmp(issuer, "Root-CA00000003-MS00000012"))
        return consoleWiiU;
    else
        return "Unknown";
}

bool verifySignature_ECDSA_SHA1(u8 *cert, bool is3DS)
{
    sha1::SHA1 s;
    u8 hash[20];

    s.processBytes(cert + 0x80, CertLength - 0x80);
    s.getDigestBytes(hash);

    return check_ecdsa(const_cast<u8 *>(is3DS ? Q_3DS : Q_WiiU),
        cert + 4, cert + 4 + 30, hash, false);
}

bool verifySignature_ECDSA_SHA256(u8 *cert, bool is3DS)
{
    std::array<u8, CertLength - 0x80> certContents;
    std::array<u8, picosha2::k_digest_size> hash;

    memcpy(certContents.data(), cert + 0x80, CertLength - 0x80);
    picosha2::hash256(certContents, hash);

    return check_ecdsa(const_cast<u8 *>(is3DS ? Q_3DS : Q_WiiU),
        cert + 4, cert + 4 + 30, hash.data(), true);
}

bool (*verifySignatureFuncs[6])(u8 *cert, bool is3DS) = 
{
    nullptr,
    nullptr,
    &verifySignature_ECDSA_SHA1,
    nullptr,
    nullptr,
    &verifySignature_ECDSA_SHA256
};

int main(int argc, char **argv)
{
    const char *console;
    FILE *f;
    std::array<u8, CertLength> certFile;

    if (argc != 2)
    {
        printf("Usage: %s cert.bin\n", argv[0]);
        return 0;
    }

    if ((f = fopen(argv[1], "rb")) == nullptr)
    {
        perror("Error");
        return 1;
    }

    fread(certFile.data(), sizeof(u8), CertLength, f);
    fclose(f);

    console = getConsoleName(reinterpret_cast<char *>(certFile.data()) + 0x80);

    printf("This is a %s certificate.\n\n", console);

    printf("Signature type: %s\n", signatureTypes[certFile.data()[3]]);
    printf("Issuer ID:      %s\n", certFile.data() + 0x80);
    printf("Key type:       %s\n", keyTypes[certFile.data()[0xc3]]);
    printf("Key ID:         %s\n", certFile.data() + 0xc4);
    printf("Valid?          %s\n",
        verifySignatureFuncs[certFile.data()[3]](certFile.data(), console == console3DS) ?
        "Yes" : "No");

    return 0;
}