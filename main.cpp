#include <array>
#include <cstdio>

#include "picosha2.h"

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

constexpr const u8 Q_WiiU[] =
{
    0x00, 0xfd, 0x56, 0x04, 0x18, 0x2c, 0xf1, 0x75, 0x09, 0x21,
    0x00, 0xc3, 0x08, 0xae, 0x48, 0x39, 0x91, 0x1b, 0x6f, 0x9f,
    0xa1, 0xd5, 0x3a, 0x95, 0xaf, 0x08, 0x33, 0x49, 0x47, 0x2b,
    0x00, 0x01, 0x71, 0x31, 0x69, 0xb5, 0x91, 0xff, 0xd3, 0x0c,
    0xbf, 0x73, 0xda, 0x76, 0x64, 0xba, 0x8d, 0x0d, 0xf9, 0x5b,
    0x4d, 0x11, 0x04, 0x44, 0x64, 0x35, 0xc0, 0xed, 0xa4, 0x2f
};

const char *getSignatureType(u32 type)
{
    switch ((reinterpret_cast<u8 *>(&type))[3])
    {
        case 0:  return "RSA-4096/SHA-1";
        case 1:  return "RSA-2048/SHA-1";
        case 2:  return "ECDSA/SHA-1";
        case 3:  return "RSA-4096/SHA-256";
        case 4:  return "RSA-2048/SHA-256";
        case 5:  return "ECDSA/SHA-256";
        default: return "Unknown";
    }
}

const char *getKeyType(u32 type)
{
    switch ((reinterpret_cast<u8 *>(&type))[3])
    {
        case 0:  return "RSA-4096";
        case 1:  return "RSA-2048";
        case 2:  return "ECDSA";
        default: return "Unknown";
    }
}

int main(int argc, char **argv)
{
    bool is3DS, valid;

    FILE *f;

    std::array<u8, CertLength> certFile;
    std::array<u8, CertLength - 0x80> certContents;
    std::array<u8, picosha2::k_digest_size> hash;

    if (argc != 2)
    {
        printf("Usage: %s cert.bin\n", argv[0]);
        return 0;
    }

    f = fopen(argv[1], "rb");

    if (f == nullptr)
    {
        perror("Error");
        return 1;
    }

    fread(certFile.data(), sizeof(u8), CertLength, f);
    fclose(f);

    memcpy(certContents.data(), certFile.data() + 0x80, CertLength - 0x80);

    picosha2::hash256(certContents, hash);

    is3DS = certContents[0] == 'N';

    printf("This is a %s certificate.\n\n", is3DS ? "3DS" : "Wii U");

    valid = check_ecdsa(const_cast<u8 *>(is3DS ? Q_3DS : Q_WiiU),
        certFile.data() + 4, certFile.data() + 4 + 30, hash.data());

    printf("Signature type: %s\n", getSignatureType(*reinterpret_cast<u32 *>(certFile.data())));
    printf("Issuer ID:      %s\n", certFile.data() + 0x80);
    printf("Key type:       %s\n", getKeyType(*reinterpret_cast<u32 *>(certFile.data() + 0xc0)));
    printf("Key ID:         %s\n", certFile.data() + 0xc4);
    printf("Valid?          %s\n", valid ? "Yes" : "No");

    return 0;
}
