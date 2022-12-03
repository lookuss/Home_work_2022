#include <iostream>
#include <string>
#include <vector>

#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rsa.h>

#define KEY_LENGTH 2048
#define PUB_EXP 3
#define PRINT_KEYS
#define WRITE_TO_FILE

uint32_t h1 = 0x67452301;
uint32_t h2 = 0xEFCDAB89;
uint32_t h3 = 0x98BADCFE;
uint32_t h4 = 0x10325476;
uint32_t h5 = 0xC3D2E1F0;

using namespace std;
#define BYTE_ROTATE_LEFT32(value, bits) (((value) << (bits)) | (((value)&0xffffffff) >> (32 - (bits))))
string input_message;

void padding()
{
    int ml = input_message.size() * 8;
    input_message += (char)0x80;

    while (input_message.size() % 64 != 64 - sizeof(ml))
    {
        input_message += (char)0x00;
    }

    for (int i = 7; i >= 0; i--)
    {
        char byte = (ml >> 8 * i) & 0xff;
        input_message += byte;
    }
}

vector<uint32_t> chunkToWords(string chunk)
{

    vector<uint32_t> words(16);
    for (int i = 0; i < 16; i++)
    {
        words[i] = (chunk[4 * i + 3] & 0xff) | (chunk[4 * i + 2] & 0xff) << 8 | (chunk[4 * i + 1] & 0xff) << 16 | (chunk[4 * i + 0] & 0xff) << 24;
    }
    return words;
}

void processChunk(int index)
{
    vector<uint32_t> words = chunkToWords(input_message.substr(index * 64, 64));

    uint32_t a = h1;
    uint32_t b = h2;
    uint32_t c = h3;
    uint32_t d = h4;
    uint32_t e = h5;

    for (int i = 16; i < 80; i++)
    {
        uint32_t w = words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i - 16];
        w = BYTE_ROTATE_LEFT32(w, 1);
        words.push_back(w);
    }

    for (int i = 0; i < 80; i++)
    {
        int f = 0;
        int k = 0;
        if (i < 20)
        {
            f = (b & c) | ((~b) & d);
            k = 0x5A827999;
        }
        else if (i < 40)
        {
            f = b ^ c ^ d;
            k = 0x6ED9EBA1;
        }
        else if (i < 60)
        {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8F1BBCDC;
        }
        else
        {
            f = b ^ c ^ d;
            k = 0xCA62C1D6;
        }

        uint32_t temp = BYTE_ROTATE_LEFT32(a, 5) + f + e + k + words[i];
        e = d;
        d = c;
        c = BYTE_ROTATE_LEFT32(b, 30);
        b = a;
        a = temp;
    }

    h1 += a;
    h2 += b;
    h3 += c;
    h4 += d;
    h5 += e;
}

string makePasswordForSha1(string password)
{
    padding();

    for (int i = 0; i < input_message.size() / 64; i++)
    {
        processChunk(i);
    }
    string passwordForSha1 = "";
    uint32_t arr[5] = {h1, h2, h3, h4, h5};
    char hexString[8];
    for (int i = 0; i < 5; i++)
    {
        sprintf(hexString, "%08x", arr[i]);
        passwordForSha1 += hexString;
    }

    return passwordForSha1;
}

void generateRSAkeyPair()
{
    cout << "Generating RSA" << KEY_LENGTH << "bits key pair..." << endl;
    int bits = 2048;

    BIGNUM *bn = BN_new();

    if (BN_set_word(bn, RSA_F4) != 1)
        throw "BN_set_word fail";

    RSA *rsa = RSA_new();

    if (RSA_generate_key_ex(rsa, bits, bn, NULL) != 1)
        throw "RSA_generate_key_ex fail";
}

int main(int argc, char const *argv[])
{

    cout << "Enter the password: ";
    cin >> input_message;

    string tmp = makePasswordForSha1(input_message);
    cout << "Password for SHA1: " << tmp << endl;
    return 0;
}
