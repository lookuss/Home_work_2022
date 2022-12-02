#include <iostream>
#include <string>
#include <vector>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

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

int main(int argc, char const *argv[])
{

    cout << "Enter the password: ";
    cin >> input_message;
    padding();

    for (int i = 0; i < input_message.size() / 64; i++)
    {
        processChunk(i);
    }

    cout << hex << h1 << h2 << h3 << h4 << h5 << endl;

    return 0;
}
