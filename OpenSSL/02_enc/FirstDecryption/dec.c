/**
 * You detected the following message
 * jyS3NIBqenyCWpDI2jkSu+z93NkDbWkUMitg2Q==
 * which has been encrypted with the program whose code is attached.
 * 
 * It has been generated with the following command line string
 * 
 * ./enc.exe file.txt 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF 11111111111111112222222222222222 file.enc openssl base64 -in file.enc
 * 
 * Write a program in C that decrypts the content and get the flag!
 */

#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/err.h>

#define ENCRYPT 1
#define DECRYPT 0


int main() {

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();


    unsigned  char key_i[] = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
    unsigned  char iv_i[] = "11111111111111112222222222222222";
    unsigned char ciphertext[] = "8F24B734806A7A7C825A90C8DA3912BBECFDDCD9036D6914322B60D9";

    unsigned char key[strlen(key_i)/2];
    for(int i = 0; i < strlen(key_i)/2; i++){
        sscanf(&key_i[2*i], "%2hhx", &key[i]); //converto la key hex_String in bin
    }

    unsigned char iv[strlen(iv_i)/2];
    for(int i = 0; i < strlen(iv_i)/2; i++){
        sscanf(&iv_i[2*i], "%2hhx", &iv[i]); //converto la IV hex_String in bin
    }

    /* Load the human-readable error strings for libcrypto */
    ERR_load_crypto_strings();
    /* Load all digest and cipher algorithms */
    OpenSSL_add_all_algorithms();

    EVP_CipherInit(ctx, EVP_chacha20(), key, iv, DECRYPT); //context initialize for encrypting with aes 128 in cbc mode

    unsigned char plaintext[strlen(ciphertext)/2];
    unsigned char ciphertext_bin[strlen(ciphertext)/2];

    for(int i=0; i < strlen(ciphertext)/2; i++){
        sscanf(&ciphertext[2*i], "%2hhx", &ciphertext_bin[i]); //converto il ciphertext da hex_String in bin
    }

    int length;
    int plaintext_len = 0;
    EVP_CipherUpdate(ctx, plaintext, &length, ciphertext_bin, strlen(ciphertext)/2);

    printf("After update: %d\n", length);
    plaintext_len += length;

    EVP_CipherFinal(ctx, plaintext+plaintext_len, &length); //ask to start not from the beginning of the plaintext but from plaintext_len, which is exactly the number of bytes processed before
    printf("After final: %d\n", length);
    plaintext_len += length;

    EVP_CIPHER_CTX_free(ctx);

    plaintext[plaintext_len]='\0';
    printf("Plaintext = %s\n", plaintext);

    return 0;
}