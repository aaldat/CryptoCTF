/**
 * You sniffed the following Base64 string
 * ZZJ+BKJNdpXA2jaX8Zg5ItRola18hi95MG8fA/9RPvg=
 * 
 * You know it is an encrypted payload that has been ciphered with these parameters: key = "0123456789ABCDEF" iv = "0123456789ABCDEF" (Note: key and iv are not to be taken as hex strings)
 * 
 * Write a program (based for instance on dec1.c or a modification of enc4.c) to decrypt it and obtain decryptedcontent.
 * 
 * Then, take note of the following instruction in your decryption program if(!EVP_CipherInit(ctx,algorithm_name(), key, iv, ENCRYPT))
 * 
 * When you succeed, build the flag in this way (Python-style string concatenation)
 * 
 * "CRYPTO25{" + decryptedcontent + algorithm_name + "}"
 */


#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/err.h>

#define ENCRYPT 1
#define DECRYPT 0

void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}


int main() {

    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();


    unsigned  char key[] = "0123456789ABCDEF"; //16 bytes, ASCII characters
    unsigned  char iv[] = "0123456789ABCDEF"; //16 bytes, ASCII characters
    unsigned char ciphertext[] = "65927E04A24D7695C0DA3697F1983922D46895AD7C862F79306F1F03FF513EF8";


    if(!EVP_CipherInit(ctx, EVP_aria_128_cbc(), key, iv, DECRYPT)){ //context initialize for encrypting with aria 128 in cbc mode
        handle_errors();
    }
    //EVP_CIPHER_CTX_set_padding(ctx,0);
    unsigned char plaintext[strlen(ciphertext)/2];
    unsigned char ciphertext_bin[strlen(ciphertext)/2];

    for(int i=0; i < strlen(ciphertext)/2; i++){
        sscanf(&ciphertext[2*i], "%2hhx", &ciphertext_bin[i]); //converto il ciphertext da Hex a Bin
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
    printf("CRYPTO25{%sEVP_aria_128_cbc}\n", plaintext);

    //completely free all the cipher data
    CRYPTO_cleanup_all_ex_data();
    //Remove error strings
    ERR_free_strings();

    return 0;
}