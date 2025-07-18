/**
 * Write a program in C that, using the OpenSSL library, encrypts the content of a file using a user-selected algorithm.
 * 
 * The input filename is passed as first parameter from the command line, key and IV are the second and third parameter, the output file is the fourth parameter, the algorithm is the last parameter.
 * 
 * The algorithm name must be an OpenSSL-compliant string (e.g., aes-128-cbc or aes-256-ecb). (In short, you have to extend enc4.c)
 * 
 * Look for the proper function here https://www.openssl.org/docs/man3.1/man3/EVP_EncryptInit.html
 * 
 * In doing the exercise you have found a very relevant function, build the flag as "CRYPTO25{" + relevantFunctionName + "}"
 */

#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/err.h>
//./enc4.exe fin.txt key IV fout.txt aes-128-cbc

#define ENCRYPT 1
#define DECRYPT 0
#define MAX_BUFFER 1024

void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}

int main(int argc, char **argv)
{

    if(argc != 6){ //controllo parametri
        fprintf(stderr,"Invalid parameters. Usage: %s file_in key iv file_out\n",argv[0]);
        exit(1);
    }


    FILE *f_in;
    if((f_in = fopen(argv[1],"r")) == NULL) {
            fprintf(stderr,"Couldn't open the input file, try again\n"); //controllo apertura f_in 
            abort();
    }
 
    if(strlen(argv[2])!=32){
        fprintf(stderr,"Wrong key length\n"); //controllo lunghezza chiave
        abort();
    }   
    if(strlen(argv[3])!=32){
        fprintf(stderr,"Wrong IV length\n"); //controllo lunghezza IV
        abort();
    }
    
    FILE *f_out;
    if((f_out = fopen(argv[4],"wb")) == NULL) {
            fprintf(stderr,"Couldn't open the output file, try again\n"); //controllo apertura f_out
            abort();
    }

    unsigned char key[strlen(argv[2])/2];
    for(int i = 0; i < strlen(argv[2])/2;i++){
        sscanf(&argv[2][2*i],"%2hhx", &key[i]); //converto la key da Hex a Bin
    }

    unsigned char iv[strlen(argv[3])/2];
    for(int i = 0; i < strlen(argv[3])/2;i++){
        sscanf(&argv[3][2*i],"%2hhx", &iv[i]); //converto l'IV da Hex a Bin
    }

    /* Load the human readable error strings for libcrypto */
    ERR_load_crypto_strings();
    /* Load all digest and cipher algorithms */
    OpenSSL_add_all_algorithms(); // deprecated since version 1.1.1



    // pedantic mode: check NULL
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    if(!EVP_CipherInit(ctx,EVP_get_cipherbyname(argv[5]), key, iv, ENCRYPT))
        handle_errors();

    int length;
    unsigned char ciphertext[MAX_BUFFER+16];

    int n_read;
    unsigned char buffer[MAX_BUFFER];

    while((n_read = fread(buffer,1,MAX_BUFFER,f_in)) > 0){
        printf("n_Read=%d-",n_read);
        if(!EVP_CipherUpdate(ctx,ciphertext,&length,buffer,n_read))
            handle_errors();
        printf("length=%d\n",length);
        if(fwrite(ciphertext, 1, length,f_out) < length){
            fprintf(stderr,"Error writing the output file\n");
            abort();
        }
    }
            
    if(!EVP_CipherFinal_ex(ctx,ciphertext,&length))
        handle_errors();

    printf("lenght=%d\n",length);

    if(fwrite(ciphertext,1, length, f_out) < length){
        fprintf(stderr,"Error writing in the output file\n"); //controllo scrittura f_out
        abort();
    }

    EVP_CIPHER_CTX_free(ctx);

    fclose(f_in);
    fclose(f_out);

    printf("File encrypted!\n");


    // completely free all the cipher data
    CRYPTO_cleanup_all_ex_data();
    /* Remove error strings */
    ERR_free_strings();

    return 0;
}

