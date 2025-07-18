/**
 * Write a program that computes the HMAC-SHA256 of two files whose names are passed as parameters from the command line (start from HMAC_computation_EVP).
 * 
 * The flag is obtained as CRYPTO25{hmac}
 * 
 * where hmac is obtained using the secret "keykeykeykeykeykey" and the two files attached to this challenge (and hexdigits in lowercase):
 * 
 * hmac = hex(HMAC-SHA256("keykeykeykeykeykey", file,file2))
 * 
 * where "keykeykeykeykeykey" is an ASCII string (no quotation marks)
 */

#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/err.h>
#include <string.h>
//./HMAC_computation_EVP.exe file.txt file2.txt

#define MAXBUF 1024

void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}

int main(int argc, char **argv){
       
    unsigned char key[] = "keykeykeykeykeykey";
    
    if(argc != 3){
        fprintf(stderr,"Invalid parameters. Usage: %s filename\n",argv[0]); //controllo numero parametri
        exit(1);
    }


    FILE *f_in1, *f_in2;
    if((f_in1 = fopen(argv[1],"r")) == NULL) {
            fprintf(stderr,"Couldn't open the input file, try again\n"); //controllo apertura file.txt
            exit(1);
    }
    if((f_in2 = fopen(argv[2],"r")) == NULL) {
        fprintf(stderr,"Couldn't open the input file, try again\n"); //controllo apertura file2.txt
        exit(1);
    }

    EVP_MD_CTX  *hmac_ctx = EVP_MD_CTX_new();

    EVP_PKEY *hkey;
    hkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, key, 18); //creo nuova hmac key

    if(!EVP_DigestSignInit(hmac_ctx, NULL, EVP_sha256(), NULL, hkey)) //inizializzo il context con SHA-256
        handle_errors();

    size_t n;
    unsigned char buffer[MAXBUF];
    while((n = fread(buffer,1,MAXBUF,f_in1)) > 0){
    // Returns 1 for success and 0 for failure.
        if(!EVP_DigestSignUpdate(hmac_ctx, buffer, n)) //aggiorno il digest context con file.txt
            handle_errors();
    }
    while((n = fread(buffer,1,MAXBUF,f_in2)) > 0){
        // Returns 1 for success and 0 for failure.
            if(!EVP_DigestSignUpdate(hmac_ctx, buffer, n)) //aggiorno il digest context con file2.txt
                handle_errors();
        }

    unsigned char hmac_value[EVP_MD_size(EVP_sha256())];
    size_t hmac_len = EVP_MD_size(EVP_sha256());

    if(!EVP_DigestSignFinal(hmac_ctx, hmac_value, &hmac_len)) //genero l'HMAC_value e l'HMAC_length dal context
        handle_errors();

    EVP_MD_CTX_free(hmac_ctx);

    printf("CRYPTO25{");
    for(int i = 0; i < hmac_len; i++)
                printf("%02x", hmac_value[i]); //visualizzo l'HMAC_value
    printf("}\n");


	return 0;

}