/**
 * Given the secret (represented as a C variable)
 * 
 * unsigned char secret[] = "this_is_my_secret";
 * 
 * Write a program in C that computes the keyed digest as
 * 
 * kd = SHA512 ( secret || input_file || secret)
 * 
 * where || indicates the concatenation (without adding any space characters)
 * hex computes the representation as an hexstring
 * 
 * Surround with CRYPTO25{hex(kd)} to obtain the flag.
 * 
 * HINT: start from hash3.c or hash4.c
 */

#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>

#define MAXBUF 1024

long count_file_length(FILE *fp) {

    fseek(fp, 0, SEEK_END);  // Posiziona il puntatore alla fine
    long length = ftell(fp); // Ottiene la posizione del puntatore (che è la lunghezza del file)
    fseek(fp, 0, SEEK_SET); // Ripristina il puntatore all'inizio

    return length;
}

int main(int argc, char **argv){

    unsigned char secret[] = "this_is_my_secret";
    int n_secret = strlen(secret);
      
        if(argc != 2){
            fprintf(stderr,"Invalid parameters. Usage: %s filename\n",argv[0]); //controllo numero parametri
            exit(1);
        }


        FILE *f_in;
        if((f_in = fopen(argv[1],"r")) == NULL) {
                fprintf(stderr,"Couldn't open the input file, try again\n"); //controllo apertura file.txt
                exit(1);
        }
        int n_file = count_file_length(f_in); //conto la lunghezza del file


		EVP_MD_CTX *md = EVP_MD_CTX_new(); //creo un nuovo context

        EVP_DigestInit(md, EVP_sha512()); //inizializzo il context con SHA-512

        int n;
        unsigned char buffer[MAXBUF];
        int length = n_secret*2 + n_file; //lunghezza sarà lunghezza secret (x2) + lunghezza file
        unsigned char message[length];
        strcpy(message, secret); //aggiungo al messaggio il secret (primo)
        while((n = fread(buffer,1,MAXBUF,f_in)) > 0){
            strcat(message, buffer); //aggiungo al messaggio il contenuto del file file.txt
        }
        strcat(message, secret); //aggiungo al messaggio il secret (secondo)
        EVP_DigestUpdate(md, message, strlen(message)); //aggiorno il context del digest col messaggio

        unsigned char md_value[EVP_MD_size(EVP_sha512())];
        int md_len;

        EVP_DigestFinal_ex(md, md_value, &md_len); //genero il digest value e il digest length

		EVP_MD_CTX_free(md);

        printf("CRYPTO25{");
        for(int i = 0; i < md_len; i++)
			     printf("%02x", md_value[i]); //visaulizzo il digest value
        printf("}\n");

	return 0;

}