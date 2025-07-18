/**
 * A program performs the following operations:
 * generates two random strings (rand1 and rand2)
 * perform the bytewise OR of rand1 and rand2 and obtains k1
 * perform the bytewise AND of rand1 and rand2 and obtains k2
 * perform the bytewise XOR of k1 and k2 and obtains key
 * 
 * Write the program that implements the bytewise operations.
 * 
 * The flag will be the result (key) when the randomly generated strings are rand1 = ed-8a-3b-e8-17-68-38-78-f6-b1-77-3e-73-b3-f7-97-f3-00-47-76-54-ee-8d-51-0a-2f-10-79-17-f8-ea-d8-81-83-6e-0f-0c-b8-49-5a-77-ef-2d-62-b6-5e-e2-10-69-d6-cc-d6-a0-77-a2-0a-d3-f7-9f-a7-9e-a7-c9-08 rand2 = 4c-75-82-ca-02-07-bd-1d-8d-52-f0-6c-7a-d6-b7-87-83-95-06-2f-e0-f7-d4-24-f8-03-68-97-41-4c-85-29-e5-0d-b0-e4-3c-ee-74-dc-18-8a-aa-26-f0-46-94-e8-52-91-4a-43-8f-dd-ea-bb-a8-cf-51-14-79-ec-17-c2
 * 
 * It needs to be printed exactly in the same format as the random numbers (i.e., two hexdigits then a dash) and surrounded by CRYPTO25{}.
 */

#include <stdio.h>
#include <stdint.h>

#define MAX 64

const char *rand1 = "ed-8a-3b-e8-17-68-38-78-f6-b1-77-3e-73-b3-f7-97-f3-00-47-76-54-ee-8d-51-0a-2f-10-79-17-f8-ea-d8-81-83-6e-0f-0c-b8-49-5a-77-ef-2d-62-b6-5e-e2-10-69-d6-cc-d6-a0-77-a2-0a-d3-f7-9f-a7-9e-a7-c9-08";
const char *rand2 = "4c-75-82-ca-02-07-bd-1d-8d-52-f0-6c-7a-d6-b7-87-83-95-06-2f-e0-f7-d4-24-f8-03-68-97-41-4c-85-29-e5-0d-b0-e4-3c-ee-74-dc-18-8a-aa-26-f0-46-94-e8-52-91-4a-43-8f-dd-ea-bb-a8-cf-51-14-79-ec-17-c2";

void print_hex(unsigned char *arr, int len) {
    printf("CRYPTO25{");
    for (int i = 0; i < len; i++) {
        printf("%02x", arr[i]);
        if (i != len - 1) {
            printf("-");
        }
    }
    printf("}\n");
}

void hex_string_to_bytes(const char *hex_str, unsigned char *bytes) {
    int i;
    for (i = 0; i < MAX; i++) {
        sscanf(hex_str + (i * 3), "%2hhx", &bytes[i]);
    }
}

int main() {

    unsigned char rand1_bin[MAX], rand2_bin[MAX];
    unsigned char k1[MAX], k2[MAX], key[MAX];
    unsigned char key_hex[MAX*3+1];

    hex_string_to_bytes(rand1, rand1_bin); //convert hex strings to bytes array
    hex_string_to_bytes(rand2, rand2_bin);

    //bytewise operations
    for (int i=0; i < MAX; i++) {
        k1[i] = rand1_bin[i] | rand2_bin[i];  //OR
        k2[i] = rand1_bin[i] & rand2_bin[i];  //AND
        key[i] = k1[i] ^ k2[i];       //XOR
    }

    print_hex(key, MAX);

    return 0;
}
