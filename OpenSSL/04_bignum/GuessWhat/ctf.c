/**
 * You have found these data
 * 
 * 00:9e:ee:82:dc:2c:d4:a0:0c:4f:5a:7b:86:63:b0:c1:ed:06:77:fc:eb:de:1a:23:5d:f4:c3:ff:87:6a:7d:ad:c6:07:fa:a8:35:f6:ae:05:03:57:3e:22:36:76:d5:0d:57:4f:99:f9:58:ad:63:7a:e7:45:a6:aa:fa:02:34:23:b6:9d:34:15:7b:11:41:b6:b1:ca:b9:1a:cd:29:55:bd:42:f5:04:ab:df:45:4a:9d:4e:ca:4e:01:f9:f8:74:59:67:ee:b6:a9:fb:96:b7:c0:94:00:17:8a:53:0e:b6:d8:31:c9:68:e6:64:38:d3:63:3a:04:d7:88:6b:f0:e1:ad:60:7f:41:bd:85:7b:d9:04:e1:97:5b:1f:9b:05:ce:ac:2c:c4:55:3f:b4:8b:89:4d:0a:50:9a:09:4e:5e:8f:5b:5f:55:69:72:5f:04:9b:3a:8a:09:b4:7f:8d:b2:ca:52:0e:5e:bf:f4:b0:ee:c9:ba:dc:93:4f:6d:d3:1f:82:1a:d9:fc:2c:a7:3f:18:23:0d:d7:44:c7:28:54:67:84:ee:73:92:65:f0:1c:e8:1e:6d:4d:95:65:b4:c8:4f:b8:04:62:58:2b:ee:32:64:a0:a7:dc:99:25:0e:50:53:76:bc:30:db:71:5e:93:d6:9f:1f:88:1c:76:5d:82:c8:59:39:51
 * 
 * 00:d2:c6:01:32:6b:4c:4b:85:5f:52:7b:b7:8e:d6:8a:e4:c8:76:7e:6b:c9:24:9a:3e:ca:cd:2f:c9:b8:75:d4:f9:71:11:e1:cf:be:62:d3:2c:5f:f9:fd:9b:fa:ed:62:f3:df:44:c7:57:fb:ee:9b:b2:32:cb:54:49:29:6c:69:2e:30:1d:8c:1f:fa:b1:8e:e4:49:66:c1:fb:92:7c:82:ca:60:c9:40:a4:0a:b2:db:50:ec:f6:ff:98:a7:16:23:38:8d:06:d2:7c:a9:85:8a:c2:2b:4d:d4:e6:f1:89:e5:b0:42:54:a0:5f:3c:dd:c7:64:33:05:11:fb:ee:8b:26:07
 * 
 * Find the other missing parameter using BIGNUM primitives (you may have to manipulate these data a bit before).
 * 
 * Use the same representation (with a ':' every two digits). Surround it with CRYPTO25{} to have your flag. Add leading zeros if needed to equalize parameters...
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <openssl/bn.h>

int countColon(unsigned char *string){
    char c;
    int count=0;
    for(int i=0; i<strlen(string); i++){
        c = string[i];
        if(c==':'){
            count++;
        }
    }
    return count;
}

unsigned char* pad_hex_string(const char *hex_str, int target_len) {
    int current_len = strlen(hex_str);
    int i=0;
    if (current_len >= target_len) {
        // If no padding is required, just return a copy of the original string
        return strdup(hex_str);
    }

    // Allocate a new buffer for the padded string
    char *padded_hex = (char *)malloc(sizeof(char)*target_len);
    if (!padded_hex) {
        printf("Memory allocation failed.\n");
        exit(1);
    }

    // Fill the beginning of the padded string with '0's
    for(i=0; i<current_len; i++){
        padded_hex[target_len-1-i] = hex_str[target_len-1-i];
    }
    for(i=0; i<target_len-current_len; i++){
        padded_hex[target_len-current_len-1-i] = '0';
    }

    // Copy the original hex string after the padding
    strcpy(padded_hex + (target_len - current_len), hex_str);

    return padded_hex;  // Return the newly padded hex string
}

unsigned char *hexColonless(unsigned char *string, int hexlen){
    unsigned char *hexn = (unsigned char *)malloc(hexlen * sizeof(unsigned char));
    if (hexn == NULL) {
        printf("Memory allocation failed.\n");
        exit(1);  // Handle memory allocation failure
    }
    
    int j=0;
    int i=0;
    for(i=0; i<strlen(string); i++){
        if (string[i] != ':') {
            hexn[j++] = string[i];
        }
    }
    hexn[i]='\0';
    return hexn;
}

void format_with_colons(const char *hex, char *output) {
    int len = strlen(hex);
    int j = 0;
    for (int i = 0; i < len; i++) {
        output[j++] = hex[i];
        if (i % 2 == 1 && i != len - 1) {
            output[j++] = ':';
        }
    }
    output[j] = '\0';
}


int main() {
    unsigned char hex1[] = "00:9e:ee:82:dc:2c:d4:a0:0c:4f:5a:7b:86:63:b0:c1:ed:06:77:fc:eb:de:1a:23:5d:f4:c3:ff:87:6a:7d:ad:c6:07:fa:a8:35:f6:ae:05:03:57:3e:22:36:76:d5:0d:57:4f:99:f9:58:ad:63:7a:e7:45:a6:aa:fa:02:34:23:b6:9d:34:15:7b:11:41:b6:b1:ca:b9:1a:cd:29:55:bd:42:f5:04:ab:df:45:4a:9d:4e:ca:4e:01:f9:f8:74:59:67:ee:b6:a9:fb:96:b7:c0:94:00:17:8a:53:0e:b6:d8:31:c9:68:e6:64:38:d3:63:3a:04:d7:88:6b:f0:e1:ad:60:7f:41:bd:85:7b:d9:04:e1:97:5b:1f:9b:05:ce:ac:2c:c4:55:3f:b4:8b:89:4d:0a:50:9a:09:4e:5e:8f:5b:5f:55:69:72:5f:04:9b:3a:8a:09:b4:7f:8d:b2:ca:52:0e:5e:bf:f4:b0:ee:c9:ba:dc:93:4f:6d:d3:1f:82:1a:d9:fc:2c:a7:3f:18:23:0d:d7:44:c7:28:54:67:84:ee:73:92:65:f0:1c:e8:1e:6d:4d:95:65:b4:c8:4f:b8:04:62:58:2b:ee:32:64:a0:a7:dc:99:25:0e:50:53:76:bc:30:db:71:5e:93:d6:9f:1f:88:1c:76:5d:82:c8:59:39:51";
    unsigned char hex2[] = "00:d2:c6:01:32:6b:4c:4b:85:5f:52:7b:b7:8e:d6:8a:e4:c8:76:7e:6b:c9:24:9a:3e:ca:cd:2f:c9:b8:75:d4:f9:71:11:e1:cf:be:62:d3:2c:5f:f9:fd:9b:fa:ed:62:f3:df:44:c7:57:fb:ee:9b:b2:32:cb:54:49:29:6c:69:2e:30:1d:8c:1f:fa:b1:8e:e4:49:66:c1:fb:92:7c:82:ca:60:c9:40:a4:0a:b2:db:50:ec:f6:ff:98:a7:16:23:38:8d:06:d2:7c:a9:85:8a:c2:2b:4d:d4:e6:f1:89:e5:b0:42:54:a0:5f:3c:dd:c7:64:33:05:11:fb:ee:8b:26:07";
    
    int hex1col = countColon(hex1);
    unsigned char hex1n[strlen(hex1)-hex1col];
    strcpy(hex1n, hexColonless(hex1, strlen(hex1)-hex1col));

    int hex2col = countColon(hex2);
    unsigned char hex2n[strlen(hex2)-hex2col];
    strcpy(hex2n, hexColonless(hex2, strlen(hex2)-hex2col));

    int target_len = strlen(hex1n) > strlen(hex2n) ? strlen(hex1n) : strlen(hex2n);
    
    unsigned char *padded_hex2;
    if (strlen(hex2n) < target_len) {
        padded_hex2 = pad_hex_string(hex2n, target_len);
    }

    hex1n[strlen(hex1n)]='\0';
    padded_hex2[strlen(padded_hex2)]='\0';
    
    BIGNUM *bn1 = BN_new();
    BIGNUM *bn2 = BN_new();
    BIGNUM *bn3 = BN_new();
    BIGNUM *resto = BN_new();
    BN_CTX *ctx = BN_CTX_new();

    if (bn1 == NULL || bn2 == NULL || bn3 == NULL || resto == NULL) {
        printf("Error: BIGNUM initialization failed.\n");
        return 1;
    }

    BN_hex2bn(&bn1, hex1n);
    BN_hex2bn(&bn2, padded_hex2);

    BN_div(bn3, resto, bn1, bn2, ctx);

    unsigned char *n_hex = BN_bn2hex(bn3);
    
    unsigned char formatted[strlen(n_hex)+strlen(n_hex)/2+1];
    format_with_colons(n_hex, formatted);

    
    printf("CRYPTO25{00:");
    for(int i=0; i<strlen(formatted); i++){
        printf("%c", tolower(formatted[i]));
    }
    printf("}\n");

    OPENSSL_free(n_hex);
    BN_free(bn1);
    BN_free(bn2);
    BN_free(bn3);
    BN_free(resto);
    BN_CTX_free(ctx);

    return 0;
}
