#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include "lib/sha1.h"


static int
validateTOTP(char * secret_hex, char * TOTP_string)
{
    time_t t = time(NULL);
    unsigned int bruh = (unsigned) t;
    unsigned int bruv = bruh/30;
    
    unsigned char hexString[8];
    hexString[0] = 0x00;
    hexString[1] = 0x00;
    hexString[2] = 0x00;
    hexString[3] = 0x00;
    hexString[4] = (bruv >> 24) & 0xFF;
    hexString[5] = (bruv >> 16) & 0xFF;
    hexString[6] = (bruv >> 8) & 0xFF;
    hexString[7] = bruv & 0xFF;
    
    
    unsigned char hexSecret[64];
    int i = 0;
    for(i = 0; i < 20; i+=2){
        sscanf(secret_hex+i, "%02X", &hexSecret[i/2]);
    }
    for(i = 10; i < 64; i++){
        hexSecret[i] = 0x00;
    }

    unsigned char ipad[64];
    unsigned char opad[64];
    unsigned char ipad_r[64];
    unsigned char opad_r[64];
    for(i = 0; i < 64; i++){
        ipad[i] = 0x36;
        opad[i] = 0x5c;
    }
    for(i = 0; i < 64; i++){
        ipad_r[i] = ipad[i] ^ hexSecret[i];
        opad_r[i] = opad[i] ^ hexSecret[i];
    }
   
            
    SHA1_INFO ctx;
    uint8_t sha[SHA1_DIGEST_LENGTH];
    sha1_init(&ctx);
    sha1_update(&ctx, ipad_r, 64);
    sha1_update(&ctx, hexString, 8);
    sha1_final(&ctx, sha);
    
    
    SHA1_INFO ctx2;
    uint8_t sha2[SHA1_DIGEST_LENGTH];
    sha1_init(&ctx2);
    sha1_update(&ctx2, opad_r, 64);
    sha1_update(&ctx2, sha, SHA1_DIGEST_LENGTH);
    sha1_final(&ctx2, sha2);
   
    
    int offset = sha2[19] & 0xf;
    
    int binary = ((sha2[offset] & 0x7f) << 24) |((sha2[offset + 1] & 0xff) << 16) | ((sha2[offset + 2] & 0xff) << 8) | (sha2[offset + 3] & 0xff);
    int otp = binary % 1000000;
    int x = atoi(TOTP_string);
    return otp == x;
}


int
main(int argc, char * argv[])
{
	if ( argc != 3 ) {
		printf("Usage: %s [secretHex] [TOTP]\n", argv[0]);
		return(-1);
	}

	char *	secret_hex = argv[1];
	char *	TOTP_value = argv[2];

	assert (strlen(secret_hex) <= 20);
	assert (strlen(TOTP_value) == 6);

	printf("\nSecret (Hex): %s\nTOTP Value: %s (%s)\n\n",
		secret_hex,
		TOTP_value,
		validateTOTP(secret_hex, TOTP_value) ? "valid" : "invalid");

	return(0);
}
