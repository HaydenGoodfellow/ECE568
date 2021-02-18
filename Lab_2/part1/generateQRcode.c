#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "lib/encoding.h"

int
main(int argc, char * argv[])
{
	if ( argc != 4 ) {
		printf("Usage: %s [issuer] [accountName] [secretHex]\n", argv[0]);
		return(-1);
	}

	char *	issuer = argv[1];
	char *	accountName = argv[2];
	char *	secret_hex = argv[3];
	assert (strlen(secret_hex) <= 20);
        
        char * urlEncodedIssuer = urlEncode(issuer);
        char * urlEncodedAccountName = urlEncode(accountName);
        unsigned char * base32EncodedSecret = malloc(16);
        unsigned char * hexSecret = malloc(10);
        int i = 0;
        for(i = 0; i < 20; i+=2){
            sscanf(&secret_hex[i], "%02X", &hexSecret[i/2]);
        } 
 
        
        base32_encode(hexSecret, 10, base32EncodedSecret, 16);
        
	printf("\nIssuer: %s\nAccount Name: %s\nSecret (Hex): %s\n\n",
		issuer, accountName, secret_hex);
        printf("%s\n", base32EncodedSecret);
	// Create an otpauth:// URI and display a QR code that's compatible
	// with Google Authenticator
        int bruh = 15 + strlen(accountName) + 8 + strlen(issuer) + 8 + 20;
        char * url = malloc(bruh);
        sprintf(url, "otpauth://totp/%s?issuer=%s&secret=%s&period=30", accountName, issuer, base32EncodedSecret);
	displayQRcode(url);

	return (0);
}
