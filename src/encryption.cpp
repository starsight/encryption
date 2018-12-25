#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
int do_crypt(FILE *in, FILE *out, int do_encrypt)
        {
        /* Allow enough space in output buffer for additional block */
        unsigned char inbuf[1024], outbuf[1024 + EVP_MAX_BLOCK_LENGTH];
        int inlen, outlen;
        EVP_CIPHER_CTX ctx;
        /* Bogus key and IV: we'd normally set these from
         * another source.
         */
        unsigned char key[] = "0123456789abcdeF";
        unsigned char iv[] = "1234567887654321";

        /* Don't set key or IV right away; we want to check lengths */
        EVP_CIPHER_CTX_init(&ctx);
        EVP_CipherInit_ex(&ctx, EVP_aes_128_cbc(), NULL, NULL, NULL,
                do_encrypt);
        OPENSSL_assert(EVP_CIPHER_CTX_key_length(&ctx) == 16);
        OPENSSL_assert(EVP_CIPHER_CTX_iv_length(&ctx) == 16);

        /* Now we can set key and IV */
        EVP_CipherInit_ex(&ctx, NULL, NULL, key, iv, do_encrypt);

        for(;;) 
                {
                inlen = fread(inbuf, 1, 1024, in);
                if(inlen <= 0) break;
                if(!EVP_CipherUpdate(&ctx, outbuf, &outlen, inbuf, inlen))
                        {
                        /* Error */
                        EVP_CIPHER_CTX_cleanup(&ctx);
                        return 0;
                        }
                fwrite(outbuf, 1, outlen, out);
                }
        if(!EVP_CipherFinal_ex(&ctx, outbuf, &outlen))
                {
                /* Error */
                EVP_CIPHER_CTX_cleanup(&ctx);
                return 0;
                }
        fwrite(outbuf, 1, outlen, out);

        EVP_CIPHER_CTX_cleanup(&ctx);
        return 1;
        }


int do_crypt2(FILE *in, FILE *out, int do_encrypt)
 {
     /* Allow enough space in output buffer for additional block */
     unsigned char inbuf[1024], outbuf[1024 + EVP_MAX_BLOCK_LENGTH];
     int inlen, outlen;
     EVP_CIPHER_CTX *ctx;
     /*
      * Bogus key and IV: we'd normally set these from
      * another source.
      */
     unsigned char key[] = "0123456789abcdeF";
     unsigned char iv[] = "1234567887654321";

     /* Don't set key or IV right away; we want to check lengths */
     ctx = EVP_CIPHER_CTX_new();
     EVP_CipherInit_ex(ctx, EVP_aes_128_cbc(), NULL, NULL, NULL,
                       do_encrypt);
     OPENSSL_assert(EVP_CIPHER_CTX_key_length(ctx) == 16);
     OPENSSL_assert(EVP_CIPHER_CTX_iv_length(ctx) == 16);

     /* Now we can set key and IV */
     EVP_CipherInit_ex(ctx, NULL, NULL, key, iv, do_encrypt);

     for (;;) {
         inlen = fread(inbuf, 1, 1024, in);
         if (inlen <= 0)
             break;
         if (!EVP_CipherUpdate(ctx, outbuf, &outlen, inbuf, inlen)) {
             /* Error */
             EVP_CIPHER_CTX_free(ctx);
             return 0;
         }
         fwrite(outbuf, 1, outlen, out);
     }
     if (!EVP_CipherFinal_ex(ctx, outbuf, &outlen)) {
         /* Error */
         EVP_CIPHER_CTX_free(ctx);
         return 0;
     }
     fwrite(outbuf, 1, outlen, out);

     EVP_CIPHER_CTX_free(ctx);
     return 1;
 }

int main(int argc, char** argv) {
    FILE *in =NULL;
    FILE *out =NULL;
    FILE *in2 =NULL;
    FILE *out2 =NULL;
    in =fopen("/home/ychj/wenjie/openssl/plcmodel.c","r");
    out =fopen("/home/ychj/wenjie/openssl/encryption.txt","w");
    do_crypt2(in,out,1);
    fclose(in);
    fclose(out);
    in2 =fopen("/home/ychj/wenjie/openssl/encryption.txt","r");
    out2 =fopen("/home/ychj/wenjie/openssl/plcmodel.txt","w");
    do_crypt2(in2,out2,0);
    fclose(in2);
    fclose(out2);
}

int main2(int argc, char** argv) {
    AES_KEY aes;
    unsigned char key[AES_BLOCK_SIZE];        // AES_BLOCK_SIZE = 16
    unsigned char iv[AES_BLOCK_SIZE];        // init vector
    unsigned char* input_string;
    unsigned char* encrypt_string;
    unsigned char* decrypt_string;
    unsigned int len;        // encrypt length (in multiple of AES_BLOCK_SIZE)
    unsigned int i;
 
    // check usage
    if (argc != 2) {
        fprintf(stderr, "%s <plain text>\n", argv[0]);
        exit(-1);
    }
 
    // set the encryption length
    len = 0;
    if ((strlen(argv[1]) + 1) % AES_BLOCK_SIZE == 0) {
        len = strlen(argv[1]) + 1;
    } else {
        len = ((strlen(argv[1]) + 1) / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE;
    }
 
    // set the input string
    input_string = (unsigned char*)calloc(len, sizeof(unsigned char));
    if (input_string == NULL) {
        fprintf(stderr, "Unable to allocate memory for input_string\n");
        exit(-1);
    }
    strncpy((char*)input_string, argv[1], strlen(argv[1]));
 
    // Generate AES 128-bit key
    for (i=0; i<16; ++i) {
        key[i] = 32 + i;
    }
 
    // Set encryption key
    for (i=0; i<AES_BLOCK_SIZE; ++i) {
        iv[i] = 0;
    }
    if (AES_set_encrypt_key(key, 128, &aes) < 0) {
        fprintf(stderr, "Unable to set encryption key in AES\n");
        exit(-1);
    }
 
    // alloc encrypt_string
    encrypt_string = (unsigned char*)calloc(len, sizeof(unsigned char));    
    if (encrypt_string == NULL) {
        fprintf(stderr, "Unable to allocate memory for encrypt_string\n");
        exit(-1);
    }
 
    // encrypt (iv will change)
    AES_cbc_encrypt(input_string, encrypt_string, len, &aes, iv, AES_ENCRYPT);
 
    // alloc decrypt_string
    decrypt_string = (unsigned char*)calloc(len, sizeof(unsigned char));
    if (decrypt_string == NULL) {
        fprintf(stderr, "Unable to allocate memory for decrypt_string\n");
        exit(-1);
    }
 
    // Set decryption key
    for (i=0; i<AES_BLOCK_SIZE; ++i) {
        iv[i] = 0;
    }
    if (AES_set_decrypt_key(key, 128, &aes) < 0) {
        fprintf(stderr, "Unable to set decryption key in AES\n");
        exit(-1);
    }
 
    // decrypt
    AES_cbc_encrypt(encrypt_string, decrypt_string, len, &aes, iv, 
            AES_DECRYPT);
 
    // print
    printf("input_string = %s\n", input_string);
    printf("encrypted string = ");
    for (i=0; i<len; ++i) {
        printf("%x%x", (encrypt_string[i] >> 4) & 0xf, 
                encrypt_string[i] & 0xf);    
    }
    printf("\n");
    printf("decrypted string = %s\n", decrypt_string);
 
    return 0;
}