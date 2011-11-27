//
//  CTOpenSSLWrapper.m
//  CTOpenSSLWrapper
//
//  Created by Oliver Letterer on 27.11.11.
//  Copyright (c) 2011 Home. All rights reserved.
//

#import "CTOpenSSLWrapper.h"
#import <openssl/evp.h>
#import <openssl/rand.h>
#import <openssl/rsa.h>
#import <openssl/engine.h>
#import <openssl/sha.h>
#import <openssl/pem.h>
#import <openssl/bio.h>
#import <openssl/err.h>
#import <openssl/ssl.h>
#import <openssl/md5.h>

void _CTOpenSSLSetup(void);
void _CTOpenSSLCleanup(void);

#pragma mark - private implementation

void _CTOpenSSLSetup(void)
{
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
}

void _CTOpenSSLCleanup(void)
{
    EVP_cleanup();
    ERR_free_strings();
}

#pragma mark - symmetric encryption

NSString *NSStringFromCTOpenSSLCipher(CTOpenSSLCipher cipher)
{
    NSString *cipherString = nil;
    
    switch (cipher) {
        case CTOpenSSLCipherAES256:
            cipherString = @"aes256";
            break;
            
        default:
            [NSException raise:NSInternalInconsistencyException format:@"CTOpenSSLCipher %i is not supported", cipher];
            break;
    }
    
    return cipherString;
}

NSData *CTOpenSSLSymmetricEncrypt(CTOpenSSLCipher CTCipher, NSData *symmetricKeyData, NSData *data)
{
    _CTOpenSSLSetup();
    
    if (data.length == 0) {
        _CTOpenSSLCleanup();
        [NSException raise:NSInternalInconsistencyException format:@"data has length 0"];
    }
    
    unsigned char *inputBytes = (unsigned char *)data.bytes;
    int inputLength = (int)data.length;
    unsigned char *outputBuffer = NULL;
    unsigned char initialVector[EVP_MAX_IV_LENGTH];
    int outputLength = 0;
    int temporaryLength = 0;
    
    // Perform symmetric encryption...
    unsigned char evp_key[EVP_MAX_KEY_LENGTH] = {"\0"};
    EVP_CIPHER_CTX cipherContext;
    
    NSString *cipherName = NSStringFromCTOpenSSLCipher(CTCipher);
    const EVP_CIPHER *cipher = EVP_get_cipherbyname(cipherName.UTF8String);
    if (!cipher) {
        _CTOpenSSLCleanup();
        [NSException raise:NSInternalInconsistencyException format:@"unable to get cipher with name %@", cipherName];
    }
    
    EVP_BytesToKey(cipher, EVP_md5(), NULL, symmetricKeyData.bytes, (int)symmetricKeyData.length, 1, evp_key, initialVector);
    EVP_CIPHER_CTX_init(&cipherContext);
    
    if (!EVP_EncryptInit(&cipherContext, cipher, evp_key, initialVector)) {
        EVP_CIPHER_CTX_cleanup(&cipherContext);
        _CTOpenSSLCleanup();
        [NSException raise:NSInternalInconsistencyException format:@"EVP_EncryptInit() failed!"];
    }
    EVP_CIPHER_CTX_set_key_length(&cipherContext, EVP_MAX_KEY_LENGTH);
    
    outputBuffer = (unsigned char *)calloc(inputLength + EVP_CIPHER_CTX_block_size(&cipherContext) - 1, sizeof(unsigned char));
    
    if (!outputBuffer) {
        EVP_CIPHER_CTX_cleanup(&cipherContext);
        _CTOpenSSLCleanup();
        [NSException raise:NSInternalInconsistencyException format:@"Cannot allocate memory for buffer!"];
    }
    
    if (!EVP_EncryptUpdate(&cipherContext, outputBuffer, &outputLength, inputBytes, inputLength)) {
        EVP_CIPHER_CTX_cleanup(&cipherContext);
        _CTOpenSSLCleanup();
        [NSException raise:NSInternalInconsistencyException format:@"EVP_EncryptUpdate() failed!"];
    }
    
    if (!EVP_EncryptFinal(&cipherContext, outputBuffer + outputLength, &temporaryLength)) {
        EVP_CIPHER_CTX_cleanup(&cipherContext);
        _CTOpenSSLCleanup();
        [NSException raise:NSInternalInconsistencyException format:@"EVP_EncryptFinal() failed!"];
    }
    
    outputLength += temporaryLength;
    EVP_CIPHER_CTX_cleanup(&cipherContext);
    
    NSData *encryptedData = [NSData dataWithBytes:outputBuffer length:outputLength];
    
    if(outputBuffer) {
        free(outputBuffer);
    }
    
    return encryptedData;
}

NSData *CTOpenSSLSymmetricDecrypt(CTOpenSSLCipher CTCipher, NSData *symmetricKeyData, NSData *encryptedData)
{
    _CTOpenSSLSetup();
    
    if (encryptedData.length == 0) {
        _CTOpenSSLCleanup();
        [NSException raise:NSInternalInconsistencyException format:@"data has length 0"];
    }
    
    unsigned char *inputBytes = (unsigned char *)encryptedData.bytes;
    unsigned char *outputBuffer = NULL;
    unsigned char initialVector[EVP_MAX_IV_LENGTH];
    int outputLength = 0;
    int temporaryLength = 0;
    int inputLength = (int)encryptedData.length;
    
    // Use symmetric decryption...
    unsigned char evp_key[EVP_MAX_KEY_LENGTH] = {"\0"};
    EVP_CIPHER_CTX cCtx;
    const EVP_CIPHER *cipher;
    
    NSString *cipherName = NSStringFromCTOpenSSLCipher(CTCipher);
    cipher = EVP_get_cipherbyname(cipherName.UTF8String);
    if (!cipher) {
        _CTOpenSSLCleanup();
        [NSException raise:NSInternalInconsistencyException format:@"unable to get cipher with name %@", cipherName];
    }
    
    EVP_BytesToKey(cipher, EVP_md5(), NULL, symmetricKeyData.bytes, (int)symmetricKeyData.length, 1, evp_key, initialVector);
    
    EVP_CIPHER_CTX_init(&cCtx);
    
    if (!EVP_DecryptInit(&cCtx, cipher, evp_key, initialVector)) {
        EVP_CIPHER_CTX_cleanup(&cCtx);
        _CTOpenSSLCleanup();
        [NSException raise:NSInternalInconsistencyException format:@"EVP_DecryptInit() failed!"];
    }
    EVP_CIPHER_CTX_set_key_length(&cCtx, EVP_MAX_KEY_LENGTH);
    
    if(EVP_CIPHER_CTX_block_size(&cCtx) > 1) {
        outputBuffer = (unsigned char *)calloc(inputLength + EVP_CIPHER_CTX_block_size(&cCtx), sizeof(unsigned char));
    } else {
        outputBuffer = (unsigned char *)calloc(inputLength, sizeof(unsigned char));
    }
    
    if (!outputBuffer) {
        EVP_CIPHER_CTX_cleanup(&cCtx);
        _CTOpenSSLCleanup();
        [NSException raise:NSInternalInconsistencyException format:@"Cannot allocate memory for buffer!"];
    }
    
    if (!EVP_DecryptUpdate(&cCtx, outputBuffer, &outputLength, inputBytes, inputLength)) {
        EVP_CIPHER_CTX_cleanup(&cCtx);
        _CTOpenSSLCleanup();
        [NSException raise:NSInternalInconsistencyException format:@"EVP_DecryptUpdate() failed!"];
    }
    
    if (!EVP_DecryptFinal(&cCtx, outputBuffer + outputLength, &temporaryLength)) {
        EVP_CIPHER_CTX_cleanup(&cCtx);
        _CTOpenSSLCleanup();
        [NSException raise:NSInternalInconsistencyException format:@"EVP_DecryptFinal() failed!"];
    }
    
    outputLength += temporaryLength;
    EVP_CIPHER_CTX_cleanup(&cCtx);
    
    NSData *decryptedData = [NSData dataWithBytes:outputBuffer length:outputLength];
    
    if (outputBuffer) {
        free(outputBuffer);
    }
    
    _CTOpenSSLCleanup();
    
    return decryptedData;
}
