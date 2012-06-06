//
//  CTOpenSSLSymmetricEncryption.m
//  CTOpenSSLWrapper
//
//  Created by Oliver Letterer on 05.06.12.
//  Copyright 2012 Home. All rights reserved.
//

#import "CTOpenSSLSymmetricEncryption.h"
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

NSString *NSStringFromCTOpenSSLCipher(CTOpenSSLCipher cipher)
{
    NSString *cipherString = nil;
    
    switch (cipher) {
        case CTOpenSSLCipherAES256:
            cipherString = @"AES256";
            break;
        default:
            [NSException raise:NSInternalInconsistencyException format:@"CTOpenSSLCipher %d is not supported", cipher];
            break;
    }
    
    return cipherString;
}

NSData *CTOpenSSLSymmetricEncrypt(CTOpenSSLCipher CTCipher, NSData *symmetricKeyData, NSData *data)
{
    CTOpenSSLInitialize();
    
    unsigned char *inputBytes = (unsigned char *)data.bytes;
    int inputLength = (int)data.length;
    unsigned char initializationVector[EVP_MAX_IV_LENGTH];
    int temporaryLength = 0;
    
    // Perform symmetric encryption...
    unsigned char evp_key[EVP_MAX_KEY_LENGTH] = {"\0"};
    EVP_CIPHER_CTX cipherContext;
    
    NSString *cipherName = NSStringFromCTOpenSSLCipher(CTCipher);
    const EVP_CIPHER *cipher = EVP_get_cipherbyname(cipherName.UTF8String);
    
    if (!cipher) {
        [NSException raise:NSInternalInconsistencyException format:@"unable to get cipher with name %@ type %d", cipherName, CTCipher];
    }
    
    EVP_BytesToKey(cipher, EVP_md5(), NULL, symmetricKeyData.bytes, (int)symmetricKeyData.length, 1, evp_key, initializationVector);
    EVP_CIPHER_CTX_init(&cipherContext);
    
    if (!EVP_EncryptInit(&cipherContext, cipher, evp_key, initializationVector)) {
        [NSException raise:NSInternalInconsistencyException format:@"EVP_EncryptInit() failed!"];
    }
    EVP_CIPHER_CTX_set_key_length(&cipherContext, EVP_MAX_KEY_LENGTH);
    
    unsigned char *outputBuffer = (unsigned char *)calloc(inputLength + EVP_CIPHER_CTX_block_size(&cipherContext) - 1, sizeof(unsigned char));
    int outputLength = 0;
    
    if (!outputBuffer) {
        [NSException raise:NSInternalInconsistencyException format:@"Cannot allocate memory for buffer!"];
    }
    
    if (!EVP_EncryptUpdate(&cipherContext, outputBuffer, &outputLength, inputBytes, inputLength)) {
        [NSException raise:NSInternalInconsistencyException format:@"EVP_EncryptUpdate() failed!"];
    }
    
    if (!EVP_EncryptFinal(&cipherContext, outputBuffer + outputLength, &temporaryLength)) {
        [NSException raise:NSInternalInconsistencyException format:@"EVP_EncryptFinal() failed!"];
    }
    
    outputLength += temporaryLength;
    EVP_CIPHER_CTX_cleanup(&cipherContext);
    
    NSData *encryptedData = [NSData dataWithBytesNoCopy:outputBuffer length:outputLength freeWhenDone:YES];
    
    return encryptedData;
}

NSData *CTOpenSSLSymmetricDecrypt(CTOpenSSLCipher CTCipher, NSData *symmetricKeyData, NSData *encryptedData)
{
    CTOpenSSLInitialize();
    
    unsigned char *inputBytes = (unsigned char *)encryptedData.bytes;
    unsigned char *outputBuffer = NULL;
    unsigned char initializationVector[EVP_MAX_IV_LENGTH];
    int outputLength = 0;
    int temporaryLength = 0;
    int inputLength = encryptedData.length;
    
    // Use symmetric decryption...
    unsigned char envelopeKey[EVP_MAX_KEY_LENGTH] = {"\0"};
    EVP_CIPHER_CTX cipherContext;
    const EVP_CIPHER *cipher;
    
    NSString *cipherName = NSStringFromCTOpenSSLCipher(CTCipher);
    cipher = EVP_get_cipherbyname(cipherName.UTF8String);
    if (!cipher) {
        [NSException raise:NSInternalInconsistencyException format:@"unable to get cipher with name %@", cipherName];
    }
    
    EVP_BytesToKey(cipher, EVP_md5(), NULL, symmetricKeyData.bytes, (int)symmetricKeyData.length, 1, envelopeKey, initializationVector);
    
    EVP_CIPHER_CTX_init(&cipherContext);
    
    if (!EVP_DecryptInit(&cipherContext, cipher, envelopeKey, initializationVector)) {
        [NSException raise:NSInternalInconsistencyException format:@"EVP_DecryptInit() failed!"];
    }
    EVP_CIPHER_CTX_set_key_length(&cipherContext, EVP_MAX_KEY_LENGTH);
    
    if(EVP_CIPHER_CTX_block_size(&cipherContext) > 1) {
        outputBuffer = (unsigned char *)calloc(inputLength + EVP_CIPHER_CTX_block_size(&cipherContext), sizeof(unsigned char));
    } else {
        outputBuffer = (unsigned char *)calloc(inputLength, sizeof(unsigned char));
    }
    
    if (!outputBuffer) {
        [NSException raise:NSInternalInconsistencyException format:@"Cannot allocate memory for buffer!"];
    }
    
    if (!EVP_DecryptUpdate(&cipherContext, outputBuffer, &outputLength, inputBytes, inputLength)) {
        [NSException raise:NSInternalInconsistencyException format:@"EVP_DecryptUpdate() failed!"];
    }
    
    if (!EVP_DecryptFinal(&cipherContext, outputBuffer + outputLength, &temporaryLength)) {
        [NSException raise:NSInternalInconsistencyException format:@"EVP_DecryptFinal() failed!"];
    }
    
    outputLength += temporaryLength;
    EVP_CIPHER_CTX_cleanup(&cipherContext);
    
    NSData *decryptedData = [NSData dataWithBytes:outputBuffer length:outputLength];
    
    if (outputBuffer) {
        free(outputBuffer);
    }
    
    return decryptedData;
}
