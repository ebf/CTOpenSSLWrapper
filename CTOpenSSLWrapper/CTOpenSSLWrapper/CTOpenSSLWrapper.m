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
    unsigned char initializationVector[EVP_MAX_IV_LENGTH];
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
    
    EVP_BytesToKey(cipher, EVP_md5(), NULL, symmetricKeyData.bytes, (int)symmetricKeyData.length, 1, evp_key, initializationVector);
    EVP_CIPHER_CTX_init(&cipherContext);
    
    if (!EVP_EncryptInit(&cipherContext, cipher, evp_key, initializationVector)) {
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
        _CTOpenSSLCleanup();
        [NSException raise:NSInternalInconsistencyException format:@"unable to get cipher with name %@", cipherName];
    }
    
    EVP_BytesToKey(cipher, EVP_md5(), NULL, symmetricKeyData.bytes, (int)symmetricKeyData.length, 1, envelopeKey, initializationVector);
    
    EVP_CIPHER_CTX_init(&cipherContext);
    
    if (!EVP_DecryptInit(&cipherContext, cipher, envelopeKey, initializationVector)) {
        EVP_CIPHER_CTX_cleanup(&cipherContext);
        _CTOpenSSLCleanup();
        [NSException raise:NSInternalInconsistencyException format:@"EVP_DecryptInit() failed!"];
    }
    EVP_CIPHER_CTX_set_key_length(&cipherContext, EVP_MAX_KEY_LENGTH);
    
    if(EVP_CIPHER_CTX_block_size(&cipherContext) > 1) {
        outputBuffer = (unsigned char *)calloc(inputLength + EVP_CIPHER_CTX_block_size(&cipherContext), sizeof(unsigned char));
    } else {
        outputBuffer = (unsigned char *)calloc(inputLength, sizeof(unsigned char));
    }
    
    if (!outputBuffer) {
        EVP_CIPHER_CTX_cleanup(&cipherContext);
        _CTOpenSSLCleanup();
        [NSException raise:NSInternalInconsistencyException format:@"Cannot allocate memory for buffer!"];
    }
    
    if (!EVP_DecryptUpdate(&cipherContext, outputBuffer, &outputLength, inputBytes, inputLength)) {
        EVP_CIPHER_CTX_cleanup(&cipherContext);
        _CTOpenSSLCleanup();
        [NSException raise:NSInternalInconsistencyException format:@"EVP_DecryptUpdate() failed!"];
    }
    
    if (!EVP_DecryptFinal(&cipherContext, outputBuffer + outputLength, &temporaryLength)) {
        EVP_CIPHER_CTX_cleanup(&cipherContext);
        _CTOpenSSLCleanup();
        [NSException raise:NSInternalInconsistencyException format:@"EVP_DecryptFinal() failed!"];
    }
    
    outputLength += temporaryLength;
    EVP_CIPHER_CTX_cleanup(&cipherContext);
    
    NSData *decryptedData = [NSData dataWithBytes:outputBuffer length:outputLength];
    
    if (outputBuffer) {
        free(outputBuffer);
    }
    
    _CTOpenSSLCleanup();
    
    return decryptedData;
}

#pragma mark - asymmetric encryption

NSData *CTOpenSSLGeneratePrivateRSAKey(int keyLength, CTOpenSSLPrivateKeyFormat format)
{
    RSA *key = NULL;
    
    do {
        key = RSA_generate_key(keyLength, RSA_F4, NULL, NULL);
    } while (RSA_check_key(key) != 1);
    
    BIO *bio = BIO_new(BIO_s_mem());
	
	switch (format) {
		case CTOpenSSLPrivateKeyFormatDER:
			i2d_RSAPrivateKey_bio(bio, key);
			break;
		case CTOpenSSLPrivateKeyFormatPEM:
			PEM_write_bio_RSAPrivateKey(bio, key, NULL, NULL, 0, NULL, NULL);
			break;
		default:
			return nil;
	}
    
    if (key) {
        RSA_free(key);
    }
    
    char *bioData = NULL;
    int bioDataLength = BIO_get_mem_data(bio, &bioData);
    NSData *result = [NSData dataWithBytes:bioData length:bioDataLength];
    
    if (bio) {
        BIO_free(bio);
    }
    
    return result;
}

NSData *CTOpenSSLExtractPublicKeyFromPrivateRSAKey(NSData *privateKeyData)
{
    BIO *privateBIO = NULL;
	RSA *privateRSA = NULL;
	
	if (!(privateBIO = BIO_new_mem_buf((unsigned char*)privateKeyData.bytes, privateKeyData.length))) {
        [NSException raise:NSInternalInconsistencyException format:@"cannot allocate new BIO memory buffer"];
		return nil;
	}
	
	if (!PEM_read_bio_RSAPrivateKey(privateBIO, &privateRSA, NULL, NULL)) {
        [NSException raise:NSInternalInconsistencyException format:@"cannot read private RSA BIO with PEM_read_bio_RSAPrivateKey()!"];
		return nil;
	}
	
	int RSAKeyError = RSA_check_key(privateRSA);
	if (RSAKeyError != 1) {
        [NSException raise:NSInternalInconsistencyException format:@"private RSA key is invalid: %d", RSAKeyError];
		return nil;
	}			
    
    BIO *bio = BIO_new(BIO_s_mem());
    
    if (!PEM_write_bio_RSA_PUBKEY(bio, privateRSA)) {
        [NSException raise:NSInternalInconsistencyException format:@"unable to write public key"];
        return nil;
    }
    
    if (privateRSA) {
        RSA_free(privateRSA);
    }
    
    char *bioData = NULL;
    int bioDataLength = BIO_get_mem_data(bio, &bioData);
    NSData *result = [NSData dataWithBytes:bioData length:bioDataLength];
    
    if (bio) {
        BIO_free(bio);
    }
    
    return result;
}

NSData *CTOpenSSLAsymmetricEncrypt(NSData *publicKeyData, NSData *data)
{
    unsigned char *inputBytes = (unsigned char *)data.bytes;
    int inputLength = data.length;
    
    BIO *publicBIO = NULL;
    RSA *publicRSA = NULL;
    
    if (!(publicBIO = BIO_new_mem_buf((unsigned char *)publicKeyData.bytes, publicKeyData.length))) {
        [NSException raise:NSInternalInconsistencyException format:@"cannot allocate new BIO memory buffer"];
        return nil;
    }
    
    if (!PEM_read_bio_RSA_PUBKEY(publicBIO, &publicRSA, NULL, NULL)) {
        [NSException raise:NSInternalInconsistencyException format:@"cannot read public RSA BIO with PEM_read_bio_RSA_PUBKEY()!"];
        return nil;
    }
    
    unsigned char *outputBuffer = (unsigned char *)malloc(RSA_size(publicRSA));
    int outputLength = 0;
    
    if (!(outputLength = RSA_public_encrypt(inputLength, inputBytes, (unsigned char*)outputBuffer, publicRSA, RSA_PKCS1_PADDING))) {
        [NSException raise:NSInternalInconsistencyException format:@"RSA public encryption RSA_public_encrypt() failed"];
        return nil;
    }
    
    if (outputLength == -1) {
        [NSException raise:NSInternalInconsistencyException format:@"Encryption failed with error %s (%s)", ERR_error_string(ERR_get_error(), NULL), ERR_reason_error_string(ERR_get_error())];
        return nil;
    }
    
    if (publicBIO) {
        BIO_free(publicBIO);
    }
    
    if (publicRSA) {
        RSA_free(publicRSA);
    }
    
    NSData *encryptedData = [NSData dataWithBytes:outputBuffer length:outputLength];
    
    if (outputBuffer) {
        free(outputBuffer);
    }
    
    return encryptedData;
}

NSData *CTOpenSSLAsymmetricDecrypt(NSData *privateKeyData, NSData *data)
{
    unsigned char *inputBytes = (unsigned char *)data.bytes;
    int inputLength = data.length;
    
    BIO *privateBIO = NULL;
    RSA *privateRSA = NULL;
    
    if (!(privateBIO = BIO_new_mem_buf((unsigned char*)privateKeyData.bytes, privateKeyData.length))) {
        [NSException raise:NSInternalInconsistencyException format:@"cannot allocate new BIO memory buffer"];
        return nil;
    }
    
    if (!PEM_read_bio_RSAPrivateKey(privateBIO, &privateRSA, NULL, NULL)) {
        [NSException raise:NSInternalInconsistencyException format:@"cannot read private RSA BIO with PEM_read_bio_RSAPrivateKey()!"];
        return nil;
    }
    
    int RSAKeyError = RSA_check_key(privateRSA);
    if (RSAKeyError != 1) {
        [NSException raise:NSInternalInconsistencyException format:@"private RSA key is invalid: %d", RSAKeyError];
        return nil;
    }
    
    unsigned char *outputBuffer = (unsigned char *)malloc(RSA_size(privateRSA));
    int outputLength = 0;
    
    if (!(outputLength = RSA_private_decrypt(inputLength, inputBytes, outputBuffer, privateRSA, RSA_PKCS1_PADDING))) {
        [NSException raise:NSInternalInconsistencyException format:@"RSA private decrypt RSA_private_decrypt() failed"];
        return nil;
    }
    
    if (outputLength == -1) {
        [NSException raise:NSInternalInconsistencyException format:@"Encryption failed with error %s (%s)", ERR_error_string(ERR_get_error(), NULL), ERR_reason_error_string(ERR_get_error())];
        return nil;
    }
    
    if (privateBIO) {
        BIO_free(privateBIO);
    }
    
    if (privateRSA) {
        RSA_free(privateRSA);
    }
    
    NSData *decryptedData = [NSData dataWithBytes:outputBuffer length:outputLength];
    
    if (outputBuffer) {
        free(outputBuffer);
    }
    
    return decryptedData;
}
