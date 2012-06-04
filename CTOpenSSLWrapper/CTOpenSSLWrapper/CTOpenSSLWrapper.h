//
//  CTOpenSSLWrapper.h
//  CTOpenSSLWrapper
//
//  Created by Oliver Letterer on 27.11.11.
//  Copyright (c) 2011 Home. All rights reserved.
//

#import <Foundation/Foundation.h>

typedef enum {
    CTOpenSSLCipherAES256 = 0
} CTOpenSSLCipher;

NSString *NSStringFromCTOpenSSLCipher(CTOpenSSLCipher cipher);

/**
 @abstract  encrypts data symmetrically
 @param     cipher: the cipher to be used
 @param     symmetricKeyData: data which will be used as symmetric key
 @param     data: data to be encrypted
 @return    encrypted data
 */
NSData *CTOpenSSLSymmetricEncrypt(CTOpenSSLCipher cipher, NSData *symmetricKeyData, NSData *data);

/**
 @abstract  decrypts data symmetrically
 @param     cipher: the cipher to be used
 @param     symmetricKeyData: data which will be used as symmetric key
 @param     encryptedData: data to be decrypted
 @return    decrypted data
 */
NSData *CTOpenSSLSymmetricDecrypt(CTOpenSSLCipher cipher, NSData *symmetricKeyData, NSData *encryptedData);



typedef enum {
    CTOpenSSLPrivateKeyFormatDER = 0,
    CTOpenSSLPrivateKeyFormatPEM
} CTOpenSSLPrivateKeyFormat;

/**
 @abstract  generates a new private key with a given length
 */
NSData *CTOpenSSLGeneratePrivateRSAKey(int keyLength, CTOpenSSLPrivateKeyFormat format);

/**
 @abstract  extracts public key from private key
 */
NSData *CTOpenSSLExtractPublicKeyFromPrivateRSAKey(NSData *privateKeyData);

/**
 @abstract  encrypts data asymmetrically
 @param     publicKeyData: data representing the public key
 @param     data: data to be encrypted
 @return    encrypted data
 */
NSData *CTOpenSSLAsymmetricEncrypt(NSData *publicKeyData, NSData *data);

/**
 @abstract  decrypts data asymmetrically
 @param     privateKeyData: data representing the private key
 @param     data: data to be decrypted
 @return    dectryped data
 */
NSData *CTOpenSSLAsymmetricDecrypt(NSData *privateKeyData, NSData *data);
