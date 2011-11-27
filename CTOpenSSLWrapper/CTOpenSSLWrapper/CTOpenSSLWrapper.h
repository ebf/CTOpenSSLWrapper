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
 @param     cypher: the cypher to be used
 @param     symmetricKeyData: data which will be used as symmetric key
 @param     data: data to be encrypted
 @return    encrypted data
 */
NSData *CTOpenSSLSymmetricEncrypt(CTOpenSSLCipher cipher, NSData *symmetricKeyData, NSData *data);

/**
 @abstract  decrypts data symmetrically
 @param     cypher: the cypher to be used
 @param     symmetricKeyData: data which will be used as symmetric key
 @param     encryptedData: data to be decrypted
 @return    decrypted data
 */
NSData *CTOpenSSLSymmetricDecrypt(CTOpenSSLCipher cipher, NSData *symmetricKeyData, NSData *encryptedData);
