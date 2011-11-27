//
//  CTOpenSSLWrapper.h
//  CTOpenSSLWrapper
//
//  Created by Oliver Letterer on 27.11.11.
//  Copyright (c) 2011 Home. All rights reserved.
//

#import <Foundation/Foundation.h>

typedef enum {
    CTOpenSSLCypherAES256 = 0
} CTOpenSSLCypher;

NSString *NSStringFromCTOpenSSLCypher(CTOpenSSLCypher cypher);

/**
 @abstract  encrypts data symmetrically
 @param     cypher: the cypher to be used
 @param     symmetricKeyData: data which will be used as symmetric key
 @param     data: data to be encrypted
 @return    encrypted data
 */
NSData *CTOpenSSLSymmetricEncrypt(CTOpenSSLCypher cypher, NSData *symmetricKeyData, NSData *data);

/**
 @abstract  decrypts data symmetrically
 @param     cypher: the cypher to be used
 @param     symmetricKeyData: data which will be used as symmetric key
 @param     encryptedData: data to be decrypted
 @return    decrypted data
 */
NSData *CTOpenSSLSymmetricDecrypt(CTOpenSSLCypher cypher, NSData *symmetricKeyData, NSData *encryptedData);
