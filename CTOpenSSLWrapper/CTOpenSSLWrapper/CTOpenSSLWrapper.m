//
//  CTOpenSSLWrapper.m
//  CTOpenSSLWrapper
//
//  Created by Oliver Letterer on 27.11.11.
//  Copyright (c) 2011 Home. All rights reserved.
//

#import "CTOpenSSLWrapper.h"

NSString *NSStringFromCTOpenSSLCypher(CTOpenSSLCypher cypher)
{
    NSString *cypherString = nil;
    
    switch (cypher) {
        case CTOpenSSLCypherAES256:
            cypherString = @"aes256";
            break;
            
        default:
            [NSException raise:NSInternalInconsistencyException format:@"CTOpenSSLCypher %i is not supported", cypher];
            break;
    }
    
    return cypherString;
}

NSData *CTOpenSSLSymmetricEncrypt(CTOpenSSLCypher cypher, NSData *symmetricKeyData, NSData *data)
{
    return nil;
}

NSData *CTOpenSSLSymmetricDecrypt(CTOpenSSLCypher cypher, NSData *symmetricKeyData, NSData *encryptedData)
{
    return nil;
}
