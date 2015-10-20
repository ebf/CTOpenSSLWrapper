//
//  CTOpenSSLDigest.h
//  CTOpenSSLWrapper
//
//  Created by Oliver Letterer on 05.06.12.
//  Copyright 2012 Home. All rights reserved.
//

NS_ASSUME_NONNULL_BEGIN

typedef enum {
    CTOpenSSLDigestTypeMD5,
    CTOpenSSLDigestTypeSHA1,
    CTOpenSSLDigestTypeSHA256,
    CTOpenSSLDigestTypeSHA512
} CTOpenSSLDigestType;

NSString *NSStringFromCTOpenSSLDigestType(CTOpenSSLDigestType digestType);

int CTOpenSSLRSASignTypeFromDigestType(CTOpenSSLDigestType digestType);

NSData *CTOpenSSLGenerateDigestFromData(NSData *data, CTOpenSSLDigestType digestType);

NS_ASSUME_NONNULL_END
