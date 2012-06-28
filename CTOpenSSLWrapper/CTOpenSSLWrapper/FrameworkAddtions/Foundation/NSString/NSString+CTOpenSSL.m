//
//  NSString+CTOpenSSL.m
//  CTOpenSSLWrapper
//
//  Created by Oliver Letterer on 06.06.12.
//  Copyright (c) 2012 Home. All rights reserved.
//

#import "NSString+CTOpenSSL.h"
#import "CTOpenSSLDigest.h"
#import "NSData+CTOpenSSL.h"

@implementation NSString (CTOpenSSL)

- (NSData *)dataFromHexadecimalString
{
    const char *bytes = [self cStringUsingEncoding:NSUTF8StringEncoding];
    NSUInteger length = strlen(bytes);
    unsigned char *dataBuffer = (unsigned char *)malloc(length / 2 + 1);
    unsigned char *index = dataBuffer;
    
    while ((*bytes) && (*(bytes + 1))) {
        char encoder[3] = {'\0', '\0', '\0'};
        encoder[0] = *bytes;
        encoder[1] = *(bytes + 1);
        *index = strtol(encoder, NULL, 16);
        index++;
        bytes+=2;
    }
    *index = '\0';
    
    return [NSData dataWithBytesNoCopy:dataBuffer length:length / 2 freeWhenDone:YES];
}

- (NSString *)MD5Digest
{
    return CTOpenSSLGenerateDigestFromData([self dataUsingEncoding:NSUTF8StringEncoding], CTOpenSSLDigestTypeMD5).hexadecimalValue;
}

- (NSString *)SHA512Digest
{
    return CTOpenSSLGenerateDigestFromData([self dataUsingEncoding:NSUTF8StringEncoding], CTOpenSSLDigestTypeSHA512).hexadecimalValue;
}

@end
