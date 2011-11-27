//
//  CTOpenSSLWrapperTests.m
//  CTOpenSSLWrapperTests
//
//  Created by Oliver Letterer on 27.11.11.
//  Copyright (c) 2011 Home. All rights reserved.
//

#import "CTOpenSSLWrapperTests.h"
#import "CTOpenSSLWrapper.h"

@implementation CTOpenSSLWrapperTests

- (void)testSymmetricEncryption
{
    NSString *key = @"SuperAwesomeKey";
    NSData *symmetricKeyData = [key dataUsingEncoding:NSUTF8StringEncoding];
    
    NSString *stringToBeDecrypted = @"SecretString";
    NSData *rawData = [stringToBeDecrypted dataUsingEncoding:NSUTF8StringEncoding];
    
    NSData *encryptedData = CTOpenSSLSymmetricEncrypt(CTOpenSSLCypherAES256, symmetricKeyData, rawData);
    NSData *decryptedData = CTOpenSSLSymmetricDecrypt(CTOpenSSLCypherAES256, symmetricKeyData, encryptedData);
    
    NSString *decryptedString = [[NSString alloc] initWithData:decryptedData encoding:NSUTF8StringEncoding];
    
    STAssertEqualObjects(stringToBeDecrypted, decryptedString, @"string before and after symmetric encryption must be the same");
}

@end
