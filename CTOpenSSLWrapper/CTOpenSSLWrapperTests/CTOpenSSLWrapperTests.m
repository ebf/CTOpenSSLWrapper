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
    
    NSData *encryptedData = CTOpenSSLSymmetricEncrypt(CTOpenSSLCipherAES256, symmetricKeyData, rawData);
    NSData *decryptedData = CTOpenSSLSymmetricDecrypt(CTOpenSSLCipherAES256, symmetricKeyData, encryptedData);
    STAssertNotNil(encryptedData, @"encrypted data cannot be nil");
    STAssertFalse([encryptedData isEqual:decryptedData], @"encryptedData and decryptedData cannot be the same");
    
    NSString *decryptedString = [[NSString alloc] initWithData:decryptedData encoding:NSUTF8StringEncoding];
    
    STAssertEqualObjects(stringToBeDecrypted, decryptedString, @"string before and after symmetric encryption must be the same");
}

- (void)testAsymmetricEncryption
{
    NSData *privateKeyData = CTOpenSSLGeneratePrivateRSAKey(1024, CTOpenSSLPrivateKeyFormatPEM);
    STAssertNotNil(privateKeyData, @"newly generated private key cannot by nil.");
    
    NSData *publicKeyData = CTOpenSSLExtractPublicKeyFromPrivateRSAKey(privateKeyData);
    STAssertNotNil(publicKeyData, @"extracted public key cannot by nil.");
    
    NSString *stringToBeDecrypted = @"SecretString";
    NSData *rawData = [stringToBeDecrypted dataUsingEncoding:NSUTF8StringEncoding];
    
    NSData *encryptedData = CTOpenSSLAsymmetricEncrypt(publicKeyData, rawData);
    STAssertNotNil(encryptedData, @"encrypted data cannot be nil");
    STAssertFalse([rawData isEqualToData:encryptedData], @"CTOpenSSLAsymmetricEncrypt cannot return unencrypted data");
    
    NSData *decryptedData = CTOpenSSLAsymmetricDecrypt(privateKeyData, encryptedData);
    STAssertNotNil(decryptedData, @"decrypted data cannot be nil");
    
    NSString *decryptedString = [[NSString alloc] initWithData:decryptedData encoding:NSUTF8StringEncoding];
    STAssertEqualObjects(stringToBeDecrypted, decryptedString, @"string before and after asymmetric encryption must be the same");
}

@end
