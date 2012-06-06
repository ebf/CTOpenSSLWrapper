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
    
    NSData *encryptedData = CTOpenSSLRSAEncrypt(publicKeyData, rawData);
    STAssertNotNil(encryptedData, @"encrypted data cannot be nil");
    STAssertFalse([rawData isEqualToData:encryptedData], @"CTOpenSSLAsymmetricEncrypt cannot return unencrypted data");
    
    NSData *decryptedData = CTOpenSSLRSADecrypt(privateKeyData, encryptedData);
    STAssertNotNil(decryptedData, @"decrypted data cannot be nil");
    
    NSString *decryptedString = [[NSString alloc] initWithData:decryptedData encoding:NSUTF8StringEncoding];
    STAssertEqualObjects(stringToBeDecrypted, decryptedString, @"string before and after asymmetric encryption must be the same");
}

- (void)testDigestGeneration
{
    NSString *testString = @"rubber duck";
    NSData *rawData = [testString dataUsingEncoding:NSUTF8StringEncoding];
    
    NSString *MD5String = CTOpenSSLGenerateDigestFromData(rawData, CTOpenSSLDigestTypeMD5).hexadecimalValue;
    STAssertEqualObjects(MD5String, @"ff5d392ea71f7be58f1161f67cd409c7", @"MD5 not working");
    
    NSString *SHA1String = CTOpenSSLGenerateDigestFromData(rawData, CTOpenSSLDigestTypeSHA1).hexadecimalValue;
    STAssertEqualObjects(SHA1String, @"d612c3d72467942ba6f756b783bae5962ecf24e8", @"SHA1 not working");
    
    NSString *SHA256String = CTOpenSSLGenerateDigestFromData(rawData, CTOpenSSLDigestTypeSHA256).hexadecimalValue;
    STAssertEqualObjects(SHA256String, @"5ce527fa9c078b383d588adfc6d94c96de37fa6383dc6e403db34fc9fdc1fd50", @"SHA256 not working");
    
    NSString *SHA512String = CTOpenSSLGenerateDigestFromData(rawData, CTOpenSSLDigestTypeSHA512).hexadecimalValue;
    STAssertEqualObjects(SHA512String, @"523e2313cb0c62d91f7c1577cb7b66f684f133cfb56499f19d590dd37d80e0894a60e6503d2bd8044432d0332c7a4f68062d1700b1b20c0aea65c70160ec1732", @"SHA512 not working");
}

- (void)testBase64Encoding
{
    NSString *testString = @"rubber duck";
    NSData *rawData = [testString dataUsingEncoding:NSUTF8StringEncoding];
    
    NSString *base64EncodedString = rawData.base64EncodedString;
    
    STAssertEqualObjects(base64EncodedString, @"cnViYmVyIGR1Y2s=", @"Base64 encoding of `rubber duck` wrong");
}

- (void)testDataSigningAndVerification
{
    NSData *privateKeyData = CTOpenSSLGeneratePrivateRSAKey(1024, CTOpenSSLPrivateKeyFormatPEM);
    STAssertNotNil(privateKeyData, @"newly generated private key cannot by nil.");
    
    NSData *publicKeyData = CTOpenSSLExtractPublicKeyFromPrivateRSAKey(privateKeyData);
    STAssertNotNil(publicKeyData, @"extracted public key cannot by nil.");
    
    
    NSString *stringToBySigned = @"Hello my dear Rubber duck";
    NSData *rawData = [stringToBySigned dataUsingEncoding:NSUTF8StringEncoding];
    
    NSData *signature = CTOpenSSLRSASignWithPrivateKey(privateKeyData, rawData, CTOpenSSLDigestTypeSHA512);
    STAssertNotNil(signature, @"signature data cannot be nil");
    
    BOOL shouldBeSigned = CTOpenSSLRSAVerifyWithPublicKey(publicKeyData, rawData, signature, CTOpenSSLDigestTypeSHA512);
    STAssertTrue(shouldBeSigned, @"CTOpenSSLDigestTypeSHA512 verification/signing not working");
    
    BOOL shouldNotBeSigned = CTOpenSSLRSAVerifyWithPublicKey(publicKeyData, rawData, signature, CTOpenSSLDigestTypeMD5);
    STAssertFalse(shouldNotBeSigned, @"verification/signing not working");
}

@end