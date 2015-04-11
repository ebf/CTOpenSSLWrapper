//
//  NSData+CTOpenSSL.h
//  CTOpenSSLWrapper
//
//  Created by Oliver Letterer on 04.06.12.
//  Copyright (c) 2012 Home. All rights reserved.
//

NS_ASSUME_NONNULL_BEGIN

@interface NSData (CTOpenSSL)

@property (nonatomic, readonly) NSString *base64EncodedString;
- (NSString *)base64EncodedStringWithNewLines:(BOOL)useNewLines;

@property (nonatomic, readonly) NSString *hexadecimalValue;

@end

NS_ASSUME_NONNULL_END
