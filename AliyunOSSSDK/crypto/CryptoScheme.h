//
//  CryptoScheme.h
//  AliyunOSSSDK iOS
//
//  Created by ws on 2021/7/29.
//  Copyright © 2021 aliyun. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonCrypto.h>

NS_ASSUME_NONNULL_BEGIN

const static NSInteger BlockSize = 16;

@interface CryptoScheme : NSObject

- (NSInteger)getKeyLengthInBits;
- (CCAlgorithm)getContentChiperAlgorithm;
- (CCMode)getContentChiperMode;
- (CCPadding)getContentChiperPadding;
- (NSInteger)getContentChiperIVLength;

- (NSData *)randomGenerateIV;
- (NSData *)randomGenerateKey;

+ (NSData *)incrementBlocks:(NSData *)counter blockDelta:(int64_t)blockDelta error:(NSError **)error;

@end

NS_ASSUME_NONNULL_END
