//
//  CryptoShemeAesCtr.m
//  AliyunOSSSDK
//
//  Created by ws on 2021/7/29.
//  Copyright © 2021 aliyun. All rights reserved.
//

#import "CryptoSchemeAesCtr.h"

@implementation CryptoSchemeAesCtr

- (NSInteger)getKeyLengthInBits {
    return kCCKeySizeAES128;
}

- (CCAlgorithm)getContentChiperAlgorithm {
    return kCCAlgorithmAES;
}

- (CCMode)getContentChiperMode {
    return kCCModeCTR;
}

- (CCPadding)getContentChiperPadding {
    return ccNoPadding;
}

- (NSInteger)getContentChiperIVLength {
    return 16;
}

- (NSData *)randomGenerateIV {
    NSInteger keyLength = [self getContentChiperIVLength];
    
    unsigned char buf[keyLength];
    CCRandomGenerateBytes(buf, sizeof(buf));
    for (int i = 8; i < 12; i++) {
        buf[i] = 0;
    }
    return [NSData dataWithBytes:buf length:sizeof(buf)];
}

@end
