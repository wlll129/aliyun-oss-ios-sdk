//
//  CryptoScheme.m
//  AliyunOSSSDK iOS
//
//  Created by ws on 2021/7/29.
//  Copyright © 2021 aliyun. All rights reserved.
//

#import "CryptoScheme.h"
#import "OSSConstants.h"
#import "OSSDefine.h"

#define MethodNotImplemented() \
    @throw \
    [NSException exceptionWithName:NSInternalInconsistencyException \
                            reason:[NSString stringWithFormat:@"You must override %@ in a subclass", NSStringFromSelector(_cmd)] \
                          userInfo:nil]

@implementation CryptoScheme

- (NSInteger)getKeyLengthInBits {
    MethodNotImplemented();
    return 0;
}
- (CCAlgorithm)getContentChiperAlgorithm {
    MethodNotImplemented();
    return 0;
}

- (CCMode)getContentChiperMode {
    MethodNotImplemented();
    return 0;
}

- (CCPadding)getContentChiperPadding {
    MethodNotImplemented();
    return 0;
}

- (NSInteger)getContentChiperIVLength {
    MethodNotImplemented();
    return 0;
}

- (NSData *)randomGenerateIV {
    NSInteger keyLength = [self getContentChiperIVLength];
    
    unsigned char buf[keyLength];
    CCRandomGenerateBytes(buf, sizeof(buf));
    return [NSData dataWithBytes:buf length:sizeof(buf)];
}

- (NSData *)randomGenerateKey {
    NSInteger keyLength = [self getKeyLengthInBits];
    
    unsigned char buf[keyLength];
    CCRandomGenerateBytes(buf, sizeof(buf));
    return [NSData dataWithBytes:buf length:sizeof(buf)];
}

+ (NSData *)incrementBlocks:(NSData *)counter blockDelta:(int64_t)blockDelta error:(NSError **)error {
    if (blockDelta == 0) {
        return counter;
    }
    if (counter == nil || counter.length != 16) {
        *error = [NSError errorWithDomain:OSSClientErrorDomain
                                     code:OSSClientErrorCodeCryptoUpdate
                                 userInfo:@{OSSErrorMessageTOKEN: @"iv is nil or not 16-bytes."}];
        return nil;
    }
    
    unsigned char* c_counter = (unsigned char *)malloc(16 * sizeof(uint8_t));
    bcopy([counter bytes], c_counter, counter.length);
    
    size_t block_size = 8 * sizeof(uint8_t);
    UInt8 *buf = (UInt8 *)malloc(block_size);

    for (int i = 12; i <= 15; i++) {
        buf[i - 8] = c_counter[i];
    }
    int64_t val = NSSwapLongLong(*(int64_t *)buf) + blockDelta;
    
    bzero(buf, block_size);
    *(int64_t *)buf = NSSwapLongLong(val);
    unsigned char *result = buf;
    
    for (int i = 8; i <= 15; i++) {
        c_counter[i] = result[i - 8];
    }
    
    NSData *incrementCounter = [NSData dataWithBytes:c_counter length:counter.length];
    free(buf);
    free(c_counter);
    
    return incrementCounter;
}

@end
