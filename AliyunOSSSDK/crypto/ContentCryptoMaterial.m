//
//  ContentCryptoMaterial.m
//  AliyunOSSSDK
//
//  Created by ws on 2021/6/28.
//

#import "ContentCryptoMaterial.h"
#import <objc/runtime.h>

@implementation ContentCryptoMaterial

- (instancetype)initWithOperation:(CCOperation)operation
                              cek:(NSData *)cek
                               iv:(NSData *)iv
                             mode:(CCMode)mode
                        algorithm:(CCAlgorithm)algorithm
                          padding:(CCPadding)padding {
    self = [super init];
    if (self) {
        _operation = operation;
        _cek = cek;
        _iv = iv;
        _mode = mode;
        _algorithm = algorithm;
        _padding = padding;
    }
    return self;
}

- (instancetype)initWithOperation:(CCOperation)operation
                     encryptedCEK:(NSData *)encryptedCEK
                      encryptedIV:(NSData *)encryptedIV
                             mode:(CCMode)mode
                        algorithm:(CCAlgorithm)algorithm
                          padding:(CCPadding)padding {
    self = [super init];
    if (self) {
        _operation = operation;
        _encryptedCEK = encryptedCEK;
        _encryptedIV = encryptedIV;
        _mode = mode;
        _algorithm = algorithm;
        _padding = padding;
    }
    return self;
}

- (void)encodeWithCoder:(NSCoder *)aCoder {
    unsigned int count = 0;
    Ivar * ivarList = class_copyIvarList([ContentCryptoMaterial class], &count);
    for (int i = 0; i < count; i++) {
        const char * name = ivar_getName(ivarList[i]);
        NSString * strname = [NSString stringWithUTF8String:name];
        NSObject * value = [self valueForKey:strname];
        if (strname && value) {
            [aCoder encodeObject:value forKey:strname];
        }
    }
    free(ivarList);
}

- (instancetype)initWithCoder:(NSCoder *)coder {
    if (self = [super init]) {
        unsigned int count = 0;
        Ivar * ivarList = class_copyIvarList([ContentCryptoMaterial class], &count);
        for (int i = 0; i < count; i++) {
            const char * name = ivar_getName(ivarList[i]);
            NSString * strname = [NSString stringWithUTF8String:name];
            id value = [coder decodeObjectForKey:strname];
            if (value && strname) {
                [self setValue:value forKey:strname];
            }
        }
        free(ivarList);
    }
    return self;
}

- (NSString *)cekAlg {
    NSString *cekAlg = @"";
    cekAlg = [NSString stringWithFormat:@"%@/%@/%@", [self algorithmString], [self modeString], [self paddingString]];
    return cekAlg;
}

- (NSString *)algorithmString {
    NSString *algorithmString = @"";
    switch (self.algorithm) {
        case kCCAlgorithmAES:
            algorithmString = @"AES";
            break;
            
        default:
            break;
    }
    return algorithmString;
}

- (void)setAlgorithmString:(NSString *)algorithmString {
    if ([algorithmString isEqualToString:@"AES"]) {
        _algorithm = kCCAlgorithmAES;
    }
}

- (NSString *)paddingString {
    NSString *paddingString = @"";
    switch (self.padding) {
        case ccNoPadding:
            paddingString = @"NoPadding";
            break;
            
        default:
            break;
    }
    return paddingString;
}

- (void)setPaddingString:(NSString *)paddingString {
    if ([paddingString isEqualToString:@"AES"]) {
        _padding = ccNoPadding;
    }
}

- (NSString *)modeString {
    NSString *modeString = @"";
    switch (self.mode) {
        case kCCModeCTR:
            modeString = @"CTR";
            break;
            
        default:
            break;
    }
    return modeString;
}

- (void)setModeString:(NSString *)modeString {
    if ([modeString isEqualToString:@"CTR"]) {
        _mode = kCCModeCTR;
    }
}

@end

