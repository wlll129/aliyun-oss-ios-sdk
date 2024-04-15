//
//  CryptoConfiguration.m
//  AliyunOSSSDK iOS
//
//  Created by ws on 2021/7/29.
//  Copyright © 2021 aliyun. All rights reserved.
//

#import "CryptoConfiguration.h"

@implementation CryptoConfiguration

- (instancetype)init
{
    self = [super init];
    if (self) {
        self.storageMethod = CryptoStorageMethodObjectMetadata;
        self.contentCryptoMode = ContentCryptoModeAESCTRMode;
    }
    return self;
}

@end
