//
//  CryptoConfiguration.h
//  AliyunOSSSDK iOS
//
//  Created by ws on 2021/7/29.
//  Copyright © 2021 aliyun. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSUInteger, CryptoStorageMethod) {
    CryptoStorageMethodObjectMetadata
};

typedef NS_ENUM(NSUInteger, ContentCryptoMode) {
    ContentCryptoModeAESCTRMode
};

@interface CryptoConfiguration : NSObject


/// the storage method to the specified storage method.
@property (nonatomic) CryptoStorageMethod storageMethod;

/// the content crypto mode to the specified crypto mode.
@property (nonatomic) ContentCryptoMode contentCryptoMode;

@end

NS_ASSUME_NONNULL_END
