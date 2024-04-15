//
//  EncryptionMaterials.h
//  AliyunOSSSDK iOS
//
//  Created by ws on 2021/7/29.
//  Copyright © 2021 aliyun. All rights reserved.
//

#import <Foundation/Foundation.h>

@class ContentCryptoMaterial;

NS_ASSUME_NONNULL_BEGIN

@protocol EncryptionMaterials <NSObject>

extern NSString *keyWrapAlgorithm;

- (void)decrypt:(nonnull ContentCryptoMaterial *)contentCryptoMaterial
          error:(NSError **)error;
- (void)encrypt:(nonnull ContentCryptoMaterial *)contentCryptoMaterial
          error:(NSError **)error;

@end

NS_ASSUME_NONNULL_END
