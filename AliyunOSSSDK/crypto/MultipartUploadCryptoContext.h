//
//  UploadCheckPoint.h
//  AliyunOSSSDK
//
//  Created by ws on 2021/7/21.
//  Copyright © 2021 aliyun. All rights reserved.
//

#import <Foundation/Foundation.h>

@class ContentCryptoMaterial;
NS_ASSUME_NONNULL_BEGIN

@interface MultipartUploadCryptoContext : NSObject <NSCoding>

@property (nonatomic, strong) NSString *uploadId;
@property (nonatomic, strong) ContentCryptoMaterial *cryptoMaterial;
@property (nonatomic, assign) NSUInteger partSize;
@property (nonatomic, assign) NSUInteger dataSize;

- (instancetype)initWithUploadId:(NSString *)uploadId
                  cryptoMaterial:(ContentCryptoMaterial *)cryptoMaterial
                        partSize:(NSUInteger)partSize
                        dataSize:(NSUInteger)dataSize;

@end

NS_ASSUME_NONNULL_END
