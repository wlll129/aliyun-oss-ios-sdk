//
//  UploadCheckPoint.m
//  AliyunOSSSDK
//
//  Created by ws on 2021/7/21.
//  Copyright © 2021 aliyun. All rights reserved.
//

#import "MultipartUploadCryptoContext.h"

@implementation MultipartUploadCryptoContext

- (void)encodeWithCoder:(nonnull NSCoder *)coder {
    [coder encodeObject:_uploadId forKey:@"uploadId"];
    [coder encodeObject:_cryptoMaterial forKey:@"cryptoMaterial"];
    [coder encodeObject:@(_partSize) forKey:@"partSize"];
    [coder encodeObject:@(_dataSize) forKey:@"dataSize"];
}

- (nullable instancetype)initWithCoder:(nonnull NSCoder *)coder {
    if (self = [super init]) {
        _uploadId = [coder decodeObjectForKey:@"uploadId"];
        _cryptoMaterial = [coder decodeObjectForKey:@"cryptoMaterial"];
        _partSize = [[coder decodeObjectForKey:@"partSize"] integerValue];
        _dataSize = [[coder decodeObjectForKey:@"dataSize"] integerValue];
    }
    return self;
}

- (instancetype)initWithUploadId:(NSString *)uploadId
                  cryptoMaterial:(ContentCryptoMaterial *)cryptoMaterial
                        partSize:(NSUInteger)partSize
                        dataSize:(NSUInteger)dataSize{
    self = [super init];
    if (self) {
        _uploadId = uploadId;
        _cryptoMaterial = cryptoMaterial;
        _partSize = partSize;
        _dataSize = dataSize;
    }
    return self;
}

@end
