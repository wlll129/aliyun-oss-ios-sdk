//
//  CryptoModule.h
//  AliyunOSSSDK
//
//  Created by ws on 2022/1/10.
//  Copyright © 2022 aliyun. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@class CryptoScheme;
@class OSSSimpleRSAEncryptionMaterials;
@class OSSTask;
@class OSSGetObjectRequest;
@class OSSPutObjectRequest;
@class OSSNetworkingRequestDelegate;
@class OSSInitMultipartUploadRequest;
@class MultipartUploadCryptoContext;
@class OSSClient;
@class OSSUploadPartRequest;

@interface CryptoModule : NSObject

@property (nonatomic, strong, readonly) CryptoScheme *cryptoScheme;
@property (nonatomic, strong, readonly) OSSSimpleRSAEncryptionMaterials *encryptionMaterials;

- (instancetype)initWithCryptoScheme:(CryptoScheme *)cryptoScheme
                 encryptionMaterials:(OSSSimpleRSAEncryptionMaterials *)encryptionMaterials;

- (OSSTask *)putObjectSecurely:(OSSPutObjectRequest *)request requestDelegate:(OSSNetworkingRequestDelegate *)requestDelegate;
- (OSSTask *)getObjectSecurely:(OSSGetObjectRequest *)request requestDelegate:(OSSNetworkingRequestDelegate *)requestDelegate;

- (OSSTask *)multipartUploadInitSecurely:(OSSInitMultipartUploadRequest *)request
                                 context:(MultipartUploadCryptoContext *)context
                                  client:(OSSClient *)client;
- (OSSTask *)uploadPart:(OSSUploadPartRequest *)request
                context:(MultipartUploadCryptoContext *)context
                 client:(OSSClient *)client;

@end

NS_ASSUME_NONNULL_END
