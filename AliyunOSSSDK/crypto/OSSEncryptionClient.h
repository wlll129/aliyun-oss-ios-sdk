//
//  OSSEncryptionClient.h
//  AliyunOSSSDK
//
//  Created by ws on 2021/6/30.
//

#import <AliyunOSSiOS/AliyunOSSiOS.h>
#import "EncryptionMaterials.h"

@class CryptoConfiguration;
@class MultipartUploadCryptoContext;
NS_ASSUME_NONNULL_BEGIN

@interface OSSEncryptionClient : OSSClient

- (instancetype)initWithEndpoint:(NSString *)endpoint
              credentialProvider:(id<OSSCredentialProvider>)credentialProvider
             clientConfiguration:(OSSClientConfiguration *)conf
             encryptionMaterials:(id<EncryptionMaterials>)encryptionMaterials
                    cryptoConfig:(CryptoConfiguration *)cryptoConfig;


/// Please use -[OSSEncryptionClient multipartUploadInit:context:]
- (OSSTask *)multipartUploadInit:(OSSInitMultipartUploadRequest *)request NS_UNAVAILABLE;
/// Please use -[OSSEncryptionClient uploadPart:context:]
- (OSSTask *)uploadPart:(OSSUploadPartRequest *)request NS_UNAVAILABLE;

- (OSSTask *)appendObject:(OSSAppendObjectRequest *)request NS_UNAVAILABLE;
- (OSSTask *)appendObject:(OSSAppendObjectRequest *)request withCrc64ecma:(nullable NSString *)crc64ecma NS_UNAVAILABLE;

/// The corresponding RESTFul API: InitiateMultipartUpload
/// @param request instance which specifies the bucket name, object key and metadata.
- (OSSTask *)multipartUploadInit:(OSSInitMultipartUploadRequest *)request context:(MultipartUploadCryptoContext *)context;
- (OSSTask *)uploadPart:(OSSUploadPartRequest *)request context:(MultipartUploadCryptoContext *)context;

@end

NS_ASSUME_NONNULL_END
