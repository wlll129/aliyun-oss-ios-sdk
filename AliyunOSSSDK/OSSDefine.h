//
//  OSSDefine.h
//  AliyunOSSiOS
//
//  Created by zhouzhuo on 5/1/16.
//  Copyright © 2016 zhouzhuo. All rights reserved.
//

#import <Foundation/Foundation.h>

#ifndef OSSDefine_h
#define OSSDefine_h

#if TARGET_OS_IOS
#define OSSUAPrefix                             @"aliyun-sdk-ios"
#elif TARGET_OS_OSX
#define OSSUAPrefix                             @"aliyun-sdk-mac"
#endif
#define OSSSDKVersion                           @"2.10.20"
#define OSSUserAgentSuffix                      @"/OSSEncryptionClient"

#define OSSListBucketResultXMLTOKEN             @"ListBucketResult"
#define OSSNameXMLTOKEN                         @"Name"
#define OSSDelimiterXMLTOKEN                    @"Delimiter"
#define OSSMarkerXMLTOKEN                       @"Marker"
#define OSSKeyMarkerXMLTOKEN                    @"KeyMarker"
#define OSSNextMarkerXMLTOKEN                   @"NextMarker"
#define OSSNextKeyMarkerXMLTOKEN                @"NextKeyMarker"
#define OSSUploadIdMarkerXMLTOKEN               @"UploadIdMarker"
#define OSSNextUploadIdMarkerXMLTOKEN           @"NextUploadIdMarker"
#define OSSMaxKeysXMLTOKEN                      @"MaxKeys"
#define OSSMaxUploadsXMLTOKEN                   @"MaxUploads"
#define OSSIsTruncatedXMLTOKEN                  @"IsTruncated"
#define OSSContentsXMLTOKEN                     @"Contents"
#define OSSUploadXMLTOKEN                       @"Upload"
#define OSSKeyXMLTOKEN                          @"Key"
#define OSSLastModifiedXMLTOKEN                 @"LastModified"
#define OSSETagXMLTOKEN                         @"ETag"
#define OSSTypeXMLTOKEN                         @"Type"
#define OSSSizeXMLTOKEN                         @"Size"
#define OSSStorageClassXMLTOKEN                 @"StorageClass"
#define OSSCommonPrefixesXMLTOKEN               @"CommonPrefixes"
#define OSSOwnerXMLTOKEN                        @"Owner"
#define OSSAccessControlListXMLTOKEN            @"AccessControlList"
#define OSSGrantXMLTOKEN                        @"Grant"
#define OSSIDXMLTOKEN                           @"ID"
#define OSSDisplayNameXMLTOKEN                  @"DisplayName"
#define OSSBucketsXMLTOKEN                      @"Buckets"
#define OSSBucketXMLTOKEN                       @"Bucket"
#define OSSCreationDate                         @"CreationDate"
#define OSSPrefixXMLTOKEN                       @"Prefix"
#define OSSUploadIdXMLTOKEN                     @"UploadId"
#define OSSLocationXMLTOKEN                     @"Location"
#define OSSNextPartNumberMarkerXMLTOKEN         @"NextPartNumberMarker"
#define OSSMaxPartsXMLTOKEN                     @"MaxParts"
#define OSSPartXMLTOKEN                         @"Part"
#define OSSPartNumberXMLTOKEN                   @"PartNumber"

#define OSSClientErrorDomain                    @"com.aliyun.oss.clientError"
#define OSSServerErrorDomain                    @"com.aliyun.oss.serverError"

#define OSSErrorMessageTOKEN                    @"ErrorMessage"

#define OSSHttpHeaderContentDisposition         @"Content-Disposition"
#define OSSHttpHeaderXOSSCallback               @"x-oss-callback"
#define OSSHttpHeaderXOSSCallbackVar            @"x-oss-callback-var"
#define OSSHttpHeaderContentEncoding            @"Content-Encoding"
#define OSSHttpHeaderContentType                @"Content-Type"
#define OSSHttpHeaderContentMD5                 @"Content-MD5"
#define OSSHttpHeaderContentRange               @"Content-Range"
#define OSSHttpHeaderContentLength              @"Content-Length"
#define OSSHttpHeaderCacheControl               @"Cache-Control"
#define OSSHttpHeaderExpires                    @"Expires"
#define OSSHttpHeaderHashSHA1                   @"x-oss-hash-sha1"
#define OSSHttpHeaderBucketACL                  @"x-oss-acl"
#define OSSHttpHeaderObjectACL                  @"x-oss-object-acl"
#define OSSHttpHeaderCopySource                 @"x-oss-copy-source"
#define OSSHttpHeaderSymlinkTarget              @"x-oss-symlink-target"
#define OSSHttpHeaderCryptoKey                  @"x-oss-meta-client-side-encryption-key"
#define OSSHttpHeaderCryptoIV                   @"x-oss-meta-client-side-encryption-start"
#define OSSHttpHeaderCryptoCEKAlg               @"x-oss-meta-client-side-encryption-cek-alg"
#define OSSHttpHeaderCryptoWrapAlg              @"x-oss-meta-client-side-encryption-wrap-alg"
#define OSSHttpHeaderCryptoMatdesc              @"x-oss-meta-client-side-encryption-matdesc"
#define OSSHttpHeaderCryptoDataSize             @"x-oss-meta-client-side-encryption-data-size"
#define OSSHttpHeaderCryptoPartSize             @"x-oss-meta-client-side-encryption-part-size"
#define OSSHttpHeaderCryptoUnencryptedContentLength @"x-oss-meta-client-side-encryption-unencrypted-content-length"
#define OSSHttpHeaderCryptoContentMD5           @"x-oss-meta-client-side-encryption-unencrypted-content-md5"

#define OSSHttpQueryProcess                     @"x-oss-process"

#define OSSDefaultRetryCount                    3
#define OSSDefaultMaxConcurrentNum              5
#define OSSDefaultTimeoutForRequestInSecond     15
#define OSSDefaultTimeoutForResourceInSecond    7 * 24 * 60 * 60
#define OSSDefaultThreadNum                     5

#endif /* OSSDefine_h */
