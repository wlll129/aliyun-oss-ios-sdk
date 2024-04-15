//
//  CryptoModule.m
//  AliyunOSSSDK
//
//  Created by ws on 2022/1/10.
//  Copyright © 2022 aliyun. All rights reserved.
//

#import "CryptoModule.h"
#import "CryptoScheme.h"
#import "CryptoSchemeAesCtr.h"
#import "CryptoConfiguration.h"
#import "OSSModel.h"
#import "OSSNetworkingRequestDelegate.h"
#import "OSSCryptoHttpResponseParser.h"
#import "OSSSimpleRSAEncryptionMaterials.h"
#import "Cryptor.h"

@interface Cryptor(ContentCryptoMaterial)

- (instancetype)initWithCryptoMaterail:(ContentCryptoMaterial *)cryptoMaterail;

@end

@implementation CryptoModule

- (instancetype)initWithCryptoScheme:(CryptoScheme *)cryptoScheme
                 encryptionMaterials:(OSSSimpleRSAEncryptionMaterials *)encryptionMaterials {
    self = [super init];
    if (self) {
        _cryptoScheme = cryptoScheme;
        _encryptionMaterials = encryptionMaterials;
    }
    return self;
}

- (OSSTask *)putObjectSecurely:(OSSPutObjectRequest *)request requestDelegate:(OSSNetworkingRequestDelegate *)requestDelegate {
    
    CipherInputStream *inputStream = nil;
    
    ContentCryptoMaterial *cryptoMaterial = [self buildContentCryptoMaterialWithCryptoScheme:self.cryptoScheme];
    Cryptor *cryptor = [[Cryptor alloc] initWithCryptoMaterail:cryptoMaterial];
    if (requestDelegate.uploadingFileURL) {
        inputStream = [[CipherInputStream alloc] initWithURL:requestDelegate.uploadingFileURL cryptor:cryptor];
        requestDelegate.uploadingFileURL = nil;
    } else if (requestDelegate.uploadingData) {
        inputStream = [[CipherInputStream alloc] initWithData:requestDelegate.uploadingData cryptor:cryptor];
        requestDelegate.uploadingData = nil;
    }
    requestDelegate.uploadingInputStream = inputStream;
    
    NSError *error;
    [self.encryptionMaterials encrypt:cryptoMaterial error:&error];
    if (error) {
        return [OSSTask taskWithError:error];
    }
    
    NSDictionary *headers = [self headerWithContentCryptoMaterial:cryptoMaterial];
    [headers enumerateKeysAndObjectsUsingBlock:^(id  _Nonnull key, id  _Nonnull obj, BOOL * _Nonnull stop) {
        requestDelegate.allNeededMessage.headerParams[key] = obj;
    }];
    error = nil;
    [self updateContentMd5:requestDelegate];
    [self updateContentLength:requestDelegate error:&error];
    if (error) {
        return [OSSTask taskWithError:error];
    }
    
    return [OSSTask taskWithResult:nil];
}

- (OSSTask *)getObjectSecurely:(OSSGetObjectRequest *)request requestDelegate:(OSSNetworkingRequestDelegate *)requestDelegate {
    
    NSString * rangeString = nil;
    OSSTask *task = [CryptoModule getAdjustedCryptoRange:request.range];
    if (task.error) {
        return task;
    }
    OSSRange *adjustedCryptoRange = task.result;
    if (adjustedCryptoRange) {
        rangeString = [adjustedCryptoRange toHeaderString];
    }
    
    OSSCryptoHttpResponseParser *responseParser = [[OSSCryptoHttpResponseParser alloc] initForOperationType:OSSOperationTypeGetObject encryptionMaterials:self.encryptionMaterials cryptoScheme:self.cryptoScheme];
    responseParser.range = request.range;
    responseParser.adjustedCryptoRange = adjustedCryptoRange;
    responseParser.downloadingFileURL = request.downloadToFileURL;
    
    requestDelegate.responseParser = responseParser;
    requestDelegate.allNeededMessage.range = rangeString;
    
    return [OSSTask taskWithResult:requestDelegate];
}

- (OSSTask *)multipartUploadInitSecurely:(OSSInitMultipartUploadRequest *)request
                                 context:(MultipartUploadCryptoContext *)context
                                  client:(OSSClient *)client {
    OSSTask *task = [self checkMultipartContext:context];
    if (task) {
        return task;
    }
    ContentCryptoMaterial *cryptoMaterial = [self buildContentCryptoMaterialWithCryptoScheme:self.cryptoScheme];

    NSError *error;
    [self.encryptionMaterials encrypt:cryptoMaterial error:&error];
    if (error) {
        return [OSSTask taskWithError:error];
    }
    
    NSMutableDictionary *headers = [NSMutableDictionary dictionaryWithDictionary:request.objectMeta];
    headers[OSSHttpHeaderCryptoKey] = [cryptoMaterial.encryptedCEK base64EncodedStringWithOptions:0];
    headers[OSSHttpHeaderCryptoIV] = [cryptoMaterial.encryptedIV base64EncodedStringWithOptions:0];
    headers[OSSHttpHeaderCryptoCEKAlg] = cryptoMaterial.cekAlg;
    headers[OSSHttpHeaderCryptoWrapAlg] = cryptoMaterial.keyWrapAlgorithm;
    headers[OSSHttpHeaderCryptoMatdesc] = [cryptoMaterial.materialsDescription base64JsonString];
    headers[OSSHttpHeaderCryptoDataSize] = [@(context.dataSize) stringValue];
    headers[OSSHttpHeaderCryptoPartSize] = [@(context.partSize) stringValue];
    
    request.objectMeta = headers;
    return [[client multipartUploadInit:request] continueWithBlock:^id _Nullable(OSSTask * _Nonnull task) {
        OSSInitMultipartUploadResult *result = task.result;
        context.uploadId = result.uploadId;
        context.cryptoMaterial = cryptoMaterial;
        return task;
    }];
}

- (OSSTask *)uploadPart:(OSSUploadPartRequest *)request
                context:(MultipartUploadCryptoContext *)context
                 client:(OSSClient *)client {
    OSSTask *task = [self checkMultipartContext:context];
    if (task) {
        return task;
    }
    if (![request.uploadId isEqualToString:context.uploadId]) {
        NSError *error = [NSError errorWithDomain:OSSClientErrorDomain
                                             code:OSSClientErrorCodeInvalidArgument
                                         userInfo:@{OSSErrorMessageTOKEN: [NSString stringWithFormat:@"The multipartUploadCryptoContextcontext input upload id is invalid.context uploadid:%@,uploadRequest uploadid:%@", context.uploadId, request.uploadId]}];
        return [OSSTask taskWithError:error];
    }
    ContentCryptoMaterial *cryptoMaterial = context.cryptoMaterial;
    NSError *error;
    
    NSInteger offset = context.partSize * (request.partNumber - 1);
    NSInteger skipBlock = offset / BlockSize;
    NSData *iv = [CryptoScheme incrementBlocks:cryptoMaterial.iv blockDelta:skipBlock error:&error];
    if (error) {
        return [OSSTask taskWithError:error];
    }
    Cryptor *cryptor = [[Cryptor alloc] initWithOperation:cryptoMaterial.operation
                                                      cek:cryptoMaterial.cek
                                                       iv:iv
                                                     mode:cryptoMaterial.mode
                                                algorithm:cryptoMaterial.algorithm
                                                  padding:cryptoMaterial.padding];
    NSData *uploadPartData = [cryptor cryptorUpdate:request.uploadPartData error:&error];
    if (error) {
        return [OSSTask taskWithError:error];
    }
    request.uploadPartData = uploadPartData;
    request.contentMd5 = [OSSUtil base64Md5ForData:uploadPartData];
    
    return [client uploadPart:request];
}

#pragma mark - private
- (ContentCryptoMaterial *)buildContentCryptoMaterialWithCryptoScheme:(CryptoScheme *)cryptoScheme {
    NSData *cek = [cryptoScheme randomGenerateKey];
    NSData *iv = [cryptoScheme randomGenerateIV];
    CCMode mode = [cryptoScheme getContentChiperMode];
    CCAlgorithm algorithm = [cryptoScheme getContentChiperAlgorithm];
    CCPadding padding = [cryptoScheme getContentChiperPadding];
    ContentCryptoMaterial *cryptoMaterial = [[ContentCryptoMaterial alloc] initWithOperation:kCCEncrypt
                                                                                         cek:cek
                                                                                          iv:iv
                                                                                        mode:mode
                                                                                   algorithm:algorithm
                                                                                     padding:padding];
    return cryptoMaterial;
}

- (CryptoScheme *)getCryptoScheme:(ContentCryptoMode)mode {
    switch (mode) {
        case ContentCryptoModeAESCTRMode:
        default:
            return [CryptoSchemeAesCtr new];
            break;
    }
}

+ (OSSTask *)getAdjustedCryptoRange:(OSSRange *)range {
    if (range == nil) {
        return [OSSTask taskWithResult:nil];
    }
    if ((range.startPosition > range.endPosition) ||
        (range.startPosition < 0) ||
        (range.endPosition <= 0)) {
        return [OSSTask taskWithError:[NSError errorWithDomain:OSSClientErrorDomain
                                                          code:OSSClientErrorCodeInvalidArgument
                                                      userInfo:@{OSSErrorMessageTOKEN: [NSString stringWithFormat:@"Your input get-range is illegal. + range:%lld~%lld", range.startPosition, range.endPosition]}]];
    }
    
    OSSRange *adjustedCryptoRange = [OSSRange new];
    adjustedCryptoRange.startPosition = [self getCipherBlockLowerBound:range.startPosition];
    adjustedCryptoRange.endPosition = range.endPosition;
    return [OSSTask taskWithResult:adjustedCryptoRange];
}

+ (int64_t)getCipherBlockLowerBound:(int64_t)leftmostBytePosition {
    int64_t cipherBlockSize = BlockSize;
    int64_t offset = leftmostBytePosition % cipherBlockSize;
    int64_t lowerBound = leftmostBytePosition - offset;
    return lowerBound;
}

- (NSDictionary *)headerWithContentCryptoMaterial:(ContentCryptoMaterial *)cryptoMaterial {
    NSMutableDictionary *headers = @{}.mutableCopy;
    
    headers[OSSHttpHeaderCryptoKey] = [cryptoMaterial.encryptedCEK base64EncodedStringWithOptions:0];
    headers[OSSHttpHeaderCryptoIV] = [cryptoMaterial.encryptedIV base64EncodedStringWithOptions:0];
    headers[OSSHttpHeaderCryptoCEKAlg] = cryptoMaterial.cekAlg;
    headers[OSSHttpHeaderCryptoWrapAlg] = cryptoMaterial.keyWrapAlgorithm;
    headers[OSSHttpHeaderCryptoMatdesc] = [cryptoMaterial.materialsDescription base64JsonString];
    
    return headers;
}

- (void)updateContentMd5:(OSSNetworkingRequestDelegate *)requestDelegate {
    if (requestDelegate.allNeededMessage.contentMd5) {
        requestDelegate.allNeededMessage.headerParams[OSSHttpHeaderCryptoContentMD5] = requestDelegate.allNeededMessage.contentMd5;
        requestDelegate.allNeededMessage.contentMd5 = nil;
    }
    
    if (requestDelegate.allNeededMessage.headerParams[OSSHttpHeaderContentMD5]) {
        requestDelegate.allNeededMessage.headerParams[OSSHttpHeaderCryptoContentMD5] = requestDelegate.allNeededMessage.headerParams[OSSHttpHeaderContentMD5];
        [requestDelegate.allNeededMessage.headerParams removeObjectForKey:OSSHttpHeaderContentMD5];
    }
}

- (void)updateContentLength:(OSSNetworkingRequestDelegate *)requestDelegate error:(NSError **)error {
    unsigned long long length = [self plaintextLength:requestDelegate error:error];
    if (length > 0) {
        requestDelegate.allNeededMessage.headerParams[OSSHttpHeaderCryptoUnencryptedContentLength] = [NSString stringWithFormat:@"%@", @(length)];
    }
    if (requestDelegate.allNeededMessage.headerParams[OSSHttpHeaderContentLength]) {
        requestDelegate.allNeededMessage.headerParams[OSSHttpHeaderCryptoUnencryptedContentLength] = requestDelegate.allNeededMessage.headerParams[OSSHttpHeaderContentLength];
    }
}

- (unsigned long long)plaintextLength:(OSSNetworkingRequestDelegate *)requestDelegate error:(NSError **)error {
    if (requestDelegate.uploadingFileURL) {
        NSError *fmError;
        NSFileManager *fm = [NSFileManager defaultManager];
        NSDictionary *attributes = [fm attributesOfItemAtPath:requestDelegate.uploadingFileURL.absoluteString
                                                        error:&fmError];
        unsigned long long length = attributes.fileSize;
        if (!fmError) {
            return length;
        } else {
            *error = [NSError errorWithDomain:OSSClientErrorDomain
                                         code:OSSClientErrorCodeInvalidArgument
                                     userInfo:@{OSSErrorMessageTOKEN: [NSString stringWithFormat:@"Get file size failed! %@", fmError.description]}];
            return 0;
        }
    }
    return 0;
}


- (OSSTask *)checkMultipartContext:(MultipartUploadCryptoContext *)context {
    if (!context) {
        return [OSSTask taskWithError:[NSError errorWithDomain:OSSClientErrorDomain
                                                          code:OSSClientErrorCodeInvalidArgument
                                                      userInfo:@{OSSErrorMessageTOKEN: @"MultipartUploadCryptoContext should not be null."}]];
    }
    if (0 != (context.partSize % BlockSize) || context.partSize <= 0) {
        return [OSSTask taskWithError:[NSError errorWithDomain:OSSClientErrorDomain
                                                          code:OSSClientErrorCodeInvalidArgument
                                                      userInfo:@{OSSErrorMessageTOKEN: @"MultipartUploadCryptoContext part size is not 16 bytes alignment."}]];
    }
    return nil;
}

@end

@implementation Cryptor(ContentCryptoMaterial)

- (instancetype)initWithCryptoMaterail:(ContentCryptoMaterial *)cryptoMaterail {
    self = [self initWithOperation:cryptoMaterail.operation
                               cek:cryptoMaterail.cek
                                iv:cryptoMaterail.iv
                              mode:cryptoMaterail.mode
                         algorithm:cryptoMaterail.algorithm
                           padding:cryptoMaterail.padding];
    return self;
}

@end
