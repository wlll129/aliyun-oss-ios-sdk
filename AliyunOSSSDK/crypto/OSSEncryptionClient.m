//
//  OSSEncryptionClient.m
//  AliyunOSSSDK
//
//  Created by ws on 2021/6/30.
//

#import "OSSEncryptionClient.h"
#import "OSSSimpleRSAEncryptionMaterials.h"
#import "OSSCryptoHttpResponseParser.h"
#import "CryptoConfiguration.h"
#import "CryptoScheme.h"
#import "CryptoSchemeAesCtr.h"

#import "ContentCryptoMaterial.h"
#import "CipherInputStream.h"
#import "MultipartUploadCryptoContext.h"
#import "Cryptor.h"
#import "CryptoModule.h"

static NSString * const kClientRecordNameWithCommonPrefix = @"oss_partInfos_storage_name";
static NSString * const kClientRecordNameWithSequentialSuffix = @"-sequential";
static NSString * const kClientRecordNameWithEncryptionSuffix = @"-encryption";
static NSString * const kClientRecordNameWithCRC64Suffix = @"-crc64";

@interface Cryptor(ContentCryptoMaterial)

- (instancetype)initWithCryptoMaterail:(ContentCryptoMaterial *)cryptoMaterail;

@end

@interface OSSRequest ()

@property (nonatomic, strong) OSSNetworkingRequestDelegate * requestDelegate;

@end

@interface OSSClient (Encryption)

- (OSSTask *)checkPutObjectFileURL:(OSSPutObjectRequest *)request;
- (void)enableCRC64WithFlag:(OSSRequestCRCFlag)flag requestDelegate:(OSSNetworkingRequestDelegate *)delegate;
- (OSSTask *)invokeRequest:(OSSNetworkingRequestDelegate *)request requireAuthentication:(BOOL)requireAuthentication;
- (unsigned long long)getSizeWithFilePath:(nonnull NSString *)filePath error:(NSError **)error;
- (NSUInteger)judgePartSizeForMultipartRequest:(OSSMultipartUploadRequest *)request fileSize:(unsigned long long)fileSize;
- (NSString *)readUploadIdForRequest:(OSSResumableUploadRequest *)request recordFilePath:(NSString **)recordFilePath sequential:(BOOL)sequential;
- (OSSTask *)processListPartsWithObjectKey:(nonnull NSString *)objectKey bucket:(nonnull NSString *)bucket uploadId:(NSString * _Nonnull *)uploadId uploadedParts:(nonnull NSMutableArray *)uploadedParts uploadedLength:(NSUInteger *)uploadedLength totalSize:(unsigned long long)totalSize partSize:(NSUInteger)partSize;
- (OSSTask *)abortMultipartUpload:(OSSMultipartUploadRequest *)request sequential:(BOOL)sequential resumable:(BOOL)resumable;
- (OSSTask *)sequentialUpload:(OSSMultipartUploadRequest *)request uploadIndex:(NSMutableArray *)alreadyUploadIndex uploadPart:(NSMutableArray *)alreadyUploadPart count:(NSUInteger)partCout uploadedLength:(NSUInteger *)uploadedLength fileSize:(unsigned long long)uploadFileSize;
- (OSSTask *)upload:(OSSMultipartUploadRequest *)request uploadIndex:(NSMutableArray *)alreadyUploadIndex uploadPart:(NSMutableArray *)alreadyUploadPart count:(NSUInteger)partCout uploadedLength:(NSUInteger *)uploadedLength fileSize:(unsigned long long)uploadFileSize;
- (OSSTask *)processCompleteMultipartUpload:(OSSMultipartUploadRequest *)request partInfos:(NSArray<OSSPartInfo *> *)partInfos clientCrc64:(uint64_t)clientCrc64 recordFilePath:(NSString *)recordFilePath localPartInfosPath:(NSString *)localPartInfosPath;
- (void)executePartUpload:(OSSMultipartUploadRequest *)request totalBytesExpectedToSend:(unsigned long long)totalBytesExpectedToSend totalBytesSent:(NSUInteger *)totalBytesSent index:(NSUInteger)idx partData:(NSData *)partData alreadyUploadPart:(NSMutableArray *)uploadedParts localParts:(NSMutableDictionary *)localParts errorTask:(OSSTask **)errorTask;
- (void)processForLocalPartInfos:(NSMutableDictionary *)localPartInfoDict partInfo:(OSSPartInfo *)partInfo uploadId:(NSString *)uploadId;
- (OSSTask *)persistencePartInfos:(NSDictionary *)partInfos withUploadId:(NSString *)uploadId;
- (void)checkRequestCrc64Setting:(OSSRequest *)request;
- (OSSTask *)preChecksForRequest:(OSSMultipartUploadRequest *)request;
- (NSMutableDictionary *)localPartInfosDictoryWithUploadId:(NSString *)uploadId;
+ (NSError *)cancelError;

@end

@interface OSSEncryptionClient()

@property (nonatomic, strong) OSSSimpleRSAEncryptionMaterials *encryptionMaterials;
@property (nonatomic, strong) CryptoConfiguration *cryptoConfig;
@property (nonatomic, strong) CryptoScheme *cryptoScheme;
@property (nonatomic, strong) CryptoModule *cryptoModule;

@end

@implementation OSSEncryptionClient

static NSObject *lock;

- (instancetype)initWithEndpoint:(NSString *)endpoint
              credentialProvider:(id<OSSCredentialProvider>)credentialProvider
             clientConfiguration:(OSSClientConfiguration *)conf
             encryptionMaterials:(id<EncryptionMaterials>)encryptionMaterials
                    cryptoConfig:(CryptoConfiguration *)cryptoConfig {
    self = [super initWithEndpoint:endpoint credentialProvider:credentialProvider clientConfiguration:conf];
    if (self) {
        if (!lock) {
            lock = [NSObject new];
        }
        self.encryptionMaterials = encryptionMaterials;
        self.cryptoConfig = cryptoConfig;
        self.cryptoScheme = [self getCryptoScheme:cryptoConfig.contentCryptoMode];
        self.cryptoModule = [[CryptoModule alloc] initWithCryptoScheme:self.cryptoScheme encryptionMaterials:self.encryptionMaterials];
    }
    return self;
}

#pragma mark - override

- (OSSTask *)putObject:(OSSPutObjectRequest *)request {
    OSSNetworkingRequestDelegate * requestDelegate = request.requestDelegate;
    NSMutableDictionary * headerParams = [NSMutableDictionary dictionaryWithDictionary:request.objectMeta];
    [self enableCRC64WithFlag:request.crcFlag requestDelegate:requestDelegate];
    
    if (request.uploadingData) {
        requestDelegate.uploadingData = request.uploadingData;
        if (requestDelegate.crc64Verifiable)
        {
            NSMutableData *mutableData = [NSMutableData dataWithData:request.uploadingData];
            requestDelegate.contentCRC = [NSString stringWithFormat:@"%llu",[mutableData oss_crc64]];
        }
    }
    if (request.uploadingFileURL) {
        OSSTask *checkIfEmptyTask = [self checkPutObjectFileURL:request];
        if (checkIfEmptyTask.error) {
            return checkIfEmptyTask;
        }
        requestDelegate.uploadingFileURL = request.uploadingFileURL;
    }
    
    if (request.uploadProgress) {
        requestDelegate.uploadProgress = request.uploadProgress;
    }
    if (request.uploadRetryCallback) {
        requestDelegate.retryCallback = request.uploadRetryCallback;
    }
    
    [headerParams oss_setObject:[request.callbackParam base64JsonString] forKey:OSSHttpHeaderXOSSCallback];
    [headerParams oss_setObject:[request.callbackVar base64JsonString] forKey:OSSHttpHeaderXOSSCallbackVar];
    [headerParams oss_setObject:request.contentDisposition forKey:OSSHttpHeaderContentDisposition];
    [headerParams oss_setObject:request.contentEncoding forKey:OSSHttpHeaderContentEncoding];
    [headerParams oss_setObject:request.expires forKey:OSSHttpHeaderExpires];
    [headerParams oss_setObject:request.cacheControl forKey:OSSHttpHeaderCacheControl];
    
    OSSHttpResponseParser *responseParser = [[OSSHttpResponseParser alloc] initForOperationType:OSSOperationTypePutObject];
    responseParser.crc64Verifiable = requestDelegate.crc64Verifiable;
    requestDelegate.responseParser = responseParser;
    
    OSSAllRequestNeededMessage *neededMsg = [[OSSAllRequestNeededMessage alloc] init];
    neededMsg.endpoint = self.endpoint;
    neededMsg.httpMethod = OSSHTTPMethodPUT;
    neededMsg.bucketName = request.bucketName;
    neededMsg.objectKey = request.objectKey;
    neededMsg.contentMd5 = request.contentMd5;
    neededMsg.contentType = request.contentType;
    neededMsg.headerParams = headerParams;
    neededMsg.contentSHA1 = request.contentSHA1;
    requestDelegate.allNeededMessage = neededMsg;
    
    requestDelegate.operType = OSSOperationTypePutObject;
    
    OSSTask *task = [self.cryptoModule putObjectSecurely:request requestDelegate:requestDelegate];
    if (task.error) {
        return task;
    }
    
    return [self invokeRequest:requestDelegate requireAuthentication:request.isAuthenticationRequired];
}

- (OSSTask *)getObject:(OSSGetObjectRequest *)request {
    OSSNetworkingRequestDelegate * requestDelegate = request.requestDelegate;
    
    NSString * rangeString = nil;
    if (request.range) {
        rangeString = [request.range toHeaderString];
    }
    if (request.downloadProgress) {
        requestDelegate.downloadProgress = request.downloadProgress;
    }
    if (request.onRecieveData) {
        requestDelegate.onRecieveData = request.onRecieveData;
    }
    NSMutableDictionary * params = [NSMutableDictionary dictionary];
    [params oss_setObject:request.xOssProcess forKey:OSSHttpQueryProcess];
    
    [self enableCRC64WithFlag:request.crcFlag requestDelegate:requestDelegate];
    OSSHttpResponseParser *responseParser = [[OSSHttpResponseParser alloc] initForOperationType:OSSOperationTypeGetObject];
    responseParser.crc64Verifiable = requestDelegate.crc64Verifiable;
    
    requestDelegate.responseParser = responseParser;
    requestDelegate.responseParser.downloadingFileURL = request.downloadToFileURL;
    
    OSSAllRequestNeededMessage *neededMsg = [[OSSAllRequestNeededMessage alloc] init];
    neededMsg.endpoint = self.endpoint;
    neededMsg.httpMethod = OSSHTTPMethodGET;
    neededMsg.bucketName = request.bucketName;
    neededMsg.objectKey = request.objectKey;
    neededMsg.range = rangeString;
    neededMsg.params = params;
    neededMsg.headerParams = request.headerFields.mutableCopy;
    requestDelegate.allNeededMessage = neededMsg;
    
    requestDelegate.operType = OSSOperationTypeGetObject;
    
    OSSTask *task = [self.cryptoModule getObjectSecurely:request requestDelegate:requestDelegate];
    if (task.error) {
        return task;
    }
        
    return [self invokeRequest:requestDelegate requireAuthentication:request.isAuthenticationRequired];
}

- (OSSTask *)multipartUpload:(OSSMultipartUploadRequest *)request resumable:(BOOL)resumable sequential:(BOOL)sequential {
    if (resumable) {
        if (![request isKindOfClass:[OSSResumableUploadRequest class]]) {
            NSError *typoError = [NSError errorWithDomain:OSSClientErrorDomain
                                                     code:OSSClientErrorCodeInvalidArgument
                                                 userInfo:@{OSSErrorMessageTOKEN: @"resumable multipart request should use instance of class OSSMultipartUploadRequest!"}];
            return [OSSTask taskWithError: typoError];
        }
    }
    
    [self checkRequestCrc64Setting:request];
    OSSTask *preTask = [self preChecksForRequest:request];
    if (preTask) {
        return preTask;
    }
    
    return [[OSSTask taskWithResult:nil] continueWithExecutor:self.ossOperationExecutor withBlock:^id(OSSTask *task) {
        
        __block NSUInteger uploadedLength = 0;
        uploadedLength = 0;
        __block OSSTask * errorTask;
        __block NSString *uploadId;
        __block MultipartUploadCryptoContext *context;
        
        NSError *error;
        unsigned long long uploadFileSize = [self getSizeWithFilePath:request.uploadingFileURL.path error:&error];
        if (error) {
            return [OSSTask taskWithError:error];
        }
        
        NSUInteger partCount = [self judgePartSizeForMultipartRequest:request fileSize:uploadFileSize];
        
        if (partCount > 1 && request.partSize < 102400) {
            NSError *checkPartSizeError = [NSError errorWithDomain:OSSClientErrorDomain
                                                 code:OSSClientErrorCodeInvalidArgument
                                             userInfo:@{OSSErrorMessageTOKEN: @"Part size must be greater than equal to 100KB"}];
            return [OSSTask taskWithError:checkPartSizeError];
        }
        
        if (request.isCancelled) {
            return [OSSTask taskWithError:[OSSClient cancelError]];
        }
        
        NSString *recordFilePath = nil;
        NSMutableArray * uploadedPart = [NSMutableArray array];
        NSString *localPartInfosPath = nil;
        NSDictionary *localPartInfos = nil;
        
        NSMutableArray<OSSPartInfo *> *uploadedPartInfos = [NSMutableArray array];
        NSMutableArray * alreadyUploadIndex = [NSMutableArray array];
        
        if (resumable) {
            OSSResumableUploadRequest *resumableRequest = (OSSResumableUploadRequest *)request;
            NSString *recordDirectoryPath = resumableRequest.recordDirectoryPath;
            request.md5String = [OSSUtil fileMD5String:request.uploadingFileURL.path];
            if ([recordDirectoryPath oss_isNotEmpty])
            {
                context = [self readMultipartUploadCryptoContextForRequest:resumableRequest recordFilePath:&recordFilePath sequential:sequential];
                uploadId = context.uploadId;
                OSSLogVerbose(@"local uploadId: %@,recordFilePath: %@",uploadId, recordFilePath);
            }
            
            if([uploadId oss_isNotEmpty])
            {
                localPartInfosPath = [[[NSString oss_documentDirectory] stringByAppendingPathComponent:kClientRecordNameWithCommonPrefix] stringByAppendingPathComponent:context.uploadId];
                
                localPartInfos = [[NSDictionary alloc] initWithContentsOfFile:localPartInfosPath];
                
                OSSTask *listPartTask = [self processListPartsWithObjectKey:request.objectKey
                                                                     bucket:request.bucketName
                                                                   uploadId:&uploadId
                                                              uploadedParts:uploadedPart
                                                             uploadedLength:&uploadedLength
                                                                  totalSize:uploadFileSize
                                                                   partSize:request.partSize];
                if (listPartTask.error)
                {
                    return listPartTask;
                }
            }
            
            [uploadedPart enumerateObjectsUsingBlock:^(NSDictionary *partInfo, NSUInteger idx, BOOL * _Nonnull stop) {
                unsigned long long remotePartNumber = 0;
                NSString *partNumberString = [partInfo objectForKey: OSSPartNumberXMLTOKEN];
                NSScanner *scanner = [NSScanner scannerWithString: partNumberString];
                [scanner scanUnsignedLongLong: &remotePartNumber];
                
                NSString *remotePartEtag = [partInfo objectForKey:OSSETagXMLTOKEN];
                
                unsigned long long remotePartSize = 0;
                NSString *partSizeString = [partInfo objectForKey:OSSSizeXMLTOKEN];
                scanner = [NSScanner scannerWithString:partSizeString];
                [scanner scanUnsignedLongLong:&remotePartSize];
                
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wshorten-64-to-32"
                
                OSSPartInfo * info = [[OSSPartInfo alloc] init];
                info.partNum = remotePartNumber;
                info.size = remotePartSize;
                info.eTag = remotePartEtag;
                
#pragma clang diagnostic pop
            
                NSDictionary *tPartInfo = [localPartInfos objectForKey: [@(remotePartNumber) stringValue]];
                info.crc64 = [tPartInfo[@"crc64"] unsignedLongLongValue];
                
                [uploadedPartInfos addObject:info];
                [alreadyUploadIndex addObject:@(remotePartNumber)];
            }];
            
            if ([alreadyUploadIndex count] > 0 && request.uploadProgress && uploadFileSize) {
                request.uploadProgress(0, uploadedLength, uploadFileSize);
            }
        }
        
        if (![uploadId oss_isNotEmpty]) {
            context = [MultipartUploadCryptoContext new];
            context.partSize = request.partSize;
            context.dataSize = uploadFileSize;
            
            OSSInitMultipartUploadRequest *initRequest = [OSSInitMultipartUploadRequest new];
            initRequest.bucketName = request.bucketName;
            initRequest.objectKey = request.objectKey;
            initRequest.contentType = request.contentType;
            initRequest.sequential = sequential;
            initRequest.crcFlag = request.crcFlag;
            
            OSSTask *task = [self processResumableInitMultipartUpload:initRequest
                                                       recordFilePath:recordFilePath
                                                              context:context];
            if (task.error)
            {
                return task;
            }
            OSSInitMultipartUploadResult *initResult = (OSSInitMultipartUploadResult *)task.result;
            uploadId = initResult.uploadId;
        }
        
        request.uploadId = uploadId;
        localPartInfosPath = [[[NSString oss_documentDirectory] stringByAppendingPathComponent:kClientRecordNameWithCommonPrefix] stringByAppendingPathComponent:uploadId];
        
        if (request.isCancelled)
        {
            if(resumable)
            {
                OSSResumableUploadRequest *resumableRequest = (OSSResumableUploadRequest *)request;
                if (resumableRequest.deleteUploadIdOnCancelling) {
                    OSSTask *abortTask = [self abortMultipartUpload:request sequential:sequential resumable:resumable];
                    [abortTask waitUntilFinished];
                }
            }
            
            return [OSSTask taskWithError:[OSSClient cancelError]];
        }
        
        if (sequential) {
            errorTask = [self sequentialUpload:request
                                   uploadIndex:alreadyUploadIndex
                                    uploadPart:uploadedPartInfos
                                         count:partCount
                                uploadedLength:&uploadedLength
                                      fileSize:uploadFileSize
                                       context:context];
        } else {
            errorTask = [self upload:request
                         uploadIndex:alreadyUploadIndex
                          uploadPart:uploadedPartInfos
                               count:partCount
                      uploadedLength:&uploadedLength
                            fileSize:uploadFileSize
                             context:context];
        }
        
        if(errorTask.error)
        {
            OSSTask *abortTask;
            if(resumable)
            {
                OSSResumableUploadRequest *resumableRequest = (OSSResumableUploadRequest *)request;
                if (resumableRequest.deleteUploadIdOnCancelling || errorTask.error.code == OSSClientErrorCodeFileCantWrite) {
                    abortTask = [self abortMultipartUpload:request sequential:sequential resumable:resumable];
                }
            }else
            {
                abortTask =[self abortMultipartUpload:request sequential:sequential resumable:resumable];
            }
            [abortTask waitUntilFinished];
            
            return errorTask;
        }
        
        [uploadedPartInfos sortUsingComparator:^NSComparisonResult(OSSPartInfo *part1,OSSPartInfo* part2) {
            if(part1.partNum < part2.partNum){
                return NSOrderedAscending;
            }else if(part1.partNum > part2.partNum){
                return NSOrderedDescending;
            }else{
                return NSOrderedSame;
            }
        }];
        
        // 如果开启了crc64的校验
        uint64_t local_crc64 = 0;
        if (request.crcFlag == OSSRequestCRCOpen)
        {
            for (NSUInteger index = 0; index< uploadedPartInfos.count; index++)
            {
                uint64_t partCrc64 = uploadedPartInfos[index].crc64;
                int64_t partSize = uploadedPartInfos[index].size;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wshorten-64-to-32"
                local_crc64 = [OSSUtil crc64ForCombineCRC1:local_crc64 CRC2:partCrc64 length:partSize];
#pragma clang diagnostic pop
            }
        }
        return [self processCompleteMultipartUpload:request
                                          partInfos:uploadedPartInfos
                                        clientCrc64:local_crc64
                                     recordFilePath:recordFilePath
                                 localPartInfosPath:localPartInfosPath];
    }];
}

- (OSSTask *)processResumableInitMultipartUpload:(OSSInitMultipartUploadRequest *)request
                                  recordFilePath:(NSString *)recordFilePath
                                         context:(MultipartUploadCryptoContext *)context {
    OSSTask *task = [self multipartUploadInit:request context:context];
    [task waitUntilFinished];
    
    if(task.result && [recordFilePath oss_isNotEmpty])
    {
        OSSInitMultipartUploadResult *result = task.result;
        if (![result.uploadId oss_isNotEmpty])
        {
            NSString *errorMessage = [NSString stringWithFormat:@"Can not get uploadId!"];
            NSError *error = [NSError errorWithDomain:OSSServerErrorDomain
                                                 code:OSSClientErrorCodeNilUploadid userInfo:@{OSSErrorMessageTOKEN:   errorMessage}];
            return [OSSTask taskWithError:error];
        }
        
        NSFileManager *defaultFM = [NSFileManager defaultManager];
        if (![defaultFM fileExistsAtPath:recordFilePath])
        {
            if (![defaultFM createFileAtPath:recordFilePath contents:nil attributes:nil]) {
                NSError *error = [NSError errorWithDomain:OSSClientErrorDomain
                                                     code:OSSClientErrorCodeFileCantWrite
                                                 userInfo:@{OSSErrorMessageTOKEN: @"uploadId for this task can't be stored persistentially!"}];
                OSSLogDebug(@"[Error]: %@", error);
                return [OSSTask taskWithError:error];
            }
        }

        NSData *data = [NSKeyedArchiver archivedDataWithRootObject:context];
        NSFileHandle * write = [NSFileHandle fileHandleForWritingAtPath:recordFilePath];
        [write writeData:data];
        [write closeFile];
    }
    return task;
}

- (OSSTask *)multipartUploadInit:(OSSInitMultipartUploadRequest *)request context:(MultipartUploadCryptoContext *)context {
    return [_cryptoModule multipartUploadInitSecurely:request context:context client:self];
}

- (OSSTask *)uploadPart:(OSSUploadPartRequest *)request context:(MultipartUploadCryptoContext *)context {
    return [_cryptoModule uploadPart:request context:context client:self];
}

- (MultipartUploadCryptoContext *)readMultipartUploadCryptoContextForRequest:(OSSResumableUploadRequest *)request recordFilePath:(NSString **)recordFilePath sequential:(BOOL)sequential
{
    MultipartUploadCryptoContext *context = nil;
    NSString *record = [NSString stringWithFormat:@"%@%@%@%lu", request.md5String, request.bucketName, request.objectKey, (unsigned long)request.partSize];
    if (sequential) {
        record = [record stringByAppendingString:kClientRecordNameWithSequentialSuffix];
    }
    if (request.crcFlag == OSSRequestCRCOpen) {
        record = [record stringByAppendingString:kClientRecordNameWithCRC64Suffix];
    }
    record = [record stringByAppendingString:kClientRecordNameWithEncryptionSuffix];
    
    NSData *data = [record dataUsingEncoding:NSUTF8StringEncoding];
    NSString *recordFileName = [OSSUtil dataMD5String:data];
    *recordFilePath = [request.recordDirectoryPath stringByAppendingPathComponent: recordFileName];
    NSFileManager *fileManager = [NSFileManager defaultManager];
    if ([fileManager fileExistsAtPath: *recordFilePath]) {
        NSFileHandle * read = [NSFileHandle fileHandleForReadingAtPath:*recordFilePath];
        context = [NSKeyedUnarchiver unarchiveObjectWithData:[read readDataToEndOfFile]];
        [read closeFile];
    } else {
        [fileManager createFileAtPath:*recordFilePath contents:nil attributes:nil];
    }
    return context;
}

- (OSSTask *)upload:(OSSMultipartUploadRequest *)request
        uploadIndex:(NSMutableArray *)alreadyUploadIndex
         uploadPart:(NSMutableArray *)alreadyUploadPart
              count:(NSUInteger)partCout
     uploadedLength:(NSUInteger *)uploadedLength
           fileSize:(unsigned long long)uploadFileSize
            context:(MultipartUploadCryptoContext *)context
{
    NSOperationQueue *queue = [[NSOperationQueue alloc] init];
    [queue setMaxConcurrentOperationCount: 5];
    
    NSObject *localLock = [[NSObject alloc] init];
    
    OSSRequestCRCFlag crcFlag = request.crcFlag;
    __block OSSTask *errorTask;
    __block NSMutableDictionary *localPartInfos = nil;
    
    if (crcFlag == OSSRequestCRCOpen) {
        localPartInfos = [self localPartInfosDictoryWithUploadId:request.uploadId];
    }
    
    if (!localPartInfos) {
        localPartInfos = [NSMutableDictionary dictionary];
    }
    
    NSError *readError;
    NSFileHandle *fileHande = [NSFileHandle fileHandleForReadingFromURL:request.uploadingFileURL error:&readError];
    if (readError) {
        return [OSSTask taskWithError: readError];
    }
    
    NSData * uploadPartData;
    NSInteger realPartLength = request.partSize;
    __block BOOL hasError = NO;
    
    
    for (NSUInteger idx = 1; idx <= partCout; idx++)
    {
        if (request.isCancelled)
        {
            [queue cancelAllOperations];
            break;
        }
        
        if ([alreadyUploadIndex containsObject:@(idx)])
        {
            continue;
        }
        
        // while operationCount >= 5,the loop will stay here
        while (queue.operationCount >= 5) {
            [NSThread sleepForTimeInterval: 0.15f];
        }
        
        if (idx == partCout) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wshorten-64-to-32"
            realPartLength = uploadFileSize - request.partSize * (idx - 1);
#pragma clang diagnostic pop
        }
        @autoreleasepool
        {
            [fileHande seekToFileOffset: request.partSize * (idx - 1)];
            uploadPartData = [fileHande readDataOfLength:realPartLength];
            
            NSBlockOperation *operation = [NSBlockOperation blockOperationWithBlock:^{
                OSSTask *uploadPartErrorTask = nil;
                
                [self executePartUpload:request
               totalBytesExpectedToSend:uploadFileSize
                         totalBytesSent:uploadedLength
                                  index:idx
                               partData:uploadPartData
                      alreadyUploadPart:alreadyUploadPart
                             localParts:localPartInfos
                              errorTask:&uploadPartErrorTask
                                context:context];
                
                if (uploadPartErrorTask != nil) {
                    @synchronized(localLock) {
                        if (!hasError) {
                            hasError = YES;
                            errorTask = uploadPartErrorTask;
                        }
                    }
                    uploadPartErrorTask = nil;
                }
            }];
            [queue addOperation:operation];
        }
    }
    [fileHande closeFile];
    [queue waitUntilAllOperationsAreFinished];
    
    localLock = nil;
    
    if (!errorTask && request.isCancelled) {
        errorTask = [OSSTask taskWithError:[OSSClient cancelError]];
    }
    
    return errorTask;
}

- (void)executePartUpload:(OSSMultipartUploadRequest *)request
 totalBytesExpectedToSend:(unsigned long long)totalBytesExpectedToSend
           totalBytesSent:(NSUInteger *)totalBytesSent
                    index:(NSUInteger)idx
                 partData:(NSData *)partData
        alreadyUploadPart:(NSMutableArray *)uploadedParts
               localParts:(NSMutableDictionary *)localParts
                errorTask:(OSSTask **)errorTask
                  context:(MultipartUploadCryptoContext *)context {
    NSUInteger bytesSent = partData.length;
    
    OSSUploadPartRequest * uploadPart = [OSSUploadPartRequest new];
    uploadPart.bucketName = request.bucketName;
    uploadPart.objectkey = request.objectKey;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wshorten-64-to-32"
    uploadPart.partNumber = idx;
#pragma clang diagnostic pop
    uploadPart.uploadId = request.uploadId;
    uploadPart.uploadPartData = partData;
    uploadPart.contentMd5 = [OSSUtil base64Md5ForData:partData];
    uploadPart.crcFlag = request.crcFlag;
    
    OSSTask * uploadPartTask = [self uploadPart:uploadPart context:context];
    [uploadPartTask waitUntilFinished];
    if (uploadPartTask.error) {
        if (labs(uploadPartTask.error.code) != 409) {
            *errorTask = uploadPartTask;
        }
    } else {
        OSSUploadPartResult * result = uploadPartTask.result;
        OSSPartInfo * partInfo = [OSSPartInfo new];
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wshorten-64-to-32"
        partInfo.partNum = idx;
#pragma clang diagnostic pop
        partInfo.eTag = result.eTag;
        partInfo.size = bytesSent;
        uint64_t crc64OfPart;
        @try {
            NSScanner *scanner = [NSScanner scannerWithString:result.remoteCRC64ecma];
            [scanner scanUnsignedLongLong:&crc64OfPart];
            partInfo.crc64 = crc64OfPart;
        } @catch (NSException *exception) {
            OSSLogError(@"multipart upload error with nil remote crc64!");
        }
        
        @synchronized(lock){
            [uploadedParts addObject:partInfo];
            
            if (request.crcFlag == OSSRequestCRCOpen)
            {
                [self processForLocalPartInfos:localParts
                                      partInfo:partInfo
                                      uploadId:request.uploadId];
                [self persistencePartInfos:localParts
                              withUploadId:request.uploadId];
            }
            
            *totalBytesSent += bytesSent;
            if (request.uploadProgress)
            {
                request.uploadProgress(bytesSent, *totalBytesSent, totalBytesExpectedToSend);
            }
        }
    }
}

- (OSSTask *)sequentialUpload:(OSSMultipartUploadRequest *)request
                  uploadIndex:(NSMutableArray *)alreadyUploadIndex
                   uploadPart:(NSMutableArray *)alreadyUploadPart
                        count:(NSUInteger)partCout
               uploadedLength:(NSUInteger *)uploadedLength
                     fileSize:(unsigned long long)uploadFileSize
                      context:(MultipartUploadCryptoContext *)context {
    OSSRequestCRCFlag crcFlag = request.crcFlag;
    __block OSSTask *errorTask;
    __block NSMutableDictionary *localPartInfos = nil;
    
    if (crcFlag == OSSRequestCRCOpen) {
        localPartInfos = [self localPartInfosDictoryWithUploadId:request.uploadId];
    }
    
    if (!localPartInfos) {
        localPartInfos = [NSMutableDictionary dictionary];
    }
    
    NSError *readError;
    NSFileHandle *fileHande = [NSFileHandle fileHandleForReadingFromURL:request.uploadingFileURL error:&readError];
    if (readError) {
        return [OSSTask taskWithError: readError];
    }
    
    NSUInteger realPartLength = request.partSize;
    
    for (int i = 1; i <= partCout; i++) {
        if (errorTask) {
            break;
        }
        
        if (request.isCancelled) {
            errorTask = [OSSTask taskWithError:[OSSClient cancelError]];
            break;
        }
        
        if ([alreadyUploadIndex containsObject:@(i)]) {
            continue;
        }
        
        realPartLength = request.partSize;
        [fileHande seekToFileOffset:request.partSize * (i - 1)];
        if (i == partCout) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wshorten-64-to-32"
            realPartLength = uploadFileSize - request.partSize * (i - 1);
#pragma clang diagnostic pop
        }
        NSData *uploadPartData = [fileHande readDataOfLength:realPartLength];
        
        @autoreleasepool {
            OSSUploadPartRequest * uploadPart = [OSSUploadPartRequest new];
            uploadPart.bucketName = request.bucketName;
            uploadPart.objectkey = request.objectKey;
            uploadPart.partNumber = i;
            uploadPart.uploadId = request.uploadId;
            uploadPart.uploadPartData = uploadPartData;
            uploadPart.contentMd5 = [OSSUtil base64Md5ForData:uploadPartData];
            uploadPart.crcFlag = request.crcFlag;
            
            OSSTask * uploadPartTask = [self uploadPart:uploadPart context:context];
            [uploadPartTask waitUntilFinished];
            
            if (uploadPartTask.error) {
                if (labs(uploadPartTask.error.code) != 409) {
                    errorTask = uploadPartTask;
                    break;
                } else {
                    NSDictionary *partDict = uploadPartTask.error.userInfo;
                    OSSPartInfo *partInfo = [[OSSPartInfo alloc] init];
                    partInfo.eTag = partDict[@"PartEtag"];
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wshorten-64-to-32"
                    partInfo.partNum = [(NSString *)partDict[@"PartNumber"] integerValue];
                    partInfo.size = realPartLength;
#pragma clang diagnostic push
                    partInfo.crc64 = [[uploadPartData mutableCopy] oss_crc64];

                    [alreadyUploadPart addObject:partInfo];
                }
            } else {
                OSSUploadPartResult * result = uploadPartTask.result;
                OSSPartInfo * partInfo = [OSSPartInfo new];
                partInfo.partNum = i;
                partInfo.eTag = result.eTag;
                partInfo.size = realPartLength;
                uint64_t crc64OfPart;
                @try {
                    NSScanner *scanner = [NSScanner scannerWithString:result.remoteCRC64ecma];
                    [scanner scanUnsignedLongLong:&crc64OfPart];
                    partInfo.crc64 = crc64OfPart;
                } @catch (NSException *exception) {
                    OSSLogError(@"multipart upload error with nil remote crc64!");
                }
                
                [alreadyUploadPart addObject:partInfo];
                if (crcFlag == OSSRequestCRCOpen)
                {
                    [self processForLocalPartInfos:localPartInfos
                                          partInfo:partInfo
                                          uploadId:request.uploadId];
                    [self persistencePartInfos:localPartInfos
                                  withUploadId:request.uploadId];
                }
                
                @synchronized(lock) {
                    *uploadedLength += realPartLength;
                    if (request.uploadProgress)
                    {
                        request.uploadProgress(realPartLength, *uploadedLength, uploadFileSize);
                    }
                }
            }
        }
    }
    [fileHande closeFile];
    
    return errorTask;
}

- (OSSTask *)invokeRequest:(OSSNetworkingRequestDelegate *)request requireAuthentication:(BOOL)requireAuthentication {
    /* if content-type haven't been set, we set one */
    if (!request.allNeededMessage.contentType.oss_isNotEmpty
        && ([request.allNeededMessage.httpMethod isEqualToString:@"POST"] || [request.allNeededMessage.httpMethod isEqualToString:@"PUT"])) {

        request.allNeededMessage.contentType = [OSSUtil detemineMimeTypeForFilePath:request.uploadingFileURL.path               uploadName:request.allNeededMessage.objectKey];
    }

    // Checks if the endpoint is in the excluded CName list.
    [self.clientConfiguration.cnameExcludeList enumerateObjectsUsingBlock:^(NSString *exclude, NSUInteger idx, BOOL * _Nonnull stop) {
        if ([self.endpoint hasSuffix:exclude]) {
            request.allNeededMessage.isHostInCnameExcludeList = YES;
            *stop = YES;
        }
    }];

    id<OSSRequestInterceptor> uaSetting = [[OSSUASettingInterceptor alloc] initWithClientConfiguration:self.clientConfiguration];
    [request.interceptors addObject:uaSetting];

    /* check if the authentication is required */
    if (requireAuthentication) {
        id<OSSRequestInterceptor> signer = [[OSSSignerInterceptor alloc] initWithCredentialProvider:self.credentialProvider];
        [request.interceptors addObject:signer];
    }

    request.isHttpdnsEnable = self.clientConfiguration.isHttpdnsEnable;
    request.isPathStyleAccessEnable = self.clientConfiguration.isPathStyleAccessEnable;
    request.isCustomPathPrefixEnable = self.clientConfiguration.isCustomPathPrefixEnable;
    
    return [self.networking sendRequest:request];
}

#pragma mark - private

- (CryptoScheme *)getCryptoScheme:(ContentCryptoMode)mode {
    switch (mode) {
        case ContentCryptoModeAESCTRMode:
        default:
            return [CryptoSchemeAesCtr new];
            break;
    }
}

- (OSSTask *)cryptoRequest:(OSSNetworkingRequestDelegate *)requestDelegate
            cryptoMaterial:(ContentCryptoMaterial *)cryptoMaterial {
    CipherInputStream *inputStream = nil;
    
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
    [self updateContentMd5:requestDelegate];
    
    return [OSSTask taskWithResult:nil];
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

- (void)updateContentLength:(OSSNetworkingRequestDelegate *)requestDelegate {
    unsigned long long length = [self plaintextLength:requestDelegate];
    if (length > 0) {
        requestDelegate.allNeededMessage.headerParams[OSSHttpHeaderCryptoUnencryptedContentLength] = [NSString stringWithFormat:@"%@", @(length)];
    }
    if (requestDelegate.allNeededMessage.headerParams[OSSHttpHeaderContentLength]) {
        requestDelegate.allNeededMessage.headerParams[OSSHttpHeaderCryptoUnencryptedContentLength] = requestDelegate.allNeededMessage.headerParams[OSSHttpHeaderContentLength];
    }
}

- (unsigned long long)plaintextLength:(OSSNetworkingRequestDelegate *)requestDelegate {
    if (requestDelegate.uploadingFileURL) {
        NSError *error;
        unsigned long long length = [self getSizeWithFilePath:requestDelegate.uploadingFileURL.absoluteString error:&error];
        if (!error) {
            return length;
        }
    }
    return 0;
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
