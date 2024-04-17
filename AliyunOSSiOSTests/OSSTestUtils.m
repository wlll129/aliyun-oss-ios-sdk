//
//  OSSTestUtils.m
//  AliyunOSSiOSTests
//
//  Created by jingdan on 2018/2/24.
//  Copyright © 2018年 aliyun. All rights reserved.
//

#import "OSSTestUtils.h"
#import <XCTest/XCTest.h>

@implementation OSSTestUtils
+ (void)cleanBucket: (NSString *)bucket with: (OSSClient *)client {
    //delete object
    OSSGetBucketRequest *listObject = [OSSGetBucketRequest new];
    listObject.bucketName = bucket;
    listObject.maxKeys = 1000;
    OSSTask *listObjectTask = [client getBucket:listObject];
    [[listObjectTask continueWithBlock:^id(OSSTask * task) {
        OSSGetBucketResult * listObjectResult = task.result;
        for (NSDictionary *dict in listObjectResult.contents) {
            NSString * objectKey = [dict objectForKey:@"Key"];
            NSLog(@"delete object %@", objectKey);
            OSSDeleteObjectRequest * deleteObj = [OSSDeleteObjectRequest new];
            deleteObj.bucketName = bucket;
            deleteObj.objectKey = objectKey;
            [[client deleteObject:deleteObj] waitUntilFinished];
        }
        return nil;
    }] waitUntilFinished];
    
    //delete multipart uploads
    OSSListMultipartUploadsRequest *listMultipartUploads = [OSSListMultipartUploadsRequest new];
    listMultipartUploads.bucketName = bucket;
    listMultipartUploads.maxUploads = 1000;
    OSSTask *listMultipartUploadsTask = [client listMultipartUploads:listMultipartUploads];
    
    [[listMultipartUploadsTask continueWithBlock:^id(OSSTask *task) {
        OSSListMultipartUploadsResult * result = task.result;
        for (NSDictionary *dict in result.uploads) {
            NSString * uploadId = [dict objectForKey:@"UploadId"];
            NSString * objectKey = [dict objectForKey:@"Key"];
            NSLog(@"delete multipart uploadId %@", uploadId);
            OSSAbortMultipartUploadRequest *abort = [OSSAbortMultipartUploadRequest new];
            abort.bucketName = bucket;
            abort.objectKey = objectKey;
            abort.uploadId = uploadId;
            [[client abortMultipartUpload:abort] waitUntilFinished];
        }
        return nil;
    }] waitUntilFinished];
    //delete bucket
    OSSDeleteBucketRequest *deleteBucket = [OSSDeleteBucketRequest new];
    deleteBucket.bucketName = bucket;
    [[client deleteBucket:deleteBucket] waitUntilFinished];
}

+ (void) putTestDataWithKey: (NSString *)key withClient: (OSSClient *)client withBucket: (NSString *)bucket
{
    NSString *objectKey = key;
    NSString *filePath = [[NSString oss_documentDirectory] stringByAppendingPathComponent:objectKey];
    NSURL * fileURL = [NSURL fileURLWithPath:filePath];
    
    OSSPutObjectRequest * request = [OSSPutObjectRequest new];
    request.bucketName = bucket;
    request.objectKey = objectKey;
    request.uploadingFileURL = fileURL;
    request.objectMeta = [NSMutableDictionary dictionaryWithObjectsAndKeys:@"value1", @"x-oss-meta-name1", nil];
    
    OSSTask * task = [client putObject:request];
    [task waitUntilFinished];
}

@end

@interface OSSProgressTestUtils()

@property (nonatomic, assign) int64_t totalBytesSent;
@property (nonatomic, assign) int64_t totalBytesExpectedToSend;

@end

@implementation OSSProgressTestUtils

- (void)updateTotalBytes:(int64_t)totalBytesSent totalBytesExpected:(int64_t)totalBytesExpectedToSend {
    XCTAssertTrue(totalBytesSent <= totalBytesExpectedToSend);
    self.totalBytesSent = totalBytesSent;
    self.totalBytesExpectedToSend = totalBytesExpectedToSend;
}
- (BOOL)completeValidateProgress {
    return self.totalBytesSent == self.totalBytesExpectedToSend;
}

@end
