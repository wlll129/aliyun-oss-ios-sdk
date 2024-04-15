//
//  CryptoModuleTests.m
//  AliyunOSSiOSTests
//
//  Created by ws on 2022/1/18.
//  Copyright © 2022 aliyun. All rights reserved.
//

#import <XCTest/XCTest.h>
#import <AliyunOSSiOS/AliyunOSSiOS.h>
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wincomplete-umbrella"
#import <AliyunOSSiOS/CryptoModule.h>
#pragma clang diagnostic pop

@interface CryptoModule(Tests)

+ (OSSTask *)getAdjustedCryptoRange:(OSSRange *)range;
- (void)updateContentLength:(OSSNetworkingRequestDelegate *)requestDelegate error:(NSError **)error;

@end

@interface CryptoModuleTests : XCTestCase

@end

@implementation CryptoModuleTests

- (void)setUp {
    // Put setup code here. This method is called before the invocation of each test method in the class.
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
}

- (void)testAPI_getAdjustedCryptoRange {
    OSSRange *range = [[OSSRange alloc] initWithStart:10 withEnd:20];
    OSSTask *task = [CryptoModule getAdjustedCryptoRange:range];
    XCTAssertNil(task.error);
    OSSRange *adjustedRange = task.result;
    XCTAssertTrue(adjustedRange.startPosition == 0);
    XCTAssertTrue(adjustedRange.endPosition == 20);
    
    range = [[OSSRange alloc] initWithStart:16 withEnd:20];
    task = [CryptoModule getAdjustedCryptoRange:range];
    XCTAssertNil(task.error);
    adjustedRange = task.result;
    XCTAssertTrue(adjustedRange.startPosition == 16);
    XCTAssertTrue(adjustedRange.endPosition == 20);
    
    range = [[OSSRange alloc] initWithStart:18 withEnd:20];
    task = [CryptoModule getAdjustedCryptoRange:range];
    XCTAssertNil(task.error);
    adjustedRange = task.result;
    XCTAssertTrue(adjustedRange.startPosition == 16);
    XCTAssertTrue(adjustedRange.endPosition == 20);

    
    range = [[OSSRange alloc] initWithStart:-1 withEnd:20];
    task = [CryptoModule getAdjustedCryptoRange:range];
    XCTAssertNotNil(task.error);
    XCTAssertTrue(task.error.code == OSSClientErrorCodeInvalidArgument);
    XCTAssertTrue([task.error.userInfo[OSSErrorMessageTOKEN] containsString:@"Your input get-range is illegal."]);

    
    range = [[OSSRange alloc] initWithStart:20 withEnd:10];
    task = [CryptoModule getAdjustedCryptoRange:range];
    XCTAssertNotNil(task.error);
    XCTAssertTrue(task.error.code == OSSClientErrorCodeInvalidArgument);
    XCTAssertTrue([task.error.userInfo[OSSErrorMessageTOKEN] containsString:@"Your input get-range is illegal."]);

    XCTAssertNil([CryptoModule getAdjustedCryptoRange:nil].result);
}

- (void)testAPI_updateContentLength {
    NSString * name = @"fileName";
    long size = 1024;
    NSString *filePath = [self createLocalFileWithName:name size:size];

    NSURL *fileUrl = [NSURL URLWithString:filePath];
    CryptoModule *cryptoModule = [CryptoModule new];
    
    OSSNetworkingRequestDelegate *delegate = [OSSNetworkingRequestDelegate new];
    delegate.allNeededMessage = [OSSAllRequestNeededMessage new];
    delegate.uploadingFileURL = fileUrl;
    
    NSError *error = nil;
    [cryptoModule updateContentLength:delegate error:&error];
    XCTAssertNil(error);
    XCTAssertNil(delegate.allNeededMessage.headerParams[OSSHttpHeaderContentLength]);
    XCTAssertTrue([delegate.allNeededMessage.headerParams[OSSHttpHeaderCryptoUnencryptedContentLength] integerValue] == size);
    
    
    delegate = [OSSNetworkingRequestDelegate new];
    delegate.allNeededMessage = [OSSAllRequestNeededMessage new];
    delegate.allNeededMessage.headerParams[OSSHttpHeaderContentLength] = [@(1000) stringValue];
    delegate.uploadingFileURL = fileUrl;
    
    error = nil;
    [cryptoModule updateContentLength:delegate error:&error];
    XCTAssertNil(error);
    XCTAssertTrue([delegate.allNeededMessage.headerParams[OSSHttpHeaderCryptoUnencryptedContentLength] isEqualToString:delegate.allNeededMessage.headerParams[OSSHttpHeaderContentLength]]);
    
    
    delegate = [OSSNetworkingRequestDelegate new];
    delegate.allNeededMessage = [OSSAllRequestNeededMessage new];
    
    error = nil;
    [cryptoModule updateContentLength:delegate error:&error];
    XCTAssertNil(error);
    XCTAssertTrue([delegate.allNeededMessage.headerParams[OSSHttpHeaderCryptoUnencryptedContentLength] integerValue] == 0);
    
    
    delegate = [OSSNetworkingRequestDelegate new];
    delegate.allNeededMessage = [OSSAllRequestNeededMessage new];
    delegate.uploadingFileURL = [NSURL URLWithString:@"error/file"];
    
    error = nil;
    [cryptoModule updateContentLength:delegate error:&error];
    XCTAssertNotNil(error);
    XCTAssertTrue(error.code == OSSClientErrorCodeInvalidArgument);
}

- (NSString *)createLocalFileWithName:(NSString *)name size:(NSInteger)size {
    NSFileManager * fm = [NSFileManager defaultManager];
    NSString * mainDir = [NSString oss_documentDirectory];
    
    NSMutableData * basePart = [NSMutableData dataWithCapacity:1024];
    for (int j = 0; j < 1024/4; j++) {
        u_int32_t randomBit = j;// arc4random();
        [basePart appendBytes:(void*)&randomBit length:4];
    }
    NSString * newFilePath = [mainDir stringByAppendingPathComponent:name];
    if ([fm fileExistsAtPath:newFilePath]) {
        [fm removeItemAtPath:newFilePath error:nil];
    }
    [fm createFileAtPath:newFilePath contents:nil attributes:nil];
    NSFileHandle * f = [NSFileHandle fileHandleForWritingAtPath:newFilePath];
    for (int k = 0; k < size/1024; k++) {
        [f writeData:basePart];
    }
    [f closeFile];
    return [mainDir stringByAppendingFormat:@"/%@", name];
}

@end
