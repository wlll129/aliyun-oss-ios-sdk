//
//  OSSCryptoTests.m
//  AliyunOSSiOSTests
//
//  Created by ws on 2021/7/14.
//  Copyright © 2021 aliyun. All rights reserved.
//

#import <XCTest/XCTest.h>
#import "OSSTestMacros.h"
#import <AliyunOSSiOS/AliyunOSSiOS.h>
#import "OSSTestUtils.h"
#import <AliyunOSSiOS/ContentCryptoMaterial.h>
#import <AliyunOSSiOS/Cryptor.h>
#import <AliyunOSSiOS/CryptoSchemeAesCtr.h>
#import <objc/runtime.h>

@interface OSSSimpleRSAEncryptionMaterials(Test)

- (instancetype)initWithPKCS1PrivateKeyUrl:(NSURL *)privateKeyUrl
                          X509PublicKeyUrl:(NSURL *)publicKeyUrl
                                      desc:(nonnull NSDictionary *)desc;

@end

@interface OSSEncryptionClientTests : XCTestCase
{
    OSSClient *_client;
    NSArray<NSNumber *> *_fileSizes;
    NSArray<NSString *> *_fileNames;
    NSString *_privateBucketName;
    NSString *_publicBucketName;
    OSSEncryptionClient *_specialClient;
    OSSClient *_commonClient;
}

@end

@implementation OSSEncryptionClientTests

static NSString *publicKey = @"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDIUc0RE+OF4qvJkFp/sBR4iiPy5czlKdHoOKOjhvh93aGpipoMb05+t07XSOBDJUzKGhqqVQJZEQahKXJUU0h3mxYyxRQMhhWWWdH1LH4s/GAjf4h5l+6tKxS6mnZGH4IlbJz1pvbPiZjzD6BEWtGBMAxZIjqPgSRjJpB6fBIrHQIDAQAB";
static NSString *privateKey = @"-----BEGIN RSA PRIVATE KEY-----\nMIICXQIBAAKBgQDIUc0RE+OF4qvJkFp/sBR4iiPy5czlKdHoOKOjhvh93aGpipoM\nb05+t07XSOBDJUzKGhqqVQJZEQahKXJUU0h3mxYyxRQMhhWWWdH1LH4s/GAjf4h5\nl+6tKxS6mnZGH4IlbJz1pvbPiZjzD6BEWtGBMAxZIjqPgSRjJpB6fBIrHQIDAQAB\nAoGAG7kmdkyYWnkqaTTvMWi/DIehvgYLu1N0V30vOHx/e3vm2b3y3/GvnV3lLWpK\nj0BkRjwioJwvPQBcOIWx6vWzu4soHNI+e1FTJgFETfWs1+HAPgR9GptbDJGdVHc4\ni85JB+nKvbuEmm/kq0xmdQ3OeSVqZqyflmGTncCMUAK5WAECQQDpBws3eDa7w4Sr\nZyomMMiv0UW6GYWWXxnvSVzK2A55AQiSoejU2RPhZ6LJzuvr2Mez9l7mOvyiJvvd\ncaO6UawdAkEA3BFM2z82m3Q9eYPSegB2knCAuKTjZZmDLt7Ibd/z1KgdKr3tpzRt\nWNlxqS0l9bsN79IfSwGwwbFFhiQSrWRLAQJAJs9gg92GqCD5IJ7u+ytW0Ul2ZndH\ns3KlXCAIz1PKnUaZyeojYAfDcuAS0a+fxUj2gbd/uLKMTulVO11o2mgt1QJBAJBb\nUN0pNDr5HzJMxI5/K0iYP/ffQcNt1d2zCir5E0tWE/vrpq9d9rSnvqVJFnOBBn1g\nimJ7c2U7Ue3ST+YpugECQQDGSAxsLaSGFLfbBOKzM7spv3cvza7vYBksfR6xT6KR\naURh6yaGmkK8gfmrkFMtWQ0CC3fNecewUNLpScuKunCh\n-----END RSA PRIVATE KEY-----";

- (void)setUp {
    [super setUp];
    NSArray *array1 = [self.name componentsSeparatedByString:@" "];
    NSArray *array2 = [array1[1] componentsSeparatedByString:@"_"];
    NSString *testName = [[array2[1] substringToIndex:([array2[1] length] -1)] lowercaseString];
    _privateBucketName = [@"oss-ios-private-" stringByAppendingString:testName];
    _publicBucketName = [@"oss-ios-public-" stringByAppendingString:testName];
    // Put setup code here. This method is called before the invocation of each test method in the class.
    [self setUpOSSClient];
    [self setUpLocalFiles];
    
}

- (void)setUpOSSClient
{
    NSURL *publicKeyUrl = [[NSBundle mainBundle]  URLForResource:@"public_key" withExtension:@"der"];
    NSURL *privateKeyUrl = [[NSBundle mainBundle]  URLForResource:@"private_key" withExtension:@"pem"];
    NSDictionary *desc = @{};

    OSSSimpleRSAEncryptionMaterials *encryptionMaterials = [[OSSSimpleRSAEncryptionMaterials alloc] initWithPKCS1PrivateKeyUrl:privateKeyUrl X509PublicKeyUrl:publicKeyUrl desc:desc];
    OSSClientConfiguration *config = [OSSClientConfiguration new];
//    config.crc64Verifiable = YES;
    
    OSSAuthCredentialProvider *authProv = [[OSSAuthCredentialProvider alloc] initWithAuthServerUrl:OSS_STSTOKEN_URL];
    CryptoConfiguration *cryptoConfig = [CryptoConfiguration new];
    _client = [[OSSEncryptionClient alloc] initWithEndpoint:OSS_ENDPOINT
                                         credentialProvider:authProv
                                        clientConfiguration:config
                                        encryptionMaterials:encryptionMaterials
                                               cryptoConfig:cryptoConfig];
    
    SecKeyRef publicKeyRef = [OSSSimpleRSAEncryptionMaterials getPublicKeyFromPemPKCS8:publicKey keySizeInBits:1024 error:nil];
    SecKeyRef privateKeyRef = [OSSSimpleRSAEncryptionMaterials getPrivateKeyFromPemPKCS1:privateKey keySizeInBits:1024 error:nil];
    OSSSimpleRSAEncryptionMaterials *specialEncryptionMaterials = [[OSSSimpleRSAEncryptionMaterials alloc] initWithPrivateKey:privateKeyRef publicKey:publicKeyRef desc:desc];
    _specialClient = [[OSSEncryptionClient alloc] initWithEndpoint:OSS_ENDPOINT
                                                credentialProvider:authProv
                                               clientConfiguration:config
                                               encryptionMaterials:specialEncryptionMaterials
                                                      cryptoConfig:cryptoConfig];
    
    _commonClient = [[OSSClient alloc] initWithEndpoint:OSS_ENDPOINT
                                     credentialProvider:authProv
                                    clientConfiguration:config];
    //
    [OSSLog enableLog];
    
    OSSCreateBucketRequest *createBucket1 = [OSSCreateBucketRequest new];
    createBucket1.bucketName = _privateBucketName;
    [[_client createBucket:createBucket1] waitUntilFinished];
    
    OSSCreateBucketRequest *createBucket2 = [OSSCreateBucketRequest new];
    createBucket2.bucketName = _publicBucketName;
    createBucket2.xOssACL = @"public-read-write";
    [[_client createBucket:createBucket2] waitUntilFinished];
}

- (void)setUpLocalFiles
{
    _fileNames = @[@"file1k", @"file10k", @"file100k", @"file1m", @"file5m", @"file10m", @"fileDirA/", @"fileDirB/"];
    _fileSizes = @[@1024, @10240, @102400, @(1024 * 1024 * 1), @(1024 * 1024 * 5), @(1024 * 1024 * 10), @1024, @1024];
    NSFileManager * fm = [NSFileManager defaultManager];
    NSString * documentDirectory = [NSString oss_documentDirectory];
    
    for (int i = 0; i < [_fileNames count]; i++)
    {
        NSMutableData * basePart = [NSMutableData dataWithCapacity:1024];
        for (int j = 0; j < 1024/4; j++)
        {
            u_int32_t randomBit = j;// arc4random();
            [basePart appendBytes:(void*)&randomBit length:4];
        }
        NSString * name = [_fileNames objectAtIndex:i];
        long size = [[_fileSizes objectAtIndex:i] longLongValue];
        NSString * newFilePath = [documentDirectory stringByAppendingPathComponent:name];
        if ([fm fileExistsAtPath:newFilePath])
        {
            [fm removeItemAtPath:newFilePath error:nil];
        }
        [fm createFileAtPath:newFilePath contents:nil attributes:nil];
        NSFileHandle * f = [NSFileHandle fileHandleForWritingAtPath:newFilePath];
        for (int k = 0; k < size/1024; k++)
        {
            [f writeData:basePart];
        }
        [f closeFile];
    }
    OSSLogVerbose(@"document directory path is: %@", documentDirectory);
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    [super tearDown];
    [OSSTestUtils cleanBucket:_privateBucketName with:_client];
    [OSSTestUtils cleanBucket:_publicBucketName with:_client];
}

- (void)testAPI_PutObjectWithFilePath {
    NSURL *fileUrl = [[NSBundle mainBundle] URLForResource:@"hasky" withExtension:@"jpeg"];
    OSSPutObjectRequest *putRequest = [OSSPutObjectRequest new];
    putRequest.bucketName = _privateBucketName;
    putRequest.objectKey = OSS_IMAGE_KEY;
    putRequest.uploadingFileURL = fileUrl;
    putRequest.uploadProgress = ^(int64_t bytesSent, int64_t totalBytesSent, int64_t totalBytesExpectedToSend) {
        NSLog(@"%lld %lld %lld", bytesSent, totalBytesSent, totalBytesExpectedToSend);
    };
    putRequest.callbackParam = @{
        @"callbackUrl": OSS_CALLBACK_URL,
        @"callbackBody": @"test"
    };
    
    [[[_client putObject:putRequest] continueWithBlock:^id _Nullable(OSSTask * _Nonnull task) {
        XCTAssertNil(task.error);
        return nil;
    }] waitUntilFinished];
    
    NSString *path = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    path = [path stringByAppendingString:@"/111"];
    
    OSSGetObjectRequest *getRequest = [OSSGetObjectRequest new];
    getRequest.bucketName = _privateBucketName;
    getRequest.objectKey = OSS_IMAGE_KEY;
    getRequest.downloadToFileURL = [NSURL URLWithString:path];
    [[[_client getObject:getRequest] continueWithBlock:^id _Nullable(OSSTask * _Nonnull task) {
        XCTAssertNil(task.error);
        return nil;
    }] waitUntilFinished];
    XCTAssertTrue([[OSSUtil base64Md5ForFilePath:path] isEqualToString:[OSSUtil base64Md5ForFileURL:fileUrl]]);
}

- (void)testAPI_PutObjectWithData {
    NSURL *fileUrl = [[NSBundle mainBundle] URLForResource:@"hasky" withExtension:@"jpeg"];
    NSData *fileData = [[NSData alloc] initWithContentsOfURL:fileUrl];
    OSSPutObjectRequest *putRequest = [OSSPutObjectRequest new];
    putRequest.bucketName = _privateBucketName;
    putRequest.objectKey = OSS_IMAGE_KEY;
    putRequest.uploadingData = fileData;
    
    [[[_client putObject:putRequest] continueWithBlock:^id _Nullable(OSSTask * _Nonnull task) {
        XCTAssertNil(task.error);
        return nil;
    }] waitUntilFinished];
    
    NSString *path = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    path = [path stringByAppendingString:@"/111"];
    
    OSSGetObjectRequest *getRequest = [OSSGetObjectRequest new];
    getRequest.bucketName = _privateBucketName;
    getRequest.objectKey = OSS_IMAGE_KEY;
    getRequest.downloadToFileURL = [NSURL URLWithString:path];
    [[[_client getObject:getRequest] continueWithBlock:^id _Nullable(OSSTask * _Nonnull task) {
        XCTAssertNil(task.error);
        return nil;
    }] waitUntilFinished];
    XCTAssertTrue([[OSSUtil base64Md5ForFilePath:path] isEqualToString:[OSSUtil base64Md5ForFileURL:fileUrl]]);
}

- (void)testAPI_PutObjectWithCRC {
    NSURL *fileUrl = [[NSBundle mainBundle] URLForResource:@"hasky" withExtension:@"jpeg"];
    OSSPutObjectRequest *putRequest = [OSSPutObjectRequest new];
    putRequest.crcFlag = OSSRequestCRCOpen;
    putRequest.bucketName = _privateBucketName;
    putRequest.objectKey = OSS_IMAGE_KEY;
    putRequest.uploadingFileURL = fileUrl;
    
    [[[_client putObject:putRequest] continueWithBlock:^id _Nullable(OSSTask * _Nonnull task) {
        XCTAssertNil(task.error);
        return nil;
    }] waitUntilFinished];
    
    NSString *path = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    path = [path stringByAppendingString:@"/111"];

    OSSGetObjectRequest *getRequest = [OSSGetObjectRequest new];
    getRequest.crcFlag = OSSRequestCRCOpen;
    getRequest.bucketName = _privateBucketName;
    getRequest.objectKey = OSS_IMAGE_KEY;
    getRequest.downloadToFileURL = [NSURL URLWithString:path];
    [[[_client getObject:getRequest] continueWithBlock:^id _Nullable(OSSTask * _Nonnull task) {
        XCTAssertNil(task.error);
        return nil;
    }] waitUntilFinished];
    XCTAssertTrue([[OSSUtil base64Md5ForFilePath:path] isEqualToString:[OSSUtil base64Md5ForFileURL:fileUrl]]);
}

- (void)testAPI_PutObjectWithErrorFilePath {
    NSString *filePath = [[NSBundle mainBundle] pathForResource:@"hasky" ofType:@"jpeg"];
    filePath = [filePath stringByAppendingString:@"error"];
    OSSPutObjectRequest *putRequest = [OSSPutObjectRequest new];
    putRequest.crcFlag = OSSRequestCRCOpen;
    putRequest.bucketName = _privateBucketName;
    putRequest.objectKey = OSS_IMAGE_KEY;
    putRequest.uploadingFileURL = [NSURL fileURLWithPath:filePath];
    
    [[[_client putObject:putRequest] continueWithBlock:^id _Nullable(OSSTask * _Nonnull task) {
        XCTAssertNotNil(task.error);
        return nil;
    }] waitUntilFinished];
}

- (void)testAPI_PutObjectWithMD5 {
    NSURL *fileUrl = [[NSBundle mainBundle] URLForResource:@"hasky" withExtension:@"jpeg"];
    OSSPutObjectRequest *putRequest = [OSSPutObjectRequest new];
    putRequest.crcFlag = OSSRequestCRCOpen;
    putRequest.bucketName = _privateBucketName;
    putRequest.objectKey = OSS_IMAGE_KEY;
    putRequest.uploadingFileURL = fileUrl;
    putRequest.contentMd5 = [OSSUtil base64Md5ForFileURL:fileUrl];
    
    [[[_client putObject:putRequest] continueWithBlock:^id _Nullable(OSSTask * _Nonnull task) {
        XCTAssertNil(task.error);
        return nil;
    }] waitUntilFinished];
}

- (void)testAPI_PutObjectWithErrorKeyAndIV {
    NSURL *fileUrl = [[NSBundle mainBundle] URLForResource:@"hasky" withExtension:@"jpeg"];
    OSSPutObjectRequest *putRequest = [OSSPutObjectRequest new];
    putRequest.crcFlag = OSSRequestCRCOpen;
    putRequest.bucketName = _privateBucketName;
    putRequest.objectKey = OSS_IMAGE_KEY;
    putRequest.uploadingFileURL = fileUrl;
    putRequest.objectMeta = @{
        OSSHttpHeaderCryptoKey:@"111",
        OSSHttpHeaderCryptoIV:@"111",
        OSSHttpHeaderCryptoCEKAlg:@"AES/NoPadding/CTR",
        OSSHttpHeaderCryptoWrapAlg:@"AES",
        OSSHttpHeaderCryptoMatdesc:@""
    };
    
    [[[_commonClient putObject:putRequest] continueWithBlock:^id _Nullable(OSSTask * _Nonnull task) {
        XCTAssertNil(task.error);
        return nil;
    }] waitUntilFinished];
    
    NSString *path = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    path = [path stringByAppendingString:@"/111"];
    
    OSSGetObjectRequest *getRequest = [OSSGetObjectRequest new];
    getRequest.bucketName = _privateBucketName;
    getRequest.objectKey = OSS_IMAGE_KEY;
    getRequest.downloadToFileURL = [NSURL URLWithString:path];
    [[[_client getObject:getRequest] continueWithBlock:^id _Nullable(OSSTask * _Nonnull task) {
        XCTAssertNotNil(task.error);
        XCTAssertTrue(task.error.code == OSSClientErrorCodeCannotDecrypted);
        return nil;
    }] waitUntilFinished];
}

- (void)testAPI_PutObjectWithErrorBase64KeyAndIV {
    NSURL *fileUrl = [[NSBundle mainBundle] URLForResource:@"hasky" withExtension:@"jpeg"];
    OSSPutObjectRequest *putRequest = [OSSPutObjectRequest new];
    putRequest.crcFlag = OSSRequestCRCOpen;
    putRequest.bucketName = _privateBucketName;
    putRequest.objectKey = OSS_IMAGE_KEY;
    putRequest.uploadingFileURL = fileUrl;
    putRequest.objectMeta = @{
        OSSHttpHeaderCryptoKey:[[@"111" dataUsingEncoding:NSUTF8StringEncoding] base64EncodedStringWithOptions:0],
        OSSHttpHeaderCryptoIV:[[@"111" dataUsingEncoding:NSUTF8StringEncoding] base64EncodedStringWithOptions:0],
        OSSHttpHeaderCryptoCEKAlg:@"AES/NoPadding/CTR",
        OSSHttpHeaderCryptoWrapAlg:@"AES",
        OSSHttpHeaderCryptoMatdesc:@""
    };
    
    [[[_commonClient putObject:putRequest] continueWithBlock:^id _Nullable(OSSTask * _Nonnull task) {
        XCTAssertNil(task.error);
        return nil;
    }] waitUntilFinished];
    
    NSString *path = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    path = [path stringByAppendingString:@"/111"];
    
    OSSGetObjectRequest *getRequest = [OSSGetObjectRequest new];
    getRequest.bucketName = _privateBucketName;
    getRequest.objectKey = OSS_IMAGE_KEY;
    getRequest.downloadToFileURL = [NSURL URLWithString:path];
    [[[_client getObject:getRequest] continueWithBlock:^id _Nullable(OSSTask * _Nonnull task) {
        XCTAssertNotNil(task.error);
        XCTAssertTrue(task.error.code == OSSClientErrorCodeCryptoUpdate);
        return nil;
    }] waitUntilFinished];
}

- (void)testAPI_PutObjectWithErrorMaterials {
    NSURL *publicKeyUrl = [[NSBundle mainBundle]  URLForResource:@"public_key" withExtension:@"der"];
    NSURL *privateKeyUrl = [[NSBundle mainBundle]  URLForResource:@"private_key" withExtension:@"pem"];
    NSDictionary *desc = @{};
    SecKeyRef publicKey = [OSSSimpleRSAEncryptionMaterials getPublicKeyFromDerX509:[NSData dataWithContentsOfURL:publicKeyUrl] error:nil];
    SecKeyRef privateKey = [OSSSimpleRSAEncryptionMaterials getPrivateKeyFromPemPKCS1:[NSString stringWithContentsOfURL:privateKeyUrl encoding:NSUTF8StringEncoding error:nil] keySizeInBits:1024 error:nil];

    OSSSimpleRSAEncryptionMaterials *encryptionMaterials = [[OSSSimpleRSAEncryptionMaterials alloc] initWithPrivateKey:publicKey publicKey:privateKey desc:desc];
    OSSClientConfiguration *config = [OSSClientConfiguration new];
    
    OSSAuthCredentialProvider *authProv = [[OSSAuthCredentialProvider alloc] initWithAuthServerUrl:OSS_STSTOKEN_URL];
    CryptoConfiguration *cryptoConfig = [CryptoConfiguration new];
    OSSClient *client = [[OSSEncryptionClient alloc] initWithEndpoint:OSS_ENDPOINT
                                                   credentialProvider:authProv
                                                  clientConfiguration:config
                                                  encryptionMaterials:encryptionMaterials
                                                         cryptoConfig:cryptoConfig];
    
    NSURL *fileUrl = [[NSBundle mainBundle] URLForResource:@"hasky" withExtension:@"jpeg"];
    OSSPutObjectRequest *putRequest = [OSSPutObjectRequest new];
    putRequest.crcFlag = OSSRequestCRCOpen;
    putRequest.bucketName = _privateBucketName;
    putRequest.objectKey = OSS_IMAGE_KEY;
    putRequest.uploadingFileURL = fileUrl;

    [[[client putObject:putRequest] continueWithBlock:^id _Nullable(OSSTask * _Nonnull task) {
        XCTAssertNotNil(task.error);
        XCTAssertTrue(task.error.code == OSSClientErrorCodeCryptoUpdate);
        return nil;
    }] waitUntilFinished];
}

- (void)testAPI_GetObjectRangeWithCRC {

    NSURL *fileUrl = [[NSBundle mainBundle] URLForResource:@"hasky" withExtension:@"jpeg"];
    OSSPutObjectRequest *putRequest = [OSSPutObjectRequest new];
    putRequest.crcFlag = OSSRequestCRCOpen;
    putRequest.bucketName = _privateBucketName;
    putRequest.objectKey = OSS_IMAGE_KEY;
    putRequest.uploadingFileURL = fileUrl;
    
    [[[_client putObject:putRequest] continueWithBlock:^id _Nullable(OSSTask * _Nonnull task) {
        XCTAssertNil(task.error);
        return nil;
    }] waitUntilFinished];
    
    NSString *path = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    path = [path stringByAppendingString:@"/111"];
    
    NSError *error;
    NSFileManager *fileManager = [NSFileManager defaultManager];
    NSDictionary *fileAttributes = [fileManager attributesOfItemAtPath:fileUrl.path error:&error];
    int64_t fileSize = fileAttributes.fileSize;
    XCTAssertNil(error);
    
    NSInteger rangeStart = 20;
    NSInteger rangeEnd = fileSize - 1;
    
    OSSRange *range = [[OSSRange alloc] initWithStart:rangeStart withEnd:rangeEnd];
    OSSGetObjectRequest *getRequest = [OSSGetObjectRequest new];
    getRequest.range = range;
    getRequest.crcFlag = OSSRequestCRCOpen;
    getRequest.bucketName = _privateBucketName;
    getRequest.objectKey = OSS_IMAGE_KEY;
    getRequest.downloadToFileURL = [NSURL URLWithString:path];
    [[[_client getObject:getRequest] continueWithBlock:^id _Nullable(OSSTask * _Nonnull task) {
        XCTAssertNil(task.error);
        return nil;
    }] waitUntilFinished];
    
    NSData *originData = [NSData dataWithContentsOfURL:fileUrl];
    originData = [originData subdataWithRange:(NSRange){rangeStart, rangeEnd - rangeStart + 1}];
    XCTAssertTrue([[OSSUtil base64Md5ForFilePath:path] isEqualToString:[OSSUtil base64Md5ForData:originData]]);
    
    rangeStart = 10;
    rangeEnd = fileSize - 1;
    
    range = [[OSSRange alloc] initWithStart:rangeStart withEnd:rangeEnd];
    getRequest = [OSSGetObjectRequest new];
    getRequest.range = range;
    getRequest.crcFlag = OSSRequestCRCOpen;
    getRequest.bucketName = _privateBucketName;
    getRequest.objectKey = OSS_IMAGE_KEY;
    getRequest.downloadToFileURL = [NSURL URLWithString:path];
    [[[_client getObject:getRequest] continueWithBlock:^id _Nullable(OSSTask * _Nonnull task) {
        XCTAssertNil(task.error);
        return nil;
    }] waitUntilFinished];
    
    originData = [NSData dataWithContentsOfURL:fileUrl];
    originData = [originData subdataWithRange:(NSRange){rangeStart, rangeEnd - rangeStart + 1}];
    XCTAssertTrue([[OSSUtil base64Md5ForFilePath:path] isEqualToString:[OSSUtil base64Md5ForData:originData]]);
    
    rangeStart = 20;
    rangeEnd = fileSize - 10;
    
    range = [[OSSRange alloc] initWithStart:rangeStart withEnd:rangeEnd];
    getRequest = [OSSGetObjectRequest new];
    getRequest.range = range;
    getRequest.crcFlag = OSSRequestCRCOpen;
    getRequest.bucketName = _privateBucketName;
    getRequest.objectKey = OSS_IMAGE_KEY;
    getRequest.downloadToFileURL = [NSURL URLWithString:path];
    [[[_client getObject:getRequest] continueWithBlock:^id _Nullable(OSSTask * _Nonnull task) {
        XCTAssertNil(task.error);
        return nil;
    }] waitUntilFinished];
    
    originData = [NSData dataWithContentsOfURL:fileUrl];
    originData = [originData subdataWithRange:(NSRange){rangeStart, rangeEnd - rangeStart + 1}];
    XCTAssertTrue([[OSSUtil base64Md5ForFilePath:path] isEqualToString:[OSSUtil base64Md5ForData:originData]]);
    
    rangeStart = 20;
    rangeEnd = fileSize + 10;
    
    range = [[OSSRange alloc] initWithStart:rangeStart withEnd:rangeEnd];
    getRequest = [OSSGetObjectRequest new];
    getRequest.range = range;
    getRequest.crcFlag = OSSRequestCRCOpen;
    getRequest.bucketName = _privateBucketName;
    getRequest.objectKey = OSS_IMAGE_KEY;
    getRequest.downloadToFileURL = [NSURL URLWithString:path];
    [[[_client getObject:getRequest] continueWithBlock:^id _Nullable(OSSTask * _Nonnull task) {
        XCTAssertNil(task.error);
        return nil;
    }] waitUntilFinished];
    
    originData = [NSData dataWithContentsOfURL:fileUrl];
    XCTAssertTrue([[OSSUtil base64Md5ForFilePath:path] isEqualToString:[OSSUtil base64Md5ForData:originData]]);
}

- (void)testAPI_GetObjectWithRangeError {
    NSURL *fileUrl = [[NSBundle mainBundle] URLForResource:@"hasky" withExtension:@"jpeg"];
    OSSPutObjectRequest *putRequest = [OSSPutObjectRequest new];
    putRequest.crcFlag = OSSRequestCRCOpen;
    putRequest.bucketName = _privateBucketName;
    putRequest.objectKey = OSS_IMAGE_KEY;
    putRequest.uploadingFileURL = fileUrl;
    
    [[[_client putObject:putRequest] continueWithBlock:^id _Nullable(OSSTask * _Nonnull task) {
        XCTAssertNil(task.error);
        return nil;
    }] waitUntilFinished];
    
    NSString *path = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    path = [path stringByAppendingString:@"/111"];
    
    NSError *error;
    NSFileManager *fileManager = [NSFileManager defaultManager];
    NSDictionary *fileAttributes = [fileManager attributesOfItemAtPath:fileUrl.path error:&error];
    int64_t fileSize = fileAttributes.fileSize;
    XCTAssertNil(error);
    
    NSInteger rangeStart = 20;
    NSInteger rangeEnd = fileSize - 1;
    
    OSSRange *range = [[OSSRange alloc] initWithStart:rangeEnd withEnd:rangeStart];
    OSSGetObjectRequest *getRequest = [OSSGetObjectRequest new];
    getRequest.range = range;
    getRequest.crcFlag = OSSRequestCRCOpen;
    getRequest.bucketName = _privateBucketName;
    getRequest.objectKey = OSS_IMAGE_KEY;
    getRequest.downloadToFileURL = [NSURL URLWithString:path];
    [[[_client getObject:getRequest] continueWithBlock:^id _Nullable(OSSTask * _Nonnull task) {
        XCTAssertNotNil(task.error);
        XCTAssertEqual(task.error.code, OSSClientErrorCodeInvalidArgument);
        return nil;
    }] waitUntilFinished];

}

- (void)testAPI_GetObjectWithMultipart {
    
    NSURL *publicKeyUrl = [[NSBundle mainBundle]  URLForResource:@"public_key" withExtension:@"der"];
    NSURL *privateKeyUrl = [[NSBundle mainBundle]  URLForResource:@"private_key" withExtension:@"pem"];
    SecKeyRef publicKeyRef = [OSSSimpleRSAEncryptionMaterials getPublicKeyFromDerX509:[NSData dataWithContentsOfURL:publicKeyUrl] error:nil];
    SecKeyRef privateKeyRef = [OSSSimpleRSAEncryptionMaterials getPrivateKeyFromPemPKCS1:[NSString stringWithContentsOfURL:privateKeyUrl encoding:NSUTF8StringEncoding error:nil] keySizeInBits:1024 error:nil];
    NSDictionary *desc = @{@"test": @"test"};

    OSSSimpleRSAEncryptionMaterials *encryptionMaterials = [[OSSSimpleRSAEncryptionMaterials alloc] initWithPrivateKey:privateKeyRef publicKey:publicKeyRef desc:desc];
    OSSClientConfiguration *config = [OSSClientConfiguration new];
    
    OSSAuthCredentialProvider *authProv = [[OSSAuthCredentialProvider alloc] initWithAuthServerUrl:OSS_STSTOKEN_URL];
    CryptoConfiguration *cryptoConfig = [CryptoConfiguration new];
    OSSEncryptionClient *client = [[OSSEncryptionClient alloc] initWithEndpoint:OSS_ENDPOINT
                                         credentialProvider:authProv
                                        clientConfiguration:config
                                        encryptionMaterials:encryptionMaterials
                                               cryptoConfig:cryptoConfig];
    
    NSURL *fileUrl = [[NSBundle mainBundle] URLForResource:@"hasky" withExtension:@"jpeg"];
    OSSPutObjectRequest *putRequest = [OSSPutObjectRequest new];
    putRequest.bucketName = _privateBucketName;
    putRequest.objectKey = @"object1";
    putRequest.uploadingFileURL = fileUrl;
    putRequest.uploadProgress = ^(int64_t bytesSent, int64_t totalBytesSent, int64_t totalBytesExpectedToSend) {
        NSLog(@"%lld %lld %lld", bytesSent, totalBytesSent, totalBytesExpectedToSend);
    };
    putRequest.callbackParam = @{
        @"callbackUrl": OSS_CALLBACK_URL,
        @"callbackBody": @"test"
    };
    
    [[[client putObject:putRequest] continueWithBlock:^id _Nullable(OSSTask * _Nonnull task) {
        XCTAssertNil(task.error);
        return nil;
    }] waitUntilFinished];
    
    NSString *path = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    path = [path stringByAppendingString:@"/111"];
    
    OSSGetObjectRequest *getRequest = [OSSGetObjectRequest new];
    getRequest.bucketName = _privateBucketName;
    getRequest.objectKey = @"object1";
    getRequest.downloadToFileURL = [NSURL URLWithString:path];
    [[[client getObject:getRequest] continueWithBlock:^id _Nullable(OSSTask * _Nonnull task) {
        XCTAssertNil(task.error);
        return nil;
    }] waitUntilFinished];
    XCTAssertTrue([[OSSUtil base64Md5ForFilePath:path] isEqualToString:[OSSUtil base64Md5ForFileURL:fileUrl]]);
    
    putRequest.bucketName = _privateBucketName;
    putRequest.objectKey = @"object2";
    putRequest.uploadingFileURL = fileUrl;
    putRequest.uploadProgress = ^(int64_t bytesSent, int64_t totalBytesSent, int64_t totalBytesExpectedToSend) {
        NSLog(@"%lld %lld %lld", bytesSent, totalBytesSent, totalBytesExpectedToSend);
    };
    putRequest.callbackParam = @{
        @"callbackUrl": OSS_CALLBACK_URL,
        @"callbackBody": @"test"
    };
    
    [[[_client putObject:putRequest] continueWithBlock:^id _Nullable(OSSTask * _Nonnull task) {
        XCTAssertNil(task.error);
        return nil;
    }] waitUntilFinished];
    
    getRequest.bucketName = _privateBucketName;
    getRequest.objectKey = @"object2";
    getRequest.downloadToFileURL = [NSURL URLWithString:path];
    [[[_client getObject:getRequest] continueWithBlock:^id _Nullable(OSSTask * _Nonnull task) {
        XCTAssertNil(task.error);
        return nil;
    }] waitUntilFinished];
    XCTAssertTrue([[OSSUtil base64Md5ForFilePath:path] isEqualToString:[OSSUtil base64Md5ForFileURL:fileUrl]]);
    
    encryptionMaterials = [[OSSSimpleRSAEncryptionMaterials alloc] initWithPKCS1PrivateKeyUrl:privateKeyUrl X509PublicKeyUrl:publicKeyUrl desc:@{}];
    
    publicKeyRef = [OSSSimpleRSAEncryptionMaterials getPublicKeyFromPemPKCS8:publicKey keySizeInBits:1024 error:nil];
    privateKeyRef = [OSSSimpleRSAEncryptionMaterials getPrivateKeyFromPemPKCS1:privateKey keySizeInBits:1024 error:nil];
    [encryptionMaterials addEncryptionMaterialWithPublicKey:publicKeyRef
                                                 privateKey:privateKeyRef
                                                       desc:@{@"test":@"test"}];

    client = [[OSSEncryptionClient alloc] initWithEndpoint:OSS_ENDPOINT
                                         credentialProvider:authProv
                                        clientConfiguration:config
                                        encryptionMaterials:encryptionMaterials
                                               cryptoConfig:cryptoConfig];
    
    getRequest.bucketName = _privateBucketName;
    getRequest.objectKey = @"object2";
    getRequest.downloadToFileURL = [NSURL URLWithString:path];
    [[[client getObject:getRequest] continueWithBlock:^id _Nullable(OSSTask * _Nonnull task) {
        XCTAssertNil(task.error);
        return nil;
    }] waitUntilFinished];
    XCTAssertTrue([[OSSUtil base64Md5ForFilePath:path] isEqualToString:[OSSUtil base64Md5ForFileURL:fileUrl]]);
    
    getRequest.bucketName = _privateBucketName;
    getRequest.objectKey = @"object1";
    getRequest.downloadToFileURL = [NSURL URLWithString:path];
    [[[client getObject:getRequest] continueWithBlock:^id _Nullable(OSSTask * _Nonnull task) {
        XCTAssertNil(task.error);
        return nil;
    }] waitUntilFinished];
    XCTAssertTrue([[OSSUtil base64Md5ForFilePath:path] isEqualToString:[OSSUtil base64Md5ForFileURL:fileUrl]]);
}

- (void)testAPI_MutipartUploadObject {
    NSURL *fileUrl = [[NSBundle mainBundle] URLForResource:@"wangwang" withExtension:@"zip"];
    OSSMultipartUploadRequest *putRequest = [OSSMultipartUploadRequest new];
    putRequest.crcFlag = OSSRequestCRCOpen;
    putRequest.bucketName = _privateBucketName;
    putRequest.objectKey = OSS_IMAGE_KEY;
    putRequest.uploadingFileURL = fileUrl;
    
    [[[_client multipartUpload:putRequest] continueWithBlock:^id _Nullable(OSSTask * _Nonnull task) {
        XCTAssertNil(task.error);
        return nil;
    }] waitUntilFinished];
    
    NSString *path = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    path = [path stringByAppendingString:@"/111"];

    OSSGetObjectRequest *getRequest = [OSSGetObjectRequest new];
    getRequest.crcFlag = OSSRequestCRCOpen;
    getRequest.bucketName = _privateBucketName;
    getRequest.objectKey = OSS_IMAGE_KEY;
    getRequest.downloadToFileURL = [NSURL URLWithString:path];
    [[[_client getObject:getRequest] continueWithBlock:^id _Nullable(OSSTask * _Nonnull task) {
        XCTAssertNil(task.error);
        return nil;
    }] waitUntilFinished];
    XCTAssertTrue([[OSSUtil base64Md5ForFilePath:path] isEqualToString:[OSSUtil base64Md5ForFileURL:fileUrl]]);
}

- (void)testAPI_MutipartUploadObjectWithCreateCryptoError {
    Method method1 = class_getInstanceMethod([CryptoSchemeAesCtr class], @selector(randomGenerateKey));
    Method method2 = class_getInstanceMethod([self class], @selector(randomGenerateKey));
    method_exchangeImplementations(method1, method2);
    
    NSURL *fileUrl = [[NSBundle mainBundle] URLForResource:@"wangwang" withExtension:@"zip"];
    OSSMultipartUploadRequest *putRequest = [OSSMultipartUploadRequest new];
    putRequest.crcFlag = OSSRequestCRCOpen;
    putRequest.bucketName = _privateBucketName;
    putRequest.objectKey = OSS_IMAGE_KEY;
    putRequest.uploadingFileURL = fileUrl;
    
    [[[_client multipartUpload:putRequest] continueWithBlock:^id _Nullable(OSSTask * _Nonnull task) {
        XCTAssertNotNil(task.error);
        XCTAssertTrue(task.error.code == OSSClientErrorCodeCryptoCreateFailed);
        return nil;
    }] waitUntilFinished];
    
    method_exchangeImplementations(method1, method2);
}

- (void)testAPI_ResumableUploadObject {
    NSURL *fileUrl = [[NSBundle mainBundle] URLForResource:@"wangwang" withExtension:@"zip"];
    OSSResumableUploadRequest *request = [OSSResumableUploadRequest new];
    request.crcFlag = OSSRequestCRCOpen;
    request.bucketName = _privateBucketName;
    request.objectKey = OSS_IMAGE_KEY;
    request.uploadingFileURL = fileUrl;
    request.deleteUploadIdOnCancelling = false;
    NSString *cachesDir = [NSSearchPathForDirectoriesInDomains(NSCachesDirectory, NSUserDomainMask, YES) firstObject];
    request.recordDirectoryPath = cachesDir;
    __weak typeof(request) weakRequest = request;
    request.uploadProgress = ^(int64_t bytesSent, int64_t totalBytesSent, int64_t totalBytesExpectedToSend) {
        if (totalBytesSent > totalBytesExpectedToSend / 2) {
            [weakRequest cancel];
        }
    };
    
    [[[_client resumableUpload:request] continueWithBlock:^id _Nullable(OSSTask * _Nonnull task) {
        XCTAssertNotNil(task.error);
        XCTAssertEqual(task.error.code, OSSClientErrorCodeTaskCancelled);
        return nil;
    }] waitUntilFinished];
    
    request = [OSSResumableUploadRequest new];
    request.crcFlag = OSSRequestCRCOpen;
    request.bucketName = _privateBucketName;
    request.objectKey = OSS_IMAGE_KEY;
    request.uploadingFileURL = fileUrl;
    request.recordDirectoryPath = cachesDir;
    request.deleteUploadIdOnCancelling = false;
    
    [[[_client resumableUpload:request] continueWithBlock:^id _Nullable(OSSTask * _Nonnull task) {
        XCTAssertNil(task.error);
        return nil;
    }] waitUntilFinished];
    
    
    NSString *path = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    path = [path stringByAppendingString:@"/111"];

    OSSGetObjectRequest *getRequest = [OSSGetObjectRequest new];
    getRequest.crcFlag = OSSRequestCRCOpen;
    getRequest.bucketName = _privateBucketName;
    getRequest.objectKey = OSS_IMAGE_KEY;
    getRequest.downloadToFileURL = [NSURL URLWithString:path];
    [[[_client getObject:getRequest] continueWithBlock:^id _Nullable(OSSTask * _Nonnull task) {
        XCTAssertNil(task.error);
        return nil;
    }] waitUntilFinished];
    NSLog(@"base64Md5ForFilePath:%@", [OSSUtil base64Md5ForFilePath:path]);
    XCTAssertTrue([[OSSUtil base64Md5ForFilePath:path] isEqualToString:[OSSUtil base64Md5ForFileURL:fileUrl]]);
}

- (void)testAPI_EncryptoError {
    NSURL *fileUrl = [[NSBundle mainBundle] URLForResource:@"hasky" withExtension:@"jpeg"];
    OSSPutObjectRequest *putRequest = [OSSPutObjectRequest new];
    putRequest.bucketName = _privateBucketName;
    putRequest.objectKey = OSS_IMAGE_KEY;
    putRequest.uploadingFileURL = fileUrl;
    
    [[[_client putObject:putRequest] continueWithBlock:^id _Nullable(OSSTask * _Nonnull task) {
        XCTAssertNil(task.error);
        return nil;
    }] waitUntilFinished];
    
    NSString *path = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    path = [path stringByAppendingString:@"/111"];
    
    OSSGetObjectRequest *getRequest = [OSSGetObjectRequest new];
    getRequest.bucketName = _privateBucketName;
    getRequest.objectKey = OSS_IMAGE_KEY;
    getRequest.downloadToFileURL = [NSURL URLWithString:path];
    [[[_specialClient getObject:getRequest] continueWithBlock:^id _Nullable(OSSTask * _Nonnull task) {
        XCTAssertNotNil(task.error);
        XCTAssertTrue(task.error.code == OSSClientErrorCodeCryptoUpdate);
        return nil;
    }] waitUntilFinished];
}

- (void)testAPI_createCryptoError {
    Method method1 = class_getInstanceMethod([CryptoSchemeAesCtr class], @selector(randomGenerateKey));
    Method method2 = class_getInstanceMethod([self class], @selector(randomGenerateKey));
    method_exchangeImplementations(method1, method2);
    
    NSURL *fileUrl = [[NSBundle mainBundle] URLForResource:@"hasky" withExtension:@"jpeg"];
    OSSPutObjectRequest *putRequest = [OSSPutObjectRequest new];
    putRequest.bucketName = _privateBucketName;
    putRequest.objectKey = OSS_IMAGE_KEY;
    putRequest.uploadingFileURL = fileUrl;
    
    [[[_client putObject:putRequest] continueWithBlock:^id _Nullable(OSSTask * _Nonnull task) {
        XCTAssertNotNil(task.error);
        XCTAssertTrue(task.error.code == OSSClientErrorCodeCryptoCreateFailed);
        return nil;
    }] waitUntilFinished];
    
    method_exchangeImplementations(method1, method2);
}

- (NSData *)randomGenerateKey {
    return [NSData new];
}

@end

@implementation OSSSimpleRSAEncryptionMaterials(Test)

- (instancetype)initWithPKCS1PrivateKeyUrl:(NSURL *)privateKeyUrl
                          X509PublicKeyUrl:(NSURL *)publicKeyUrl
                                      desc:(nonnull NSDictionary *)desc {
    
    NSString *privateKey = [NSString stringWithContentsOfURL:privateKeyUrl encoding:NSUTF8StringEncoding error:nil];
    NSData *publicKey = [NSData dataWithContentsOfURL:publicKeyUrl];
    
    SecKeyRef privateKeyRef = [OSSSimpleRSAEncryptionMaterials getPrivateKeyFromPemPKCS1:privateKey keySizeInBits:1024 error:nil];
    SecKeyRef publicKeyRef = [OSSSimpleRSAEncryptionMaterials getPublicKeyFromDerX509:publicKey error:nil];
    
    return [self initWithPrivateKey:privateKeyRef
                          publicKey:publicKeyRef
                               desc:desc];
}

@end
