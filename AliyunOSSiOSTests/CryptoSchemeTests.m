//
//  CryptoSchemeTests.m
//  AliyunOSSiOSTests
//
//  Created by ws on 2022/1/7.
//  Copyright © 2022 aliyun. All rights reserved.
//

#import <XCTest/XCTest.h>
#import <AliyunOSSiOS/AliyunOSSiOS.h>

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

@interface CryptoSchemeTests : XCTestCase {
    ContentCryptoMaterial *_cryptoMaterial;
}

@end

@implementation CryptoSchemeTests

- (void)setUp {
    // Put setup code here. This method is called before the invocation of each test method in the class.
    CryptoSchemeAesCtr *scheme = [CryptoSchemeAesCtr new];
    _cryptoMaterial = [[ContentCryptoMaterial alloc] initWithOperation:kCCEncrypt cek:[scheme randomGenerateKey] iv:[scheme randomGenerateIV] mode:[scheme getContentChiperMode] algorithm:[scheme getContentChiperAlgorithm] padding:[scheme getContentChiperPadding]];
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
}

- (void)testExample {
    // This is an example of a functional test case.
    // Use XCTAssert and related functions to verify your tests produce the correct results.
}

- (void)testPerformanceExample {
    // This is an example of a performance test case.
    [self measureBlock:^{
        // Put the code you want to measure the time of here.
    }];
}

- (void)testAPI_IncrementBlocks {
    Byte b_iv[] = { 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0x01, 0x02, 0x03, 0x04 };
    NSData *iv = [NSData dataWithBytes:b_iv length:sizeof(b_iv)];
    NSError *error = nil;
    NSData *retIV = [CryptoScheme incrementBlocks:iv blockDelta:0X1122334400000000L error:nil];
    XCTAssertNil(error);
    
    Byte b_expectedIV[] = { 1, 2, 3, 4, 5, 6, 7, 8, 0x11, 0x22, 0x33, 0x44, 0x01, 0x02, 0x03, 0x04 };
    NSData *expectedIV = [NSData dataWithBytes:b_expectedIV length:sizeof(b_expectedIV)];
    XCTAssertTrue([retIV isEqual:expectedIV]);
}

- (void)testAPI_IncrementBlocksWithNil {
    Byte b_iv[] = { 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0x01, 0x02, 0x03 };
    NSData *iv = [NSData dataWithBytes:b_iv length:sizeof(b_iv)];
    
    NSError *error = nil;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wnonnull"
    NSData *retIV = [CryptoScheme incrementBlocks:nil blockDelta:0X1122334400000000L error:&error];
#pragma clang diagnostic pop
    XCTAssertNil(retIV);
    XCTAssertNotNil(error);
    XCTAssertTrue([error.userInfo[OSSErrorMessageTOKEN] isEqualToString:@"iv is nil or not 16-bytes."]);
    
    error = nil;
    retIV = [CryptoScheme incrementBlocks:iv blockDelta:0X1122334400000000L error:&error];
    XCTAssertNil(retIV);
    XCTAssertNotNil(error);
    XCTAssertTrue([error.userInfo[OSSErrorMessageTOKEN] isEqualToString:@"iv is nil or not 16-bytes."]);
}

- (void)testAPI_abstractMethod {
    CryptoScheme *cryptoScheme = [CryptoScheme new];
    XCTAssertThrowsSpecificNamed([cryptoScheme getContentChiperAlgorithm], NSException, NSInternalInconsistencyException);
    XCTAssertThrowsSpecificNamed([cryptoScheme getContentChiperMode], NSException, NSInternalInconsistencyException);
    XCTAssertThrowsSpecificNamed([cryptoScheme getContentChiperPadding], NSException, NSInternalInconsistencyException);
    XCTAssertThrowsSpecificNamed([cryptoScheme getKeyLengthInBits], NSException, NSInternalInconsistencyException);
    XCTAssertThrowsSpecificNamed([cryptoScheme getContentChiperIVLength], NSException, NSInternalInconsistencyException);
    
    XCTAssertThrowsSpecificNamed([cryptoScheme randomGenerateIV], NSException, NSInternalInconsistencyException);
    XCTAssertThrowsSpecificNamed([cryptoScheme randomGenerateKey], NSException, NSInternalInconsistencyException);
}

- (void)testAPI_mutilpartCrypto {
    CryptoSchemeAesCtr *scheme = [CryptoSchemeAesCtr new];
    ContentCryptoMaterial *cryptoMaterial = [[ContentCryptoMaterial alloc] initWithOperation:kCCEncrypt cek:[scheme randomGenerateKey] iv:[scheme randomGenerateIV] mode:[scheme getContentChiperMode] algorithm:[scheme getContentChiperAlgorithm] padding:[scheme getContentChiperPadding]];
    Cryptor *cryptor = [[Cryptor alloc] initWithCryptoMaterail:cryptoMaterial];

    NSString *path = [[NSBundle mainBundle] pathForResource:@"hasky" ofType:@"jpeg"];
    NSData *originData = [NSData dataWithContentsOfFile:path];

    NSError *error;
    NSData *cryptedData = [cryptor cryptorUpdate:originData error:&error];

    NSFileManager *fm = [NSFileManager defaultManager];
    NSDictionary *attributes = [fm attributesOfItemAtPath:path error:nil];
    NSInteger partSize = 100 * 1024;
    NSInteger partLength = (attributes.fileSize / partSize) + 1;

    NSMutableData *mutilpartCryptedData = [NSMutableData data];
    for (int i = 0; i < partLength; i++) {
        NSFileHandle *fileHandle = [NSFileHandle fileHandleForReadingAtPath:path];
        [fileHandle seekToFileOffset:partSize * i];
        NSData *partData;
        if (i == partLength - 1) {
            partData = [fileHandle readDataToEndOfFile];
        } else {
            partData = [fileHandle readDataOfLength:partSize];
        }

        NSInteger offset = partSize * i;
        NSInteger skipBlock = offset / 16;
        NSData *iv = [CryptoScheme incrementBlocks:cryptoMaterial.iv blockDelta:skipBlock error:&error];
        XCTAssertNil(error);
        Cryptor *partCryptor = [[Cryptor alloc] initWithOperation:cryptoMaterial.operation
                                                              cek:cryptoMaterial.cek
                                                               iv:iv
                                                             mode:cryptoMaterial.mode
                                                        algorithm:cryptoMaterial.algorithm
                                                          padding:cryptoMaterial.padding];
        NSData *cryptedPartData = [partCryptor cryptorUpdate:partData error:nil];
        [mutilpartCryptedData appendData:cryptedPartData];
    }

    XCTAssertTrue([[OSSUtil base64Md5ForData:cryptedData] isEqualToString:[OSSUtil base64Md5ForData:mutilpartCryptedData]]);
}

@end
