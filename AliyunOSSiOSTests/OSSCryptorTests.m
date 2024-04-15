//
//  OSSCrypterTests.m
//  AliyunOSSiOSTests
//
//  Created by ws on 2022/1/6.
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

@interface OSSCryptorTests : XCTestCase {
    ContentCryptoMaterial *_cryptoMaterial;
}

@end

@implementation OSSCryptorTests

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

- (void)testAPI_createCryptorFailed {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wnonnull"
    Cryptor *cryptor = [[Cryptor alloc] initWithOperation:_cryptoMaterial.operation
                                                      cek:nil
                                                       iv:_cryptoMaterial.iv
                                                     mode:_cryptoMaterial.mode
                                                algorithm:_cryptoMaterial.algorithm
                                                  padding:_cryptoMaterial.padding];
#pragma clang diagnostic pop

    NSString *path = [[NSBundle mainBundle] pathForResource:@"hasky" ofType:@"jpeg"];
    NSData *originData = [NSData dataWithContentsOfFile:path];

    NSError *error;
    NSData *cryptedData = [cryptor cryptorUpdate:originData error:&error];
    XCTAssertNil(cryptedData);
    XCTAssertNotNil(error);
    XCTAssertTrue([error.domain isEqualToString:OSSClientErrorDomain]);
    XCTAssertTrue(error.code == OSSClientErrorCodeCryptoCreateFailed);
}

- (void)testAPI_crypto {
    Cryptor *cryptor = [[Cryptor alloc] initWithCryptoMaterail:_cryptoMaterial];
    NSString *path = [[NSBundle mainBundle] pathForResource:@"hasky" ofType:@"jpeg"];
    NSData *originData = [NSData dataWithContentsOfFile:path];
    
    NSError *error;
    NSData *cryptedData = [cryptor cryptorUpdate:originData error:&error];
    XCTAssertNil(error);
    XCTAssertNotNil(cryptedData);
}

- (void)testAPI_cryptoWithNilData {
    Cryptor *cryptor = [[Cryptor alloc] initWithCryptoMaterail:_cryptoMaterial];

    NSError *error;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wnonnull"
    NSData *cryptedData = [cryptor cryptorUpdate:nil error:&error];
#pragma clang diagnostic pop
    XCTAssertNil(error);
    XCTAssertNotNil(cryptedData);
}

- (void)testAPI_cryptorUploadDataFailed {
//    Cryptor *cryptor = [[Cryptor alloc] initWithOperation:kCCDecrypt
//                                                      cek:_cryptoMaterial.cek
//                                                       iv:_cryptoMaterial.iv
//                                                     mode:_cryptoMaterial.mode
//                                                algorithm:_cryptoMaterial.algorithm
//                                                  padding:_cryptoMaterial.padding];
//
//    NSString *path = [[NSBundle mainBundle] pathForResource:@"hasky" ofType:@"jpeg"];
//    NSData *originData = [NSData dataWithContentsOfFile:path];
//
//    NSError *error;
//    NSData *cryptedData = [cryptor cryptorUpdate:originData error:&error];
//    XCTAssertNotNil(error);
//    XCTAssertTrue([error.domain isEqualToString:OSSClientErrorDomain]);
//    XCTAssertTrue(error.code == OSSClientErrorCodeCryptoUpdate);
}

- (void)testAPI_resetCryptor {
    Cryptor *cryptor = [[Cryptor alloc] initWithCryptoMaterail:_cryptoMaterial];
    NSString *path = [[NSBundle mainBundle] pathForResource:@"hasky" ofType:@"jpeg"];
    NSData *originData = [NSData dataWithContentsOfFile:path];
    
    NSError *error;
    NSData *firstCryptedData = [cryptor cryptorUpdate:originData error:&error];
    XCTAssertNil(error);
    NSData *countinueCryptedData = [cryptor cryptorUpdate:originData error:&error];
    XCTAssertNil(error);
    XCTAssertFalse([[OSSUtil base64Md5ForData:firstCryptedData] isEqualToString:[OSSUtil base64Md5ForData:countinueCryptedData]]);
    
    CCCryptorStatus status = [cryptor resetCryptor];
    XCTAssertEqual(status, kCCSuccess);
    NSData *secondCryptedData = [cryptor cryptorUpdate:originData error:&error];
    XCTAssertNil(error);
    XCTAssertTrue([[OSSUtil base64Md5ForData:firstCryptedData] isEqualToString:[OSSUtil base64Md5ForData:secondCryptedData]]);
}

@end

