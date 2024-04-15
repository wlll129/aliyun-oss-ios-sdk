//
//  OSSCryptoInputStreamTest.m
//  AliyunOSSiOSTests
//
//  Created by ws on 2021/8/26.
//  Copyright © 2021 aliyun. All rights reserved.
//

#import <XCTest/XCTest.h>
#import <AliyunOSSiOS/AliyunOSSiOS.h>
#import <AliyunOSSiOS/CipherInputStream.h>
#import <AliyunOSSiOS/Cryptor.h>
#import <AliyunOSSiOS/CryptoSchemeAesCtr.h>
#import <objc/runtime.h>

@interface OSSCipherInputStreamTest : XCTestCase <NSStreamDelegate>

@end

@implementation OSSCipherInputStreamTest

- (void)setUp {
    // Put setup code here. This method is called before the invocation of each test method in the class.
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
}

- (void)testAPI_read {
    CryptoSchemeAesCtr *scheme = [CryptoSchemeAesCtr new];
    Cryptor *cryptor = [[Cryptor alloc] initWithOperation:kCCEncrypt
                                                      cek:[scheme randomGenerateKey]
                                                       iv:[scheme randomGenerateIV]
                                                     mode:[scheme getContentChiperMode]
                                                algorithm:[scheme getContentChiperAlgorithm]
                                                  padding:[scheme getContentChiperPadding]];
    
    NSURL *url = [[NSBundle mainBundle] URLForResource:@"hasky" withExtension:@"jpeg"];
    NSData *originData = [NSData dataWithContentsOfURL:url];
    
    CipherInputStream *inputStream = [[CipherInputStream alloc] initWithURL:url cryptor:cryptor];
    NSMutableData *data = [NSMutableData new];

    [inputStream open];
    while (inputStream.hasBytesAvailable) {
        uint8_t buf[1024];
        unsigned long len = 0;
        len = [inputStream read:buf maxLength:1024];
        if (len) {
            [data appendBytes:(const void *)buf length:len];
        }
    }
    [inputStream close];
    
    [cryptor resetCryptor];
    NSData *cryptedData = [cryptor cryptorUpdate:originData error:nil];

    XCTAssertTrue([[OSSUtil base64Md5ForData:cryptedData] isEqualToString:[OSSUtil base64Md5ForData:data]]);
}

- (void)testAPI_getBuffer {
    
    Method a = class_getInstanceMethod([NSData class], @selector(length));
    Method b = class_getInstanceMethod([self class], @selector(length));

    method_exchangeImplementations(a, b);
    
    CryptoSchemeAesCtr *scheme = [CryptoSchemeAesCtr new];
    Cryptor *cryptor = [[Cryptor alloc] initWithOperation:kCCEncrypt
                                                      cek:[scheme randomGenerateKey]
                                                       iv:[scheme randomGenerateIV]
                                                     mode:[scheme getContentChiperMode]
                                                algorithm:[scheme getContentChiperAlgorithm]
                                                  padding:[scheme getContentChiperPadding]];
    
    NSURL *url = [[NSBundle mainBundle] URLForResource:@"wangwang" withExtension:@"zip"];
    NSData *originData = [NSData dataWithContentsOfURL:url];
    NSData *d = [originData copy];
    
    CipherInputStream *inputStream = [[CipherInputStream alloc] initWithData:d cryptor:cryptor];
    NSMutableData *data = [NSMutableData new];
    [inputStream open];
    while (inputStream.hasBytesAvailable) {
        uint8_t *buf;
        NSUInteger len;
        BOOL readed = [inputStream getBuffer:&buf length:&len];
        if (readed) {
            [data appendBytes:(const void *)buf length:len];
        } else {
            break;
        }
    }
    
    [inputStream close];
    
    [cryptor resetCryptor];
    NSData *cryptedData = [cryptor cryptorUpdate:originData error:nil];

    XCTAssertTrue([[OSSUtil base64Md5ForData:cryptedData] isEqualToString:[OSSUtil base64Md5ForData:data]]);
}

- (NSUInteger)length {
    return 10;
}

@end
