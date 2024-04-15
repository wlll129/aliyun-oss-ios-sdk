//
//  OSSCryptoHttpResponseParserTest.m
//  AliyunOSSiOSTests
//
//  Created by ws on 2022/1/7.
//  Copyright © 2022 aliyun. All rights reserved.
//

#import <XCTest/XCTest.h>
#import <AliyunOSSiOS/AliyunOSSiOS.h>

@interface OSSCryptoHttpResponseParserTest : XCTestCase {
    OSSSimpleRSAEncryptionMaterials *_encryptionMaterials;
    CryptoSchemeAesCtr *_cryptoScheme;
    ContentCryptoMaterial *_cryptoMaterial;
    NSDictionary *_desc;
}

@end

@implementation OSSCryptoHttpResponseParserTest

static NSString *publicKey = @"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDIUc0RE+OF4qvJkFp/sBR4iiPy5czlKdHoOKOjhvh93aGpipoMb05+t07XSOBDJUzKGhqqVQJZEQahKXJUU0h3mxYyxRQMhhWWWdH1LH4s/GAjf4h5l+6tKxS6mnZGH4IlbJz1pvbPiZjzD6BEWtGBMAxZIjqPgSRjJpB6fBIrHQIDAQAB";
static NSString *privateKey = @"-----BEGIN RSA PRIVATE KEY-----\nMIICXQIBAAKBgQDIUc0RE+OF4qvJkFp/sBR4iiPy5czlKdHoOKOjhvh93aGpipoM\nb05+t07XSOBDJUzKGhqqVQJZEQahKXJUU0h3mxYyxRQMhhWWWdH1LH4s/GAjf4h5\nl+6tKxS6mnZGH4IlbJz1pvbPiZjzD6BEWtGBMAxZIjqPgSRjJpB6fBIrHQIDAQAB\nAoGAG7kmdkyYWnkqaTTvMWi/DIehvgYLu1N0V30vOHx/e3vm2b3y3/GvnV3lLWpK\nj0BkRjwioJwvPQBcOIWx6vWzu4soHNI+e1FTJgFETfWs1+HAPgR9GptbDJGdVHc4\ni85JB+nKvbuEmm/kq0xmdQ3OeSVqZqyflmGTncCMUAK5WAECQQDpBws3eDa7w4Sr\nZyomMMiv0UW6GYWWXxnvSVzK2A55AQiSoejU2RPhZ6LJzuvr2Mez9l7mOvyiJvvd\ncaO6UawdAkEA3BFM2z82m3Q9eYPSegB2knCAuKTjZZmDLt7Ibd/z1KgdKr3tpzRt\nWNlxqS0l9bsN79IfSwGwwbFFhiQSrWRLAQJAJs9gg92GqCD5IJ7u+ytW0Ul2ZndH\ns3KlXCAIz1PKnUaZyeojYAfDcuAS0a+fxUj2gbd/uLKMTulVO11o2mgt1QJBAJBb\nUN0pNDr5HzJMxI5/K0iYP/ffQcNt1d2zCir5E0tWE/vrpq9d9rSnvqVJFnOBBn1g\nimJ7c2U7Ue3ST+YpugECQQDGSAxsLaSGFLfbBOKzM7spv3cvza7vYBksfR6xT6KR\naURh6yaGmkK8gfmrkFMtWQ0CC3fNecewUNLpScuKunCh\n-----END RSA PRIVATE KEY-----";

- (void)setUp {
    // Put setup code here. This method is called before the invocation of each test method in the class.
    _desc = @{@"test": @"test"};
    
    SecKeyRef publicKeyRef = [OSSSimpleRSAEncryptionMaterials getPublicKeyFromPemPKCS8:publicKey keySizeInBits:1024 error:nil];
    SecKeyRef privateKeyRef = [OSSSimpleRSAEncryptionMaterials getPrivateKeyFromPemPKCS1:privateKey keySizeInBits:1024 error:nil];
   
    _encryptionMaterials = [[OSSSimpleRSAEncryptionMaterials alloc] initWithPrivateKey:privateKeyRef publicKey:publicKeyRef desc:@{}];
    
    _cryptoScheme = [CryptoSchemeAesCtr new];
    _cryptoMaterial = [[ContentCryptoMaterial alloc] initWithOperation:kCCEncrypt
                                                                   cek:[_cryptoScheme randomGenerateKey]
                                                                    iv:[_cryptoScheme randomGenerateIV]
                                                                  mode:[_cryptoScheme getContentChiperMode]
                                                             algorithm:[_cryptoScheme getContentChiperAlgorithm]
                                                               padding:[_cryptoScheme getContentChiperPadding]];
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
}

- (void)testAPI_encryptedData {
    NSString *path = [[NSBundle mainBundle] pathForResource:@"hasky" ofType:@"jpeg"];
    NSData *originData = [NSData dataWithContentsOfFile:path];
    __block NSData *parseData = nil;
    
    NSError *error = nil;
    ContentCryptoMaterial *cryptoMaterial = [[ContentCryptoMaterial alloc] initWithOperation:kCCEncrypt
                                                                                         cek:[_cryptoScheme randomGenerateKey]
                                                                                          iv:[_cryptoScheme randomGenerateIV]
                                                                                        mode:[_cryptoScheme getContentChiperMode]
                                                                                   algorithm:[_cryptoScheme getContentChiperAlgorithm]
                                                                                     padding:[_cryptoScheme getContentChiperPadding]];
    NSData *encryptedData = [self cryptoData:originData cryptoMaterial:cryptoMaterial];

    [_encryptionMaterials encrypt:cryptoMaterial error:&error];
    
    OSSCryptoHttpResponseParser *responseParser = [[OSSCryptoHttpResponseParser alloc]
                                                             initForOperationType:OSSOperationTypeGetObject
                                                             encryptionMaterials:_encryptionMaterials
                                                             cryptoScheme:_cryptoScheme];
    responseParser.onRecieveBlock = ^(NSData * data) {
        parseData = data;
    };
    NSDictionary *header = @{
        OSSHttpHeaderCryptoKey: [cryptoMaterial.encryptedCEK base64EncodedStringWithOptions:0],
        OSSHttpHeaderCryptoIV: [cryptoMaterial.encryptedIV base64EncodedStringWithOptions:0],
        OSSHttpHeaderCryptoMatdesc: [_desc base64JsonString],
        OSSHttpHeaderContentLength: [NSString stringWithFormat:@"%ld", originData.length],
        OSSHttpHeaderCryptoWrapAlg: @"RSA/NONE/PKCS1Padding",
        OSSHttpHeaderCryptoCEKAlg: @"AES/CTR/NoPadding"
    };

    NSHTTPURLResponse *response = [[NSHTTPURLResponse alloc] initWithURL:[NSURL URLWithString:@"http://www.aliyun.com"]
                                                              statusCode:200
                                                             HTTPVersion:@"HTTP/1.1"
                                                            headerFields:header];
    [responseParser consumeHttpResponse:response];
    OSSTask *task = [responseParser consumeHttpResponseBody:encryptedData];
    [task waitUntilFinished];
    XCTAssertNil(task.error);
    XCTAssertNotNil(parseData);
    XCTAssertTrue([[OSSUtil base64Md5ForData:parseData] isEqualToString:[OSSUtil base64Md5ForData:originData]]);
}

- (void)testAPI_mutilpartEncryptedData {
    NSString *path = [[NSBundle mainBundle] pathForResource:@"hasky" ofType:@"jpeg"];
    NSData *originData = [NSData dataWithContentsOfFile:path];
    __block NSMutableData *parseData = [NSMutableData new];
    NSInteger partSize = 10240;

    NSError *error = nil;
    ContentCryptoMaterial *cryptoMaterial = [[ContentCryptoMaterial alloc] initWithOperation:kCCEncrypt
                                                                                         cek:[_cryptoScheme randomGenerateKey]
                                                                                          iv:[_cryptoScheme randomGenerateIV]
                                                                                        mode:[_cryptoScheme getContentChiperMode]
                                                                                   algorithm:[_cryptoScheme getContentChiperAlgorithm]
                                                                                     padding:[_cryptoScheme getContentChiperPadding]];
    NSData *encryptedData = [self cryptoData:originData cryptoMaterial:cryptoMaterial];

    [_encryptionMaterials encrypt:cryptoMaterial error:&error];
    
    OSSCryptoHttpResponseParser *responseParser = [[OSSCryptoHttpResponseParser alloc]
                                                             initForOperationType:OSSOperationTypeGetObject
                                                             encryptionMaterials:_encryptionMaterials
                                                             cryptoScheme:_cryptoScheme];
    responseParser.onRecieveBlock = ^(NSData * data) {
        [parseData appendData:data];
    };
    NSDictionary *header = @{
        OSSHttpHeaderCryptoKey: [cryptoMaterial.encryptedCEK base64EncodedStringWithOptions:0],
        OSSHttpHeaderCryptoIV: [cryptoMaterial.encryptedIV base64EncodedStringWithOptions:0],
        OSSHttpHeaderCryptoMatdesc: [_desc base64JsonString],
        OSSHttpHeaderContentLength: [NSString stringWithFormat:@"%ld", originData.length],
        OSSHttpHeaderCryptoWrapAlg: @"RSA/NONE/PKCS1Padding",
        OSSHttpHeaderCryptoCEKAlg: @"AES/CTR/NoPadding"
    };

    NSHTTPURLResponse *response = [[NSHTTPURLResponse alloc] initWithURL:[NSURL URLWithString:@"http://www.aliyun.com"]
                                                              statusCode:200
                                                             HTTPVersion:@"HTTP/1.1"
                                                            headerFields:header];
    [responseParser consumeHttpResponse:response];
    NSInteger partNum = ([encryptedData length] / partSize) + ([encryptedData length] % partSize > 0 ? 1 : 0);
    for (int i = 0; i < partNum; i++) {
        NSInteger length = (i == partNum - 1 && [encryptedData length] % partSize > 0) ? [encryptedData length] - (partSize * i) : partSize;
        NSData *data = [encryptedData subdataWithRange:(NSRange){i * partSize, length}];
        OSSTask *task = [responseParser consumeHttpResponseBody:data];
        [task waitUntilFinished];
        XCTAssertNil(task.error);
    }
    XCTAssertNotNil(parseData);
    XCTAssertTrue([[OSSUtil base64Md5ForData:parseData] isEqualToString:[OSSUtil base64Md5ForData:originData]]);
}

- (void)testAPI_encryptedDataWithRange {
    NSString *path = [[NSBundle mainBundle] pathForResource:@"hasky" ofType:@"jpeg"];
    NSData *originData = [NSData dataWithContentsOfFile:path];
    __block NSMutableData *parseData = [NSMutableData new];
    NSInteger partSize = 10240;
    NSInteger start = 2 * 16;
    NSInteger length = originData.length - start;
    OSSRange *range = [[OSSRange alloc] initWithStart:start withEnd:length + start];
    
    NSError *error = nil;
    ContentCryptoMaterial *cryptoMaterial = [[ContentCryptoMaterial alloc] initWithOperation:kCCEncrypt
                                                                                         cek:[_cryptoScheme randomGenerateKey]
                                                                                          iv:[_cryptoScheme randomGenerateIV]
                                                                                        mode:[_cryptoScheme getContentChiperMode]
                                                                                   algorithm:[_cryptoScheme getContentChiperAlgorithm]
                                                                                     padding:[_cryptoScheme getContentChiperPadding]];
    NSData *encryptedData = [self cryptoData:originData cryptoMaterial:cryptoMaterial];

    [_encryptionMaterials encrypt:cryptoMaterial error:&error];
    
    NSDictionary *header = @{
        OSSHttpHeaderCryptoKey: [cryptoMaterial.encryptedCEK base64EncodedStringWithOptions:0],
        OSSHttpHeaderCryptoIV: [cryptoMaterial.encryptedIV base64EncodedStringWithOptions:0],
        OSSHttpHeaderCryptoMatdesc: [_desc base64JsonString],
        OSSHttpHeaderContentLength: [NSString stringWithFormat:@"%ld", length],
        OSSHttpHeaderCryptoWrapAlg: @"RSA/NONE/PKCS1Padding",
        OSSHttpHeaderCryptoCEKAlg: @"AES/CTR/NoPadding",
        OSSHttpHeaderContentRange: [NSString stringWithFormat:@"%ld-%@", start, (length + start == originData.length) ? @"": @(originData.length)],
    };

    NSHTTPURLResponse *response = [[NSHTTPURLResponse alloc] initWithURL:[NSURL URLWithString:@"http://www.aliyun.com"]
                                                              statusCode:200
                                                             HTTPVersion:@"HTTP/1.1"
                                                            headerFields:header];
    
    OSSCryptoHttpResponseParser *responseParser = [[OSSCryptoHttpResponseParser alloc]
                                                             initForOperationType:OSSOperationTypeGetObject
                                                             encryptionMaterials:_encryptionMaterials
                                                             cryptoScheme:_cryptoScheme];
    responseParser.range = range;
    responseParser.adjustedCryptoRange = range;
    responseParser.onRecieveBlock = ^(NSData * data) {
        [parseData appendData:data];
    };
    [responseParser consumeHttpResponse:response];
    encryptedData = [encryptedData subdataWithRange:(NSRange){start, length}];
    NSInteger partNum = ([encryptedData length] / partSize) + ([encryptedData length] % partSize > 0 ? 1 : 0);
    for (int i = 0; i < partNum; i++) {
        NSInteger length = (i == partNum - 1 && [encryptedData length] % partSize > 0) ? [encryptedData length] - (partSize * i) : partSize;
        NSLog(@"%ld: %ld - %ld", [encryptedData length], i * partSize, length);
        NSData *data = [encryptedData subdataWithRange:(NSRange){i * partSize, length}];
        OSSTask *task = [responseParser consumeHttpResponseBody:data];
        [task waitUntilFinished];
        XCTAssertNil(task.error);
    }
    XCTAssertNotNil(parseData);
    NSData *subData = [originData subdataWithRange:NSMakeRange(start, length)];
    XCTAssertTrue([[OSSUtil base64Md5ForData:parseData] isEqualToString:[OSSUtil base64Md5ForData:subData]]);
}

- (void)testAPI_encryptedDataWithEmptyHeader {
    NSString *path = [[NSBundle mainBundle] pathForResource:@"hasky" ofType:@"jpeg"];
    NSData *originData = [NSData dataWithContentsOfFile:path];
    __block NSMutableData *parseData = [NSMutableData new];
    NSInteger partSize = 10240;

    NSError *error = nil;
    ContentCryptoMaterial *cryptoMaterial = [[ContentCryptoMaterial alloc] initWithOperation:kCCEncrypt
                                                                                         cek:[_cryptoScheme randomGenerateKey]
                                                                                          iv:[_cryptoScheme randomGenerateIV]
                                                                                        mode:[_cryptoScheme getContentChiperMode]
                                                                                   algorithm:[_cryptoScheme getContentChiperAlgorithm]
                                                                                     padding:[_cryptoScheme getContentChiperPadding]];
    NSData *encryptedData = [self cryptoData:originData cryptoMaterial:cryptoMaterial];

    [_encryptionMaterials encrypt:cryptoMaterial error:&error];
    
    NSDictionary *header = @{
        OSSHttpHeaderCryptoMatdesc: [_desc base64JsonString],
        OSSHttpHeaderContentLength: [NSString stringWithFormat:@"%ld", originData.length],
    };
    NSHTTPURLResponse *response = [[NSHTTPURLResponse alloc] initWithURL:[NSURL URLWithString:@"http://www.aliyun.com"]
                                                              statusCode:200
                                                             HTTPVersion:@"HTTP/1.1"
                                                            headerFields:header];
    OSSCryptoHttpResponseParser *responseParser = [[OSSCryptoHttpResponseParser alloc]
                                                             initForOperationType:OSSOperationTypeGetObject
                                                             encryptionMaterials:_encryptionMaterials
                                                             cryptoScheme:_cryptoScheme];
    responseParser.onRecieveBlock = ^(NSData * data) {
        [parseData appendData:data];
    };
    [responseParser consumeHttpResponse:response];
    NSInteger partNum = ([encryptedData length] / partSize) + ([encryptedData length] % partSize > 0 ? 1 : 0);
    for (int i = 0; i < partNum; i++) {
        NSInteger length = (i == partNum - 1 && [encryptedData length] % partSize > 0) ? [encryptedData length] - (partSize * i) : partSize;
        NSData *data = [encryptedData subdataWithRange:(NSRange){i * partSize, length}];
        OSSTask *task = [responseParser consumeHttpResponseBody:data];
        [task waitUntilFinished];
        XCTAssertNil(task.error);
    }
    XCTAssertNotNil(parseData);
    XCTAssertTrue([[OSSUtil base64Md5ForData:parseData] isEqualToString:[OSSUtil base64Md5ForData:encryptedData]]);
}

- (void)testAPI_encryptedDataWithErrorHeader {
    NSString *path = [[NSBundle mainBundle] pathForResource:@"hasky" ofType:@"jpeg"];
    NSData *originData = [NSData dataWithContentsOfFile:path];
    __block NSMutableData *parseData = [NSMutableData new];
    NSInteger partSize = 10240;

    ContentCryptoMaterial *cryptoMaterial = [[ContentCryptoMaterial alloc] initWithOperation:kCCEncrypt
                                                                                         cek:[_cryptoScheme randomGenerateKey]
                                                                                          iv:[_cryptoScheme randomGenerateIV]
                                                                                        mode:[_cryptoScheme getContentChiperMode]
                                                                                   algorithm:[_cryptoScheme getContentChiperAlgorithm]
                                                                                     padding:[_cryptoScheme getContentChiperPadding]];
    [_encryptionMaterials encrypt:cryptoMaterial error:nil];
    NSData *encryptedData = [self cryptoData:originData cryptoMaterial:cryptoMaterial];
    
    NSDictionary *header = @{
        OSSHttpHeaderCryptoKey: @"111",
        OSSHttpHeaderCryptoIV: @"222",
        OSSHttpHeaderCryptoMatdesc: [_desc base64JsonString],
        OSSHttpHeaderContentLength: [NSString stringWithFormat:@"%ld", originData.length],
        OSSHttpHeaderCryptoWrapAlg: @"RSA/NONE/PKCS1Padding",
        OSSHttpHeaderCryptoCEKAlg: @"AES/CTR/NoPadding"
    };
    NSHTTPURLResponse *response = [[NSHTTPURLResponse alloc] initWithURL:[NSURL URLWithString:@"http://www.aliyun.com"]
                                                              statusCode:200
                                                             HTTPVersion:@"HTTP/1.1"
                                                            headerFields:header];
    OSSCryptoHttpResponseParser *responseParser = [[OSSCryptoHttpResponseParser alloc]
                                                             initForOperationType:OSSOperationTypeGetObject
                                                             encryptionMaterials:_encryptionMaterials
                                                             cryptoScheme:_cryptoScheme];
    responseParser.onRecieveBlock = ^(NSData * data) {
        [parseData appendData:data];
    };
    [responseParser consumeHttpResponse:response];
    NSInteger partNum = ([encryptedData length] / partSize) + ([encryptedData length] % partSize > 0 ? 1 : 0);
    for (int i = 0; i < partNum; i++) {
        NSInteger length = (i == partNum - 1 && [encryptedData length] % partSize > 0) ? [encryptedData length] - (partSize * i) : partSize;
        NSData *data = [encryptedData subdataWithRange:(NSRange){i * partSize, length}];
        OSSTask *task = [responseParser consumeHttpResponseBody:data];
        [task waitUntilFinished];
        XCTAssertNotNil(task.error);
        XCTAssertTrue(task.error.code == OSSClientErrorCodeCannotDecrypted);
        XCTAssertTrue([task.error.userInfo[OSSErrorMessageTOKEN] containsString:@"key or iv is not base64 ebdcoded string."]);
    }
    
    
    // cek or iv error
    header = @{
        OSSHttpHeaderCryptoKey: [cryptoMaterial.cek base64EncodedStringWithOptions:0],
        OSSHttpHeaderCryptoIV: [cryptoMaterial.iv base64EncodedStringWithOptions:0],
        OSSHttpHeaderCryptoMatdesc: [_desc base64JsonString],
        OSSHttpHeaderContentLength: [NSString stringWithFormat:@"%ld", originData.length],
        OSSHttpHeaderCryptoWrapAlg: @"RSA/NONE/PKCS1Padding",
        OSSHttpHeaderCryptoCEKAlg: @"AES/CTR/NoPadding"
    };
    response = [[NSHTTPURLResponse alloc] initWithURL:[NSURL URLWithString:@"http://www.aliyun.com"]
                                           statusCode:200
                                          HTTPVersion:@"HTTP/1.1"
                                         headerFields:header];
    responseParser = [[OSSCryptoHttpResponseParser alloc] initForOperationType:OSSOperationTypeGetObject
                                                           encryptionMaterials:_encryptionMaterials
                                                                  cryptoScheme:_cryptoScheme];
    responseParser.onRecieveBlock = ^(NSData * data) {
        [parseData appendData:data];
    };
    [responseParser consumeHttpResponse:response];
    partNum = ([encryptedData length] / partSize) + ([encryptedData length] % partSize > 0 ? 1 : 0);
    for (int i = 0; i < partNum; i++) {
        NSInteger length = (i == partNum - 1 && [encryptedData length] % partSize > 0) ? [encryptedData length] - (partSize * i) : partSize;
        NSData *data = [encryptedData subdataWithRange:(NSRange){i * partSize, length}];
        OSSTask *task = [responseParser consumeHttpResponseBody:data];
        [task waitUntilFinished];
        XCTAssertNotNil(task.error);
        XCTAssertTrue(task.error.code == OSSClientErrorCodeCryptoUpdate);
    }
    
    // CEKAlg error
    header = @{
        OSSHttpHeaderCryptoKey: [cryptoMaterial.encryptedCEK base64EncodedStringWithOptions:0],
        OSSHttpHeaderCryptoIV: [cryptoMaterial.encryptedIV base64EncodedStringWithOptions:0],
        OSSHttpHeaderCryptoMatdesc: [_desc base64JsonString],
        OSSHttpHeaderContentLength: [NSString stringWithFormat:@"%ld", originData.length],
        OSSHttpHeaderCryptoWrapAlg: @"RSA/NONE/PKCS1Padding",
        OSSHttpHeaderCryptoCEKAlg: @"AES/CTR"
    };
    response = [[NSHTTPURLResponse alloc] initWithURL:[NSURL URLWithString:@"http://www.aliyun.com"]
                                           statusCode:200
                                          HTTPVersion:@"HTTP/1.1"
                                         headerFields:header];
    responseParser = [[OSSCryptoHttpResponseParser alloc] initForOperationType:OSSOperationTypeGetObject
                                                           encryptionMaterials:_encryptionMaterials
                                                                  cryptoScheme:_cryptoScheme];
    responseParser.onRecieveBlock = ^(NSData * data) {
        [parseData appendData:data];
    };
    [responseParser consumeHttpResponse:response];
    partNum = ([encryptedData length] / partSize) + ([encryptedData length] % partSize > 0 ? 1 : 0);
    for (int i = 0; i < partNum; i++) {
        NSInteger length = (i == partNum - 1 && [encryptedData length] % partSize > 0) ? [encryptedData length] - (partSize * i) : partSize;
        NSData *data = [encryptedData subdataWithRange:(NSRange){i * partSize, length}];
        OSSTask *task = [responseParser consumeHttpResponseBody:data];
        [task waitUntilFinished];
        XCTAssertNotNil(task.error);
        XCTAssertTrue(task.error.code == OSSClientErrorCodeCannotDecrypted);
        XCTAssertTrue([task.error.userInfo[OSSErrorMessageTOKEN] containsString:@"cek algorithm is error."]);
    }
    
    // CEKAlg error
    header = @{
        OSSHttpHeaderCryptoKey: [cryptoMaterial.encryptedCEK base64EncodedStringWithOptions:0],
        OSSHttpHeaderCryptoIV: [cryptoMaterial.encryptedCEK base64EncodedStringWithOptions:0],
        OSSHttpHeaderCryptoMatdesc: [_desc base64JsonString],
        OSSHttpHeaderContentLength: [NSString stringWithFormat:@"%ld", originData.length],
        OSSHttpHeaderCryptoWrapAlg: @"KMS/ALICLOUD",
        OSSHttpHeaderCryptoCEKAlg: @"AES/CTR/NoPadding"
    };
    response = [[NSHTTPURLResponse alloc] initWithURL:[NSURL URLWithString:@"http://www.aliyun.com"]
                                           statusCode:200
                                          HTTPVersion:@"HTTP/1.1"
                                         headerFields:header];
    responseParser = [[OSSCryptoHttpResponseParser alloc] initForOperationType:OSSOperationTypeGetObject
                                                           encryptionMaterials:_encryptionMaterials
                                                                  cryptoScheme:_cryptoScheme];
    responseParser.onRecieveBlock = ^(NSData * data) {
        [parseData appendData:data];
    };
    [responseParser consumeHttpResponse:response];
    partNum = ([encryptedData length] / partSize) + ([encryptedData length] % partSize > 0 ? 1 : 0);
    for (int i = 0; i < partNum; i++) {
        NSInteger length = (i == partNum - 1 && [encryptedData length] % partSize > 0) ? [encryptedData length] - (partSize * i) : partSize;
        NSData *data = [encryptedData subdataWithRange:(NSRange){i * partSize, length}];
        OSSTask *task = [responseParser consumeHttpResponseBody:data];
        [task waitUntilFinished];
        XCTAssertNotNil(task.error);
        XCTAssertTrue(task.error.code == OSSClientErrorCodeCryptoUpdate);
        XCTAssertTrue([task.error.userInfo[OSSErrorMessageTOKEN] containsString:@"Unrecognize your object key wrap algorithm"]);
    }
    
    
}

- (void)testAPI_encryptedDataError {
    NSString *path = [[NSBundle mainBundle] pathForResource:@"hasky" ofType:@"jpeg"];
    NSData *originData = [NSData dataWithContentsOfFile:path];
    __block NSMutableData *parseData = [NSMutableData new];
    NSInteger partSize = 10240;

    NSError *error = nil;
    ContentCryptoMaterial *cryptoMaterial = [[ContentCryptoMaterial alloc] initWithOperation:kCCEncrypt
                                                                                         cek:[_cryptoScheme randomGenerateKey]
                                                                                          iv:[_cryptoScheme randomGenerateIV]
                                                                                        mode:[_cryptoScheme getContentChiperMode]
                                                                                   algorithm:[_cryptoScheme getContentChiperAlgorithm]
                                                                                     padding:[_cryptoScheme getContentChiperPadding]];
    NSData *encryptedData = [self cryptoData:originData cryptoMaterial:cryptoMaterial];

    [_encryptionMaterials encrypt:cryptoMaterial error:&error];
    
    NSDictionary *header = @{
        OSSHttpHeaderCryptoKey: [cryptoMaterial.encryptedCEK base64EncodedStringWithOptions:0],
        OSSHttpHeaderCryptoIV: [cryptoMaterial.encryptedIV base64EncodedStringWithOptions:0],
        OSSHttpHeaderCryptoMatdesc: [_desc base64JsonString],
        OSSHttpHeaderContentLength: [NSString stringWithFormat:@"%ld", originData.length],
        OSSHttpHeaderCryptoWrapAlg: @"RSA/NONE/PKCS1Padding",
        OSSHttpHeaderCryptoCEKAlg: @"AES/CTR/NoPadding",
    };
    NSHTTPURLResponse *response = [[NSHTTPURLResponse alloc] initWithURL:[NSURL URLWithString:@"http://www.aliyun.com"]
                                                              statusCode:200
                                                             HTTPVersion:@"HTTP/1.1"
                                                            headerFields:header];
    OSSCryptoHttpResponseParser *responseParser = [[OSSCryptoHttpResponseParser alloc]
                                                             initForOperationType:OSSOperationTypeGetObject
                                                             encryptionMaterials:_encryptionMaterials
                                                             cryptoScheme:_cryptoScheme];
    responseParser.onRecieveBlock = ^(NSData * data) {
        [parseData appendData:data];
    };
    [responseParser consumeHttpResponse:response];
    NSInteger partNum = ([encryptedData length] / partSize) + ([encryptedData length] % partSize > 0 ? 1 : 0);
    for (int i = 0; i < partNum; i++) {
        NSInteger length = (i == partNum - 1 && [encryptedData length] % partSize > 0) ? [encryptedData length] - (partSize * i) : partSize;
        NSData *data = [originData subdataWithRange:(NSRange){i * partSize, length}];
        OSSTask *task = [responseParser consumeHttpResponseBody:data];
        [task waitUntilFinished];
//        XCTAssertNotNil(task.error);
//        XCTAssertTrue(task.error.code == OSSClientErrorCodeCryptoUpdate);
    }
}

- (NSData *)cryptoData:(NSData *)data cryptoMaterial:(ContentCryptoMaterial *)cryptoMaterial {
    Cryptor *cryptor = [[Cryptor alloc] initWithOperation:cryptoMaterial.operation
                                                      cek:cryptoMaterial.cek
                                                       iv:cryptoMaterial.iv
                                                     mode:cryptoMaterial.mode
                                                algorithm:cryptoMaterial.algorithm
                                                  padding:cryptoMaterial.padding];

    NSError *error;
    NSData *cryptedData = [cryptor cryptorUpdate:data error:&error];
    XCTAssertNil(error);
    return cryptedData;
}

@end
