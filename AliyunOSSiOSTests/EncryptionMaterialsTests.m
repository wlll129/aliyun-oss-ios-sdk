//
//  EncryptionMaterialsTests.m
//  AliyunOSSiOSTests
//
//  Created by ws on 2022/1/13.
//  Copyright © 2022 aliyun. All rights reserved.
//

#import <XCTest/XCTest.h>
#import <AliyunOSSiOS/OSSSimpleRSAEncryptionMaterials.h>
#import <AliyunOSSiOS/CryptoSchemeAesCtr.h>
#import <AliyunOSSiOS/ContentCryptoMaterial.h>
#import <AliyunOSSiOS/AliyunOSSiOS.h>

@interface EncryptionMaterialsTests : XCTestCase

@end

@implementation EncryptionMaterialsTests

NSString *publicKey = @"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDIUc0RE+OF4qvJkFp/sBR4iiPy5czlKdHoOKOjhvh93aGpipoMb05+t07XSOBDJUzKGhqqVQJZEQahKXJUU0h3mxYyxRQMhhWWWdH1LH4s/GAjf4h5l+6tKxS6mnZGH4IlbJz1pvbPiZjzD6BEWtGBMAxZIjqPgSRjJpB6fBIrHQIDAQAB";
NSString *privateKey = @"-----BEGIN RSA PRIVATE KEY-----\nMIICXQIBAAKBgQDIUc0RE+OF4qvJkFp/sBR4iiPy5czlKdHoOKOjhvh93aGpipoM\nb05+t07XSOBDJUzKGhqqVQJZEQahKXJUU0h3mxYyxRQMhhWWWdH1LH4s/GAjf4h5\nl+6tKxS6mnZGH4IlbJz1pvbPiZjzD6BEWtGBMAxZIjqPgSRjJpB6fBIrHQIDAQAB\nAoGAG7kmdkyYWnkqaTTvMWi/DIehvgYLu1N0V30vOHx/e3vm2b3y3/GvnV3lLWpK\nj0BkRjwioJwvPQBcOIWx6vWzu4soHNI+e1FTJgFETfWs1+HAPgR9GptbDJGdVHc4\ni85JB+nKvbuEmm/kq0xmdQ3OeSVqZqyflmGTncCMUAK5WAECQQDpBws3eDa7w4Sr\nZyomMMiv0UW6GYWWXxnvSVzK2A55AQiSoejU2RPhZ6LJzuvr2Mez9l7mOvyiJvvd\ncaO6UawdAkEA3BFM2z82m3Q9eYPSegB2knCAuKTjZZmDLt7Ibd/z1KgdKr3tpzRt\nWNlxqS0l9bsN79IfSwGwwbFFhiQSrWRLAQJAJs9gg92GqCD5IJ7u+ytW0Ul2ZndH\ns3KlXCAIz1PKnUaZyeojYAfDcuAS0a+fxUj2gbd/uLKMTulVO11o2mgt1QJBAJBb\nUN0pNDr5HzJMxI5/K0iYP/ffQcNt1d2zCir5E0tWE/vrpq9d9rSnvqVJFnOBBn1g\nimJ7c2U7Ue3ST+YpugECQQDGSAxsLaSGFLfbBOKzM7spv3cvza7vYBksfR6xT6KR\naURh6yaGmkK8gfmrkFMtWQ0CC3fNecewUNLpScuKunCh\n-----END RSA PRIVATE KEY-----";

- (void)setUp {
    // Put setup code here. This method is called before the invocation of each test method in the class.
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
}

- (void)testAPI_SimpleRSA {
    SecKeyRef publicKeyRef = [OSSSimpleRSAEncryptionMaterials getPublicKeyFromPemPKCS8:publicKey keySizeInBits:1024 error:nil];
    SecKeyRef privateKeyRef = [OSSSimpleRSAEncryptionMaterials getPrivateKeyFromPemPKCS1:privateKey keySizeInBits:1024 error:nil];
    OSSSimpleRSAEncryptionMaterials * simple = [[OSSSimpleRSAEncryptionMaterials alloc] initWithPrivateKey:privateKeyRef publicKey:publicKeyRef desc:@{}];
    
    CryptoScheme *cryptoScheme = [[CryptoSchemeAesCtr alloc] init];
    ContentCryptoMaterial *cryptoMaterial = [[ContentCryptoMaterial alloc] initWithOperation:kCCEncrypt
                                                                                         cek:[cryptoScheme randomGenerateKey]
                                                                                          iv:[cryptoScheme randomGenerateIV]
                                                                                        mode:[cryptoScheme getContentChiperMode]
                                                                                   algorithm:[cryptoScheme getContentChiperAlgorithm]
                                                                                     padding:[cryptoScheme getContentChiperPadding]];

    NSError *error;
    [simple encrypt:cryptoMaterial error:&error];
    XCTAssertNil(error);
    ContentCryptoMaterial *encryptedMeterial = [[ContentCryptoMaterial alloc] initWithOperation:kCCEncrypt
                                                                                   encryptedCEK:cryptoMaterial.encryptedCEK
                                                                                    encryptedIV:cryptoMaterial.encryptedIV
                                                                                           mode:cryptoMaterial.mode
                                                                                      algorithm:cryptoMaterial.algorithm
                                                                                        padding:cryptoMaterial.padding];
    encryptedMeterial.keyWrapAlgorithm = cryptoMaterial.keyWrapAlgorithm;
    error = nil;
    [simple decrypt:encryptedMeterial error:&error];
    XCTAssertNil(error);

    XCTAssertTrue([cryptoMaterial.iv isEqualToData:encryptedMeterial.iv]);
    XCTAssertTrue([cryptoMaterial.cek isEqualToData:encryptedMeterial.cek]);
}

- (void)testAPI_MultipartSimpleRSA {
    SecKeyRef publicKeyRef = [OSSSimpleRSAEncryptionMaterials getPublicKeyFromPemPKCS8:publicKey keySizeInBits:1024 error:nil];
    SecKeyRef privateKeyRef = [OSSSimpleRSAEncryptionMaterials getPrivateKeyFromPemPKCS1:privateKey keySizeInBits:1024 error:nil];
    OSSSimpleRSAEncryptionMaterials * simple = [[OSSSimpleRSAEncryptionMaterials alloc] initWithPrivateKey:privateKeyRef publicKey:publicKeyRef desc:@{@"key1":@"value1"}];
    
    NSData *pubData = [NSData dataWithContentsOfFile:[[NSBundle mainBundle] pathForResource:@"public_key" ofType:@"der"]];
    NSString *privateKeyString = [NSString stringWithContentsOfURL:[[NSBundle mainBundle] URLForResource:@"private_key" withExtension:@"pem"]
                                                          encoding:NSUTF8StringEncoding
                                                             error:nil];
    publicKeyRef = [OSSSimpleRSAEncryptionMaterials getPublicKeyFromDerX509:pubData error:nil];
    privateKeyRef = [OSSSimpleRSAEncryptionMaterials getPrivateKeyFromPemPKCS1:privateKeyString keySizeInBits:1024 error:nil];
    [simple addEncryptionMaterialWithPublicKey:publicKeyRef privateKey:privateKeyRef desc:@{@"key2":@"value2"}];
    
    publicKeyRef = [OSSSimpleRSAEncryptionMaterials getPublicKeyFromDerX509:pubData error:nil];
    privateKeyRef = [OSSSimpleRSAEncryptionMaterials getPrivateKeyFromPemPKCS1:privateKeyString keySizeInBits:1024 error:nil];
    OSSSimpleRSAEncryptionMaterials * simple2 = [[OSSSimpleRSAEncryptionMaterials alloc] initWithPrivateKey:privateKeyRef publicKey:publicKeyRef desc:@{@"key2":@"value2"}];
    
    CryptoScheme *cryptoScheme = [[CryptoSchemeAesCtr alloc] init];
    ContentCryptoMaterial *cryptoMaterial = [[ContentCryptoMaterial alloc] initWithOperation:kCCEncrypt
                                                                                         cek:[cryptoScheme randomGenerateKey]
                                                                                          iv:[cryptoScheme randomGenerateIV]
                                                                                        mode:[cryptoScheme getContentChiperMode]
                                                                                   algorithm:[cryptoScheme getContentChiperAlgorithm]
                                                                                     padding:[cryptoScheme getContentChiperPadding]];

    NSError *error;
    [simple encrypt:cryptoMaterial error:&error];
    XCTAssertNil(error);
    ContentCryptoMaterial *encryptedMeterial = [[ContentCryptoMaterial alloc] initWithOperation:kCCEncrypt
                                                                                   encryptedCEK:cryptoMaterial.encryptedCEK
                                                                                    encryptedIV:cryptoMaterial.encryptedIV
                                                                                           mode:cryptoMaterial.mode
                                                                                      algorithm:cryptoMaterial.algorithm
                                                                                        padding:cryptoMaterial.padding];
    
    encryptedMeterial.keyWrapAlgorithm = cryptoMaterial.keyWrapAlgorithm;
    error = nil;
    [simple decrypt:encryptedMeterial error:&error];
    XCTAssertNil(error);

    XCTAssertTrue([cryptoMaterial.iv isEqualToData:encryptedMeterial.iv]);
    XCTAssertTrue([cryptoMaterial.cek isEqualToData:encryptedMeterial.cek]);
    
    error = nil;
    [simple2 encrypt:cryptoMaterial error:&error];
    XCTAssertNil(error);
    encryptedMeterial = [[ContentCryptoMaterial alloc] initWithOperation:kCCEncrypt
                                                            encryptedCEK:cryptoMaterial.encryptedCEK
                                                             encryptedIV:cryptoMaterial.encryptedIV
                                                                    mode:cryptoMaterial.mode
                                                               algorithm:cryptoMaterial.algorithm
                                                                 padding:cryptoMaterial.padding];
    encryptedMeterial.keyWrapAlgorithm = cryptoMaterial.keyWrapAlgorithm;
    encryptedMeterial.materialsDescription = cryptoMaterial.materialsDescription;
    error = nil;
    [simple decrypt:encryptedMeterial error:&error];
    XCTAssertNil(error);

    XCTAssertTrue([cryptoMaterial.iv isEqualToData:encryptedMeterial.iv]);
    XCTAssertTrue([cryptoMaterial.cek isEqualToData:encryptedMeterial.cek]);
}

- (void)testAPI_getPrivateKeyFromPemPKCS1 {
    NSError *error = nil;
    SecKeyRef privateKeyRef = [OSSSimpleRSAEncryptionMaterials getPrivateKeyFromPemPKCS1:privateKey keySizeInBits:1024 error:&error];
    XCTAssertNil(error);
    XCTAssertTrue(privateKeyRef != nil);
    
    error = nil;
    privateKeyRef = [OSSSimpleRSAEncryptionMaterials getPrivateKeyFromPemPKCS1:@"aaa" keySizeInBits:1024 error:&error];
    XCTAssertTrue(error.code == OSSClientErrorCodeCryptoUpdate);
    XCTAssertTrue(privateKeyRef == nil);

}

- (void)testAPI_NullSimpleRSA {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wnonnull"
    OSSSimpleRSAEncryptionMaterials * simple = [[OSSSimpleRSAEncryptionMaterials alloc] initWithPrivateKey:nil publicKey:nil desc:@{}];
#pragma clang diagnostic pop

    CryptoScheme *cryptoScheme = [[CryptoSchemeAesCtr alloc] init];
    ContentCryptoMaterial *cryptoMaterial = [[ContentCryptoMaterial alloc] initWithOperation:kCCEncrypt
                                                                                         cek:[cryptoScheme randomGenerateKey]
                                                                                          iv:[cryptoScheme randomGenerateIV]
                                                                                        mode:[cryptoScheme getContentChiperMode]
                                                                                   algorithm:[cryptoScheme getContentChiperAlgorithm]
                                                                                     padding:[cryptoScheme getContentChiperPadding]];

    NSError *error;
    [simple encrypt:cryptoMaterial error:&error];
    XCTAssertNotNil(error);
    XCTAssertTrue(error.code == OSSClientErrorCodeCryptoUpdate);
    XCTAssertTrue([error.userInfo[OSSErrorMessageTOKEN] isEqualToString:@"publicKey is nil!"]);
    ContentCryptoMaterial *encryptedMeterial = [[ContentCryptoMaterial alloc] initWithOperation:kCCEncrypt
                                                                                   encryptedCEK:cryptoMaterial.encryptedCEK
                                                                                    encryptedIV:cryptoMaterial.encryptedIV
                                                                                           mode:cryptoMaterial.mode
                                                                                      algorithm:cryptoMaterial.algorithm
                                                                                        padding:cryptoMaterial.padding];
    error = nil;
    [simple decrypt:encryptedMeterial error:&error];
    XCTAssertNotNil(error);
    XCTAssertTrue(error.code == OSSClientErrorCodeCryptoUpdate);
    XCTAssertTrue([error.userInfo[OSSErrorMessageTOKEN] containsString:@"Unrecognize your object key wrap algorithm"]);
    
    
    encryptedMeterial.keyWrapAlgorithm = @"RSA/NONE/PKCS1Padding";
    error = nil;
    [simple decrypt:encryptedMeterial error:&error];
    XCTAssertNotNil(error);
    XCTAssertTrue(error.code == OSSClientErrorCodeCryptoUpdate);
    XCTAssertTrue([error.userInfo[OSSErrorMessageTOKEN] containsString:@"privateKey is nil!"]);
    
    
    SecKeyRef publicKeyRef = [OSSSimpleRSAEncryptionMaterials getPublicKeyFromPemPKCS8:publicKey keySizeInBits:1024 error:nil];
    SecKeyRef privateKeyRef = [OSSSimpleRSAEncryptionMaterials getPrivateKeyFromPemPKCS1:privateKey keySizeInBits:1024 error:nil];
    simple = [[OSSSimpleRSAEncryptionMaterials alloc] initWithPrivateKey:privateKeyRef publicKey:publicKeyRef desc:@{}];
    
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wnonnull"
    cryptoMaterial = [[ContentCryptoMaterial alloc] initWithOperation:kCCEncrypt
                                                                  cek:nil
                                                                   iv:[cryptoScheme randomGenerateIV]
                                                                 mode:[cryptoScheme getContentChiperMode]
                                                            algorithm:[cryptoScheme getContentChiperAlgorithm]
                                                              padding:[cryptoScheme getContentChiperPadding]];
#pragma clang diagnostic pop
    error = nil;
    [simple encrypt:cryptoMaterial error:&error];
    XCTAssertNotNil(error);
    XCTAssertTrue([error.userInfo[OSSErrorMessageTOKEN] isEqualToString:@"cek is nil!"]);
    
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wnonnull"
    cryptoMaterial = [[ContentCryptoMaterial alloc] initWithOperation:kCCEncrypt
                                                                  cek:[cryptoScheme randomGenerateKey]
                                                                   iv:nil
                                                                 mode:[cryptoScheme getContentChiperMode]
                                                            algorithm:[cryptoScheme getContentChiperAlgorithm]
                                                              padding:[cryptoScheme getContentChiperPadding]];
#pragma clang diagnostic pop
    error = nil;
    [simple encrypt:cryptoMaterial error:&error];
    XCTAssertNotNil(error);
    XCTAssertTrue([error.userInfo[OSSErrorMessageTOKEN] isEqualToString:@"iv is nil!"]);
}

- (void)testAPI_encryptedError {
    CryptoScheme *cryptoScheme = [[CryptoSchemeAesCtr alloc] init];
    ContentCryptoMaterial *cryptoMaterial = [[ContentCryptoMaterial alloc] initWithOperation:kCCEncrypt
                                                                                         cek:[cryptoScheme randomGenerateKey]
                                                                                          iv:[cryptoScheme randomGenerateIV]
                                                                                        mode:[cryptoScheme getContentChiperMode]
                                                                                   algorithm:[cryptoScheme getContentChiperAlgorithm]
                                                                                     padding:[cryptoScheme getContentChiperPadding]];
    SecKeyRef publicKeyRef = [OSSSimpleRSAEncryptionMaterials getPublicKeyFromPemPKCS8:publicKey keySizeInBits:1024 error:nil];
    SecKeyRef privateKeyRef = [OSSSimpleRSAEncryptionMaterials getPrivateKeyFromPemPKCS1:privateKey keySizeInBits:1024 error:nil];
    OSSSimpleRSAEncryptionMaterials * simple = [[OSSSimpleRSAEncryptionMaterials alloc] initWithPrivateKey:privateKeyRef publicKey:publicKeyRef desc:@{}];
    
    NSError *error = nil;
    [simple encrypt:cryptoMaterial error:&error];
    
    
    
}

@end
