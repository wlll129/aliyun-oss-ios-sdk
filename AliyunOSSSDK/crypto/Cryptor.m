//
//  Crypto.m
//  AliyunOSSSDK
//
//  Created by ws on 2021/6/25.
//

#import "Cryptor.h"
#import "ContentCryptoMaterial.h"
#import "OSSSimpleRSAEncryptionMaterials.h"
#import "OSSLog.h"
#import "OSSDefine.h"
#import "OSSConstants.h"

#import <CommonCrypto/CommonCrypto.h>
#import <Security/Security.h>

@interface Cryptor() {
    CCCryptorRef _cryptorRef;
}

@end

@implementation Cryptor

- (instancetype)initWithOperation:(CCOperation)operation
                              cek:(NSData *)cek
                               iv:(NSData *)iv
                             mode:(CCMode)mode
                        algorithm:(CCAlgorithm)algorithm
                          padding:(CCPadding)padding {
    self = [super init];
    if (self) {
        _operation = operation;
        _cek = cek;
        _iv = iv;
        _mode = mode;
        _algorithm = algorithm;
        _padding = padding;
    }
    return self;
}

- (NSData *)cryptorUpdate:(NSData *)content error:(NSError **)error {
    if (content == nil) {
        return nil;
    }
    NSData *result = nil;

    NSUInteger dataLength = content.length;
    
    CCCryptorRef cryptorRef = _cryptorRef;
    if (!cryptorRef) {
        CCCryptorStatus status = [self resetCryptor];
        
        if (status != kCCSuccess) {
            OSSLogError(@"status: %@, operation: %@, mode: %@, algorithm: %@, padding: %@", @(status), @(self.operation), @(self.mode), @(self.algorithm), @(self.padding));
            NSString *errorMessage = [NSString stringWithFormat:@"Cryptor Create failed, code=%d", status];
            *error = [NSError errorWithDomain:OSSClientErrorDomain
                                         code:OSSClientErrorCodeCryptoCreateFailed
                                     userInfo:@{OSSErrorMessageTOKEN: errorMessage}];
            return nil;
        }

        cryptorRef = _cryptorRef;
    }
    
    size_t encryptSize = CCCryptorGetOutputLength(cryptorRef, (size_t)dataLength, false);
    void *encryptedBytes = malloc(encryptSize);
    size_t actualOutSize = 0;

    CCCryptorStatus status = CCCryptorUpdate(cryptorRef,
                                             content.bytes,
                                             dataLength,
                                             encryptedBytes,
                                             encryptSize,
                                             &actualOutSize);
    if (status != kCCSuccess) {
        OSSLogError(@"CryptorUpdateStatus:%@, content length: %@", @(status), @(dataLength));
        NSString *errorMessage = [NSString stringWithFormat:@"Cryptor Update failed, code=%d", status];
        *error = [NSError errorWithDomain:OSSClientErrorDomain
                                     code:OSSClientErrorCodeCryptoUpdate
                                 userInfo:@{OSSErrorMessageTOKEN: errorMessage}];
        return nil;
    }
    
    result = [NSData dataWithBytesNoCopy:encryptedBytes length:actualOutSize];
    return result;
}

- (CCCryptorStatus)resetCryptor {
    if (_cryptorRef) CCCryptorRelease(_cryptorRef);
    _cryptorRef = nil;
    
    CCOperation operation = self.operation;
    CCMode mode = self.mode;
    CCAlgorithm algorithm = self.algorithm;
    CCPadding padding = self.padding;
    NSData *key = self.cek;
    NSData *iv = self.iv;
    
    CCCryptorStatus status = CCCryptorCreateWithMode(operation,
                                                     mode,
                                                     algorithm,
                                                     padding,
                                                     iv.bytes,
                                                     key.bytes,
                                                     key.length,
                                                     NULL,
                                                     0,
                                                     0,
                                                     0,
                                                     &_cryptorRef);
    return status;
}

- (void)dealloc {
    if (_cryptorRef) CCCryptorRelease(_cryptorRef);
}

@end
