//
//  OSSCryptoHttpResponseParser.m
//  AliyunOSSSDK
//
//  Created by ws on 2021/7/6.
//

#import "OSSCryptoHttpResponseParser.h"
#import "OSSSimpleRSAEncryptionMaterials.h"
#import "Cryptor.h"
#import "ContentCryptoMaterial.h"
#import "CryptoScheme.h"

@interface OSSCryptoHttpResponseParser () {
    BOOL _needWithRange;
}

@property (nonatomic, strong) Cryptor *cryptor;
@property (nonatomic, strong) OSSSimpleRSAEncryptionMaterials *encryptionMaterials;
@property (nonatomic, strong) CryptoScheme *cryptoScheme;
@property (nonatomic, strong) NSError *error;

@end

@implementation OSSCryptoHttpResponseParser

- (instancetype)initForOperationType:(OSSOperationType)operationType
                 encryptionMaterials:(OSSSimpleRSAEncryptionMaterials *)encryptionMaterials
                        cryptoScheme:(CryptoScheme *)cryptoScheme {
    self = [super initForOperationType:operationType];
    if (self) {
        _encryptionMaterials = encryptionMaterials;
        _cryptoScheme = cryptoScheme;
    }
    return self;
}

- (void)consumeHttpResponse:(NSHTTPURLResponse *)response {
    [super consumeHttpResponse:response];
    NSDictionary *header = response.allHeaderFields;
    NSString *contentRange = header[OSSHttpHeaderContentRange];
    if (contentRange == nil && self.adjustedCryptoRange) {
        self.range.startPosition = 0;
        self.range.endPosition = [header[OSSHttpHeaderContentLength] integerValue] - 1;
        self.adjustedCryptoRange = [self.range copy];
    }
    
    NSError *error;
    ContentCryptoMaterial *contentCryptoMaterial = [self contentCryptoMaterialWithHeader:header error:&error];
    if (error) {
        self.error = error;
        return;
    }
    if (contentCryptoMaterial) {
        [_encryptionMaterials decrypt:contentCryptoMaterial error:&error];
        if (error) {
            self.error = error;
            return;
        }
        
        NSData *iv = contentCryptoMaterial.iv;
        if (self.adjustedCryptoRange) {
            int64_t skipBlock = self.adjustedCryptoRange.startPosition / BlockSize;
            iv = [CryptoScheme incrementBlocks:iv blockDelta:skipBlock error:&error];
            if (error) {
                self.error = error;
                return;
            }
        }
        
        _cryptor = [[Cryptor alloc] initWithOperation:contentCryptoMaterial.operation
                                                  cek:contentCryptoMaterial.cek
                                                   iv:iv
                                                 mode:contentCryptoMaterial.mode
                                            algorithm:contentCryptoMaterial.algorithm
                                              padding:contentCryptoMaterial.padding];
        _needWithRange = true;
    }
}

- (ContentCryptoMaterial *)contentCryptoMaterialWithHeader:(NSDictionary *)header error:(NSError **)error {
    ContentCryptoMaterial *contentCryptoMaterial = nil;
    NSString *key = header[OSSHttpHeaderCryptoKey];
    NSString *iv = header[OSSHttpHeaderCryptoIV];
    NSString *cekAlg = header[OSSHttpHeaderCryptoCEKAlg];
    NSString *wrapAlg = header[OSSHttpHeaderCryptoWrapAlg];
    NSString *descStirng = header[OSSHttpHeaderCryptoMatdesc];

    if ([key oss_isNotEmpty] && [iv oss_isNotEmpty]) {
        contentCryptoMaterial = [ContentCryptoMaterial new];
        contentCryptoMaterial.operation = kCCDecrypt;
        NSData *encryptedCEK = [[NSData alloc] initWithBase64EncodedString:key options:NSDataBase64DecodingIgnoreUnknownCharacters];
        NSData *encryptedIV = [[NSData alloc] initWithBase64EncodedString:iv options:NSDataBase64DecodingIgnoreUnknownCharacters];
        if (!encryptedCEK || !encryptedIV) {
            OSSLogError(@"key or iv is not base64 ebdcoded string. key: %@, iv: %@", key, iv);
            *error = [NSError errorWithDomain:OSSClientErrorDomain
                                         code:OSSClientErrorCodeCannotDecrypted
                                     userInfo:@{OSSErrorMessageTOKEN: [NSString stringWithFormat:@"key or iv is not base64 ebdcoded string. key: %@, iv: %@", key, iv]}];
            return nil;
        }
        contentCryptoMaterial.encryptedIV = encryptedIV;
        contentCryptoMaterial.encryptedCEK = encryptedCEK;
        NSArray<NSString *> *cekAlgs = [cekAlg componentsSeparatedByString:@"/"];
        if (cekAlgs.count != 3) {
            OSSLogError(@"cekAlgs error: %@", cekAlgs);
            *error = [NSError errorWithDomain:OSSClientErrorDomain
                                         code:OSSClientErrorCodeCannotDecrypted
                                     userInfo:@{OSSErrorMessageTOKEN: [NSString stringWithFormat:@"cek algorithm is error. cekAlg: %@", cekAlgs]}];
            return nil;
        }
        [contentCryptoMaterial setAlgorithmString:cekAlgs[0]];
        [contentCryptoMaterial setModeString:cekAlgs[1]];
        [contentCryptoMaterial setPaddingString:cekAlgs[2]];
        contentCryptoMaterial.keyWrapAlgorithm = wrapAlg;
        
        NSDictionary *desc = nil;
        if (descStirng) {
            NSData *descData = [[NSData alloc] initWithBase64EncodedString:descStirng options:NSDataBase64DecodingIgnoreUnknownCharacters];
            desc = [NSJSONSerialization JSONObjectWithData:descData options:NSJSONReadingMutableContainers error:nil];
        }
        contentCryptoMaterial.materialsDescription = desc;
    }
    return contentCryptoMaterial;
}

- (OSSTask *)handleData:(NSData *)data {
    if (self.error) {
        return [OSSTask taskWithError:self.error];
    }
    if (_cryptor) {
        NSError *error;
        NSData *result = [_cryptor cryptorUpdate:data error:&error];
        if (_needWithRange && self.range && self.adjustedCryptoRange) {
            int64_t numBytesToSkip = 0;
            if (self.adjustedCryptoRange.startPosition < self.range.startPosition) {
                numBytesToSkip = self.range.startPosition - self.adjustedCryptoRange.startPosition;
                result = [result subdataWithRange:(NSRange){numBytesToSkip, result.length - numBytesToSkip}];
            }
            _needWithRange = false;
        }
        if (error) {
            return [OSSTask taskWithError:error];
        }
        return [OSSTask taskWithResult:result];
    }
    return [OSSTask taskWithResult:data];
}

@end
