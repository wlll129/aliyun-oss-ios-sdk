//
//  OSSSimpleRSAEncryptionMaterials.m
//  AliyunOSSSDK
//
//  Created by ws on 2021/6/23.
//

#import "OSSSimpleRSAEncryptionMaterials.h"
#import "ContentCryptoMaterial.h"

#import <Security/Security.h>
#import <CommonCrypto/CommonCrypto.h>
#import <AliyunOSSiOS/AliyunOSSiOS.h>

@interface OSSSimpleRSAEncryptionMaterials()

@property (nonatomic, strong) NSMutableDictionary<NSDictionary<NSString *, NSString *> *, KeyPair *> *keyPairDescMaterials;

@end

@implementation OSSSimpleRSAEncryptionMaterials

NSString *keyWrapAlgorithm = @"RSA/NONE/PKCS1Padding";

- (instancetype)initWithPrivateKey:(SecKeyRef)privateKey
                         publicKey:(SecKeyRef)publicKey
                              desc:(nonnull NSDictionary<NSString *, NSString *> *)desc{
    self = [super init];
    if (self) {
        _keypair = [[KeyPair alloc] initWithPrivateKey:privateKey
                                             publicKey:publicKey
                                                  desc:desc];
        if (!desc) {
            desc = @{};
        }
        [self.keyPairDescMaterials setObject:_keypair forKey:desc];
    }
    return self;
}

+ (SecKeyRef)getPrivateKeyFromPemPKCS1:(NSString *)privateKey keySizeInBits:(NSInteger)size error:(NSError **)error {
    SecKeyRef privateKeyRef = NULL;
    
    privateKey = [privateKey stringByReplacingOccurrencesOfString:@"-----BEGIN PRIVATE KEY-----" withString:@""];
    privateKey = [privateKey stringByReplacingOccurrencesOfString:@"-----BEGIN RSA PRIVATE KEY-----" withString:@""];
    privateKey = [privateKey stringByReplacingOccurrencesOfString:@"-----END PRIVATE KEY-----" withString:@""];
    privateKey = [privateKey stringByReplacingOccurrencesOfString:@"-----END RSA PRIVATE KEY-----" withString:@""];
    privateKey = [privateKey stringByReplacingOccurrencesOfString:@"\n" withString:@""];
    privateKey = [privateKey stringByReplacingOccurrencesOfString:@"\r" withString:@""];
    privateKey = [privateKey stringByReplacingOccurrencesOfString:@" " withString:@""];
    
    
    NSData *data = [[NSData alloc] initWithBase64EncodedString:privateKey options:NSDataBase64DecodingIgnoreUnknownCharacters];
    NSMutableDictionary *attributes = @{
        (__bridge id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeRSA,
        (__bridge id)kSecAttrKeyClass: (__bridge id)kSecAttrKeyClassPrivate,
    }.mutableCopy;
    if (size != 0) {
        attributes[(__bridge id)kSecAttrKeySizeInBits] = @(size);
    }
    CFErrorRef errorRef = nil;
    
    privateKeyRef = SecKeyCreateWithData((__bridge CFDataRef)data,
                                         (__bridge CFDictionaryRef)attributes,
                                         &errorRef);
    if (errorRef) {
        *error = [NSError errorWithDomain:OSSClientErrorDomain
                                     code:OSSClientErrorCodeCryptoUpdate
                                 userInfo:@{OSSErrorMessageTOKEN: (__bridge NSString*)CFErrorCopyDescription(errorRef)}];
        return nil;
    }
    
    return privateKeyRef;
}

+ (SecKeyRef)getPublicKeyFromPemPKCS8:(NSString *)privateKey keySizeInBits:(NSInteger)size error:(NSError **)error {
    SecKeyRef privateKeyRef = NULL;
    
    privateKey = [privateKey stringByReplacingOccurrencesOfString:@"-----BEGIN PRIVATE KEY-----" withString:@""];
    privateKey = [privateKey stringByReplacingOccurrencesOfString:@"-----BEGIN RSA PRIVATE KEY-----" withString:@""];
    privateKey = [privateKey stringByReplacingOccurrencesOfString:@"-----END PRIVATE KEY-----" withString:@""];
    privateKey = [privateKey stringByReplacingOccurrencesOfString:@"-----END RSA PRIVATE KEY-----" withString:@""];
    privateKey = [privateKey stringByReplacingOccurrencesOfString:@"\n" withString:@""];
    privateKey = [privateKey stringByReplacingOccurrencesOfString:@"\r" withString:@""];
    privateKey = [privateKey stringByReplacingOccurrencesOfString:@" " withString:@""];
    
    
    NSData *data = [[NSData alloc] initWithBase64EncodedString:privateKey options:NSDataBase64DecodingIgnoreUnknownCharacters];
    NSMutableDictionary *attributes = @{
        (__bridge id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeRSA,
        (__bridge id)kSecAttrKeyClass: (__bridge id)kSecAttrKeyClassPublic,
    }.mutableCopy;
    if (size != 0) {
        attributes[(__bridge id)kSecAttrKeySizeInBits] = @(size);
    }
    CFErrorRef errorRef = nil;
    
    privateKeyRef = SecKeyCreateWithData((__bridge CFDataRef)data,
                                         (__bridge CFDictionaryRef)attributes,
                                         &errorRef);
    if (errorRef) {
        *error = [NSError errorWithDomain:OSSClientErrorDomain
                                     code:OSSClientErrorCodeCryptoUpdate
                                 userInfo:@{OSSErrorMessageTOKEN: (__bridge NSString*)CFErrorCopyDescription(errorRef)}];
        return nil;
    }
    
    return privateKeyRef;
}

+ (SecKeyRef)getPublicKeyFromDerX509:(NSData *)publicKey error:(NSError **)error  {
    SecKeyRef publicKeyRef = NULL;
    
    SecCertificateRef certificateRef = SecCertificateCreateWithData(nil, (__bridge CFDataRef)publicKey);
    if (!certificateRef) {
        return nil;
    }
    SecTrustRef trustRef;
    SecPolicyRef policyRef = SecPolicyCreateBasicX509();
    OSStatus status = SecTrustCreateWithCertificates(certificateRef,
                                                     policyRef,
                                                     &trustRef);
    if (status != errSecSuccess) {
        return nil;
    }
    
    SecTrustSetAnchorCertificates(trustRef, (__bridge CFArrayRef)@[(__bridge_transfer id)certificateRef]);
    
    if (@available(iOS 12.0, *)) {
        CFErrorRef errorRef = nil;
        if (SecTrustEvaluateWithError(trustRef, &errorRef)) {
            publicKeyRef = SecTrustCopyPublicKey(trustRef);
        } else if (errorRef) {
            *error = [NSError errorWithDomain:OSSClientErrorDomain
                                         code:OSSClientErrorCodeCryptoUpdate
                                     userInfo:@{OSSErrorMessageTOKEN: (__bridge NSString*)CFErrorCopyDescription(errorRef)}];
            return nil;
        }
    } else {
        SecTrustResultType result;
        OSStatus osstatus = SecTrustEvaluate(trustRef, &result);
        if (osstatus == errSecSuccess) {
            publicKeyRef = SecTrustCopyPublicKey(trustRef);
        } else {
            *error = [NSError errorWithDomain:OSSClientErrorDomain
                                         code:OSSClientErrorCodeCryptoUpdate
                                     userInfo:@{OSSErrorMessageTOKEN: [NSString stringWithFormat:@"Security Error Codes: %d", (int)osstatus]}];
            return nil;
        }
    }
    
    
    
    if (policyRef) CFRelease(policyRef);
    if (certificateRef) CFRelease(certificateRef);
    return publicKeyRef;
}

- (void)addEncryptionMaterialWithPublicKey:(SecKeyRef)publicKeyRef
                                privateKey:(SecKeyRef)privateKeyRef
                                      desc:(NSDictionary<NSString *, NSString *> *)desc {
    KeyPair *keyPair = [[KeyPair alloc] initWithPrivateKey:privateKeyRef
                                                 publicKey:publicKeyRef
                                                      desc:desc];
    if (!desc) {
        desc = @{};
    }
    [self.keyPairDescMaterials setObject:keyPair forKey:desc];
}

- (KeyPair *)findEncryptionMaterialsByDescription:(NSDictionary<NSString *, NSString *> *)desc {
    if (!desc) {
        return nil;
    }
    __block KeyPair *keyPair = nil;
    [self.keyPairDescMaterials enumerateKeysAndObjectsUsingBlock:^(id  _Nonnull key, id  _Nonnull obj, BOOL * _Nonnull stop) {
        if ([key isEqualToDictionary:desc]) {
            keyPair = obj;
            *stop = true;
        }
    }];
    return keyPair;
}

- (void)decrypt:(nonnull ContentCryptoMaterial *)contentCryptoMaterial
          error:(NSError **)error {
    if (![contentCryptoMaterial.keyWrapAlgorithm isEqualToString:keyWrapAlgorithm]) {
        *error = [NSError errorWithDomain:OSSClientErrorDomain
                                     code:OSSClientErrorCodeCryptoUpdate
                                 userInfo:@{OSSErrorMessageTOKEN: [NSString stringWithFormat:@"Unrecognize your object key wrap algorithm: %@", contentCryptoMaterial.keyWrapAlgorithm]}];
        return;
    }
    KeyPair *keyPair = [self findEncryptionMaterialsByDescription:contentCryptoMaterial.materialsDescription];
    if (!keyPair) {
        keyPair = self.keyPairDescMaterials.allValues.firstObject;
    }
    SecKeyRef privateKey = keyPair.privateKey;
    if (!privateKey) {
        *error = [NSError errorWithDomain:OSSClientErrorDomain
                                     code:OSSClientErrorCodeCryptoUpdate
                                 userInfo:@{OSSErrorMessageTOKEN: @"privateKey is nil!"}];
        return;
    }
    SecKeyAlgorithm algorithm = kSecKeyAlgorithmRSAEncryptionPKCS1;
    
    BOOL canDecryptCEK = ([contentCryptoMaterial.encryptedCEK length] == SecKeyGetBlockSize(privateKey));
    BOOL canDecryptIV = ([contentCryptoMaterial.encryptedIV length] == SecKeyGetBlockSize(privateKey));
    if (!canDecryptCEK || !canDecryptIV) {
        *error = [NSError errorWithDomain:OSSClientErrorDomain
                                     code:OSSClientErrorCodeCryptoUpdate
                                 userInfo:@{OSSErrorMessageTOKEN: @"Unable to decrypt content secured key and iv."}];
        return;
    }
    
    CFErrorRef decryptedCEKErrorRef = nil;
    CFDataRef cek = SecKeyCreateDecryptedData(privateKey,
                                              algorithm,
                                              (__bridge CFDataRef)contentCryptoMaterial.encryptedCEK,
                                              &decryptedCEKErrorRef);
    
    CFErrorRef decryptedIVErrorRef = nil;
    CFDataRef iv = SecKeyCreateDecryptedData(privateKey,
                                             algorithm,
                                             (__bridge CFDataRef)contentCryptoMaterial.encryptedIV,
                                             &decryptedIVErrorRef);
    
    if (!cek || !iv) {
        NSString *decryptedCEKErrorMessage = decryptedCEKErrorRef ? ((__bridge NSError *)(decryptedCEKErrorRef)).description : @"";
        NSString *decryptedIVErrorMessage = decryptedIVErrorRef ? ((__bridge NSError *)(decryptedIVErrorRef)).description : @"";
        
        NSString *message = [NSString stringWithFormat:@"Unable to decrypt content secured key and iv.Please check your materails description. %@ %@", decryptedCEKErrorMessage, decryptedIVErrorMessage];
        *error = [NSError errorWithDomain:OSSClientErrorDomain
                                     code:OSSClientErrorCodeCryptoUpdate
                                 userInfo:@{OSSErrorMessageTOKEN: message}];
        OSSLogError(@"encrypt error: %@", message);
        
        if (decryptedCEKErrorRef) {
            CFRelease(decryptedCEKErrorRef);
        }
        if (decryptedIVErrorRef) {
            CFRelease(decryptedIVErrorRef);
        }
        return;
    }
    
    contentCryptoMaterial.cek = (__bridge NSData * _Nonnull)(cek);
    contentCryptoMaterial.iv = (__bridge NSData * _Nonnull)(iv);
}

- (void)encrypt:(nonnull ContentCryptoMaterial *)contentCryptoMaterial
          error:(NSError **)error {
    SecKeyRef publicKey = _keypair.publicKey;
    if (!publicKey) {
        *error = [NSError errorWithDomain:OSSClientErrorDomain
                                     code:OSSClientErrorCodeCryptoUpdate
                                 userInfo:@{OSSErrorMessageTOKEN: @"publicKey is nil!"}];
        return;
    }
    if (!contentCryptoMaterial.cek) {
        *error = [NSError errorWithDomain:OSSClientErrorDomain
                                     code:OSSClientErrorCodeCryptoUpdate
                                 userInfo:@{OSSErrorMessageTOKEN: @"cek is nil!"}];
        return;
    }
    if (!contentCryptoMaterial.iv) {
        *error = [NSError errorWithDomain:OSSClientErrorDomain
                                     code:OSSClientErrorCodeCryptoUpdate
                                 userInfo:@{OSSErrorMessageTOKEN: @"iv is nil!"}];
        return;
    }
    SecKeyAlgorithm algorithm = kSecKeyAlgorithmRSAEncryptionPKCS1;
    
    
    CFErrorRef encryptedCEKErrorRef = nil;
    CFDataRef encryptedCEK = SecKeyCreateEncryptedData(publicKey,
                                                       algorithm,
                                                       (__bridge CFDataRef)contentCryptoMaterial.cek,
                                                       &encryptedCEKErrorRef);
    
    CFErrorRef encryptedIVErrorRef = nil;
    CFDataRef encryptedIV = SecKeyCreateEncryptedData(publicKey,
                                                      algorithm,
                                                      (__bridge CFDataRef)contentCryptoMaterial.iv,
                                                      &encryptedIVErrorRef);
    
    if (!encryptedCEK || !encryptedIV) {
        NSString *encryptedCEKErrorMessage = encryptedCEKErrorRef ? ((__bridge NSError *)(encryptedCEKErrorRef)).description : @"";
        NSString *encryptedIVErrorMessage = encryptedIVErrorRef ? ((__bridge NSError *)(encryptedIVErrorRef)).description : @"";
        
        NSString *message = [NSString stringWithFormat:@"Unable to encrypt content secured key and iv.Please check your materails description. %@ %@", encryptedCEKErrorMessage, encryptedIVErrorMessage];
        *error = [NSError errorWithDomain:OSSClientErrorDomain
                                     code:OSSClientErrorCodeCryptoUpdate
                                 userInfo:@{OSSErrorMessageTOKEN: message}];
        OSSLogError(@"encrypt error: %@", message);
        
        if (encryptedCEKErrorRef) {
            CFRelease(encryptedCEKErrorRef);
        }
        if (encryptedIVErrorRef) {
            CFRelease(encryptedIVErrorRef);
        }
        return;
    }
    
    contentCryptoMaterial.encryptedCEK = (__bridge NSData * _Nonnull)(encryptedCEK);
    contentCryptoMaterial.encryptedIV = (__bridge NSData * _Nonnull)(encryptedIV);
    contentCryptoMaterial.materialsDescription = _keypair.desc;
    contentCryptoMaterial.keyWrapAlgorithm = keyWrapAlgorithm;
}

- (NSMutableDictionary<NSDictionary<NSString *, NSString *> *,KeyPair *> *)keyPairDescMaterials {
    if (!_keyPairDescMaterials) {
        _keyPairDescMaterials = [NSMutableDictionary dictionary];
    }
    return _keyPairDescMaterials;
}

@end

@implementation KeyPair

- (instancetype)initWithPrivateKey:(nonnull SecKeyRef)privateKey
                         publicKey:(nonnull SecKeyRef)publicKey
                              desc:(nonnull NSDictionary<NSString *, NSString *> *)desc
{
    self = [super init];
    if (self) {
        _privateKey = privateKey;
        _publicKey = publicKey;
        _desc = desc;
    }
    return self;
}

- (void)dealloc {
    if (_privateKey) CFRelease(_privateKey);
    if (_publicKey) CFRelease(_publicKey);
}

@end
