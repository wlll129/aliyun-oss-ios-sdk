//
//  OSSSimpleRSAEncryptionMaterials.h
//  AliyunOSSSDK
//
//  Created by ws on 2021/6/23.
//

#import <Foundation/Foundation.h>
#import "EncryptionMaterials.h"

NS_ASSUME_NONNULL_BEGIN

@class ContentCryptoMaterial;

@interface KeyPair : NSObject

@property (nonatomic, readonly) SecKeyRef privateKey;
@property (nonatomic, readonly) SecKeyRef publicKey;
@property (nonatomic, copy, readonly) NSDictionary<NSString *, NSString *> *desc;

- (instancetype)initWithPrivateKey:(nonnull SecKeyRef)privateKey
                         publicKey:(nonnull SecKeyRef)publicKey
                              desc:(nonnull NSDictionary<NSString *, NSString *> *)desc;

@end

@interface OSSSimpleRSAEncryptionMaterials : NSObject<EncryptionMaterials>

+ (SecKeyRef)getPrivateKeyFromPemPKCS1:(NSString *)privateKey keySizeInBits:(NSInteger)size error:(NSError **)error ;
+ (SecKeyRef)getPublicKeyFromDerX509:(NSData *)publicKey error:(NSError **)error ;
+ (SecKeyRef)getPublicKeyFromPemPKCS8:(NSString *)privateKey keySizeInBits:(NSInteger)size error:(NSError **)error ;

@property (nonatomic, strong, readonly) KeyPair *keypair;

- (instancetype)initWithPrivateKey:(SecKeyRef)privateKey
                         publicKey:(SecKeyRef)publicKey
                              desc:(NSDictionary<NSString *, NSString *> *)desc;

- (void)addEncryptionMaterialWithPublicKey:(SecKeyRef)publicKey
                                privateKey:(SecKeyRef)privateKey
                                      desc:(NSDictionary<NSString *, NSString *> *)desc;
@end

NS_ASSUME_NONNULL_END
