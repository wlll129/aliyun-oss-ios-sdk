//
//  Crypto.h
//  AliyunOSSSDK
//
//  Created by ws on 2021/6/25.
//

#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonCrypto.h>

NS_ASSUME_NONNULL_BEGIN

@interface Cryptor : NSObject

@property (nonatomic, assign, readonly) CCOperation operation;

@property (nonatomic, copy) NSData *cek;
@property (nonatomic, copy) NSData *iv;
@property (nonatomic, assign, readonly) CCMode mode;
@property (nonatomic, assign, readonly) CCAlgorithm algorithm;
@property (nonatomic, assign, readonly) CCPadding padding;

- (instancetype)initWithOperation:(CCOperation)operation
                              cek:(NSData *)cek
                               iv:(NSData *)iv
                             mode:(CCMode)mode
                        algorithm:(CCAlgorithm)algorithm
                          padding:(CCPadding)padding;

- (NSData *)cryptorUpdate:(NSData *)content error:(NSError **)error;
- (CCCryptorStatus)resetCryptor;

@end

NS_ASSUME_NONNULL_END
