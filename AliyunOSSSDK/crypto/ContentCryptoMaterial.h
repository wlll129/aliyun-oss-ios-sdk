//
//  ContentCryptoMaterial.h
//  AliyunOSSSDK
//
//  Created by ws on 2021/6/28.
//

#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonCrypto.h>


NS_ASSUME_NONNULL_BEGIN

@interface ContentCryptoMaterial : NSObject <NSCoding>

- (instancetype)initWithOperation:(CCOperation)operation
                              cek:(NSData *)cek
                               iv:(NSData *)iv
                             mode:(CCMode)mode
                        algorithm:(CCAlgorithm)algorithm
                          padding:(CCPadding)padding;

- (instancetype)initWithOperation:(CCOperation)operation
                     encryptedCEK:(NSData *)encryptedCEK
                      encryptedIV:(NSData *)encryptedIV
                             mode:(CCMode)mode
                        algorithm:(CCAlgorithm)algorithm
                          padding:(CCPadding)padding;

@property (nonatomic, assign) CCOperation operation;

@property (nonatomic, copy) NSData *cek;
@property (nonatomic, copy) NSData *iv;

@property (nonatomic, assign) CCMode mode;
@property (nonatomic, assign) CCAlgorithm algorithm;
@property (nonatomic, assign) CCPadding padding;
@property (nonatomic, copy) NSString *keyWrapAlgorithm;

@property (nonatomic, copy) NSData *encryptedIV;
@property (nonatomic, copy) NSData *encryptedCEK;

@property (nonatomic, copy) NSDictionary<NSString *, NSString *> *materialsDescription;

- (NSString *)cekAlg;
- (NSString *)algorithmString;
- (void)setAlgorithmString:(NSString *)algorithmString;
- (NSString *)paddingString;
- (void)setPaddingString:(NSString *)paddingString;
- (NSString *)modeString;
- (void)setModeString:(NSString *)modeString;

@end

NS_ASSUME_NONNULL_END
