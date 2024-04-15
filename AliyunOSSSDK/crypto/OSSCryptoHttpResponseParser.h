//
//  OSSCryptoHttpResponseParser.h
//  AliyunOSSSDK
//
//  Created by ws on 2021/7/6.
//

#import <AliyunOSSiOS/AliyunOSSiOS.h>

NS_ASSUME_NONNULL_BEGIN

@class OSSSimpleRSAEncryptionMaterials;
@class CryptoScheme;

@interface OSSCryptoHttpResponseParser : OSSHttpResponseParser

@property (nonatomic, strong) OSSRange *range;
@property (nonatomic, strong) OSSRange *adjustedCryptoRange;

- (instancetype)initForOperationType:(OSSOperationType)operationType
                 encryptionMaterials:(OSSSimpleRSAEncryptionMaterials *)encryptionMaterials
                        cryptoScheme:(CryptoScheme *)cryptoScheme;

@end

NS_ASSUME_NONNULL_END
