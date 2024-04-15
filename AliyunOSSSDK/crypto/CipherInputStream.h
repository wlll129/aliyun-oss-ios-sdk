//
//  InputStream.h
//  AliyunOSSSDK
//
//  Created by ws on 2021/6/30.
//

#import <Foundation/Foundation.h>

@class Cryptor;

NS_ASSUME_NONNULL_BEGIN

@interface CipherInputStream : NSInputStream

- (instancetype)initWithURL:(NSURL *)url cryptor:(Cryptor *)cryptor;
- (instancetype)initWithData:(NSData *)data cryptor:(Cryptor *)cryptor;

- (void)reset;

@end

NS_ASSUME_NONNULL_END
