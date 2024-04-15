//
//  InputStream.m
//  AliyunOSSSDK
//
//  Created by ws on 2021/6/30.
//

#import "CipherInputStream.h"
#import "Cryptor.h"

@interface NSStream ()
@property (readwrite) NSStreamStatus streamStatus;
@property (readwrite, copy) NSError *streamError;
@end

@interface CipherInputStream()

@property (nonatomic, strong) Cryptor *cryptor;

@property (readwrite) NSInputStream *inputStream;

@property (nonatomic, strong) NSURL *url;
@property (nonatomic, strong) NSData *data;

@end

@implementation CipherInputStream

@synthesize streamStatus;
@synthesize streamError;

- (instancetype)initWithURL:(NSURL *)url cryptor:(Cryptor *)cryptor {
    self = [super init];
    if (self) {
        _cryptor = cryptor;
        _url = url;
        _inputStream = [[NSInputStream alloc] initWithURL:url];
    }
    return self;
}

- (instancetype)initWithData:(NSData *)data cryptor:(Cryptor *)cryptor {
    self = [super init];
    if (self) {
        _cryptor = cryptor;
        _data = data;
        _inputStream = [[NSInputStream alloc] initWithData:data];
    }
    return self;
}

- (NSInteger)read:(uint8_t *)buffer maxLength:(NSUInteger)len {
    uint8_t *bufin = (uint8_t *)malloc(len);
    NSInteger readLen = [self.inputStream read:bufin maxLength:len];
    
    NSData *data = [NSData dataWithBytes:bufin length:readLen];
    free(bufin);

    NSError *error;
    NSData *cryptedData = [_cryptor cryptorUpdate:data error:&error];
    if (error) {
        self.streamError = error;
        return -1;
    }
    memcpy(buffer, cryptedData.bytes, readLen);
        
    return readLen;
}

- (BOOL)getBuffer:(uint8_t * _Nullable *)buffer length:(NSUInteger *)len {
    uint8_t *bufin = nil;
    BOOL read = [self.inputStream getBuffer:&bufin length:len];
    
    NSData *data = [NSData dataWithBytes:bufin length:*len];
    free(bufin);

    NSError *error;
    NSData *cryptedData = [_cryptor cryptorUpdate:data error:&error];
    if (error) {
        self.streamError = error;
        return false;
    }
    memcpy(buffer, cryptedData.bytes, *len);
        
    return read;
}

- (BOOL)hasBytesAvailable {
    return [self.inputStream hasBytesAvailable];
}

- (void)open {
    [self.inputStream open];
}

- (void)close {
    [self.inputStream close];
}

- (void)setDelegate:(id<NSStreamDelegate>)delegate {
    [self.inputStream setDelegate:delegate];
}

- (id<NSStreamDelegate>)delegate {
    return [self.inputStream delegate];
}

- (void)scheduleInRunLoop:(NSRunLoop *)aRunLoop forMode:(NSRunLoopMode)mode {
    [self.inputStream scheduleInRunLoop:aRunLoop forMode:mode];
}

- (void)removeFromRunLoop:(NSRunLoop *)aRunLoop forMode:(NSRunLoopMode)mode {
    [self.inputStream removeFromRunLoop:aRunLoop forMode:mode];
}

- (id)propertyForKey:(NSStreamPropertyKey)key {
    return [self.inputStream propertyForKey:key];
}

- (BOOL)setProperty:(id)property forKey:(NSStreamPropertyKey)key {
    return [self.inputStream setProperty:property forKey:key];
}

- (NSStreamStatus)streamStatus {
    return [self.inputStream streamStatus];
}

- (void)reset {
    NSInputStream *inputStream;
    if (self.url) {
        inputStream = [[NSInputStream alloc] initWithURL:self.url];
    } else if (self.data) {
        inputStream = [[NSInputStream alloc] initWithData:self.data];
    }
    self.inputStream = inputStream;
}

@end
