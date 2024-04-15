//
//  OSSEncryptUASettingInterceptor.m
//  AliyunOSSSDK
//
//  Created by ws on 2021/9/24.
//  Copyright © 2021 aliyun. All rights reserved.
//

#import "OSSEncryptUASettingInterceptor.h"

@interface OSSEncryptUASettingInterceptor(Encryption)

- (NSString *)getUserAgent:(NSString *)customUserAgent;

@end

@implementation OSSEncryptUASettingInterceptor

- (OSSTask *)interceptRequestMessage:(OSSAllRequestNeededMessage *)request {
    NSString * userAgent = [self getUserAgent:self.clientConfiguration.userAgentMark];
    userAgent = [userAgent stringByAppendingString:OSSUserAgentSuffix];
    [request.headerParams oss_setObject:userAgent forKey:@"User-Agent"];
    return [OSSTask taskWithResult:nil];
}

@end
