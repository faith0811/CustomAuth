//
//  RSAEncypt.h
//  CustomAuth
//
//  Created by wangyanqing on 14-4-28.
//  Copyright (c) 2014年 twob. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface RSAEncypt : NSObject

+(NSData *)encryptString:(id)string withKey:(NSString *)keyString identify:(NSString *)identify;

@end
