//
//  Auth.h
//  CustomAuth
//
//  Created by wangyanqing on 14-4-28.
//  Copyright (c) 2014年 twob. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface Auth : NSObject


-(id)initWithRegion:(NSString *)region;
-(id)initWithSerialCode:(NSString *)serial secretCode:(Byte [])secret;
-(id)initWithRestoreCode:(NSString *)restoreCode SerialCode:(NSString *)serial;



-(NSString *)result;

@end
