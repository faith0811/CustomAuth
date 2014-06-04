//
//  HttpPostOperator.h
//  CustomAuth
//
//  Created by wangyanqing on 14-5-7.
//  Copyright (c) 2014年 twob. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface HttpPostOperator : NSObject

-(NSData *)postData:(NSData *)origData withUrl:(NSString *)urlString;

@end
