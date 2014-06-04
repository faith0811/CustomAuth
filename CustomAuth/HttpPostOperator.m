//
//  HttpPostOperator.m
//  CustomAuth
//
//  Created by wangyanqing on 14-5-7.
//  Copyright (c) 2014年 twob. All rights reserved.
//

#import "HttpPostOperator.h"

@implementation HttpPostOperator

-(NSData *)postData:(NSData *)origData withUrl:(NSString *)urlString{
    NSURL *url = [NSURL URLWithString:urlString];
    NSMutableURLRequest *urlRequest = [[NSMutableURLRequest alloc]initWithURL:url cachePolicy:NSURLRequestReloadIgnoringLocalCacheData timeoutInterval:30];
    [urlRequest setHTTPMethod:@"POST"];
    if (origData==nil) {
        [urlRequest setHTTPMethod:@"GET"];
    }
    NSString *contentType = @"application/octet-stream";
    [urlRequest setValue:contentType forHTTPHeaderField:@"Content-Type"];
    [urlRequest setValue:[NSString stringWithFormat:@"%lu",(unsigned long)[origData length]] forHTTPHeaderField:@"Content-Length"];
    NSData *body = origData;
    [urlRequest setHTTPBody:body];
    //will be use gcd on viewcontroller.
    NSData *receivedData = [NSURLConnection sendSynchronousRequest:urlRequest returningResponse:nil error:nil];
    return receivedData;
}

@end
