//
//  Auth.m
//  CustomAuth
//
//  Created by wangyanqing on 14-4-28.
//  Copyright (c) 2014年 twob. All rights reserved.
//

#import "Auth.h"
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonHMAC.h>
#import "RSAEncypt.h"
#import "HttpPostOperator.h"

#pragma mark - const

//this is Blizzard Auth Public Key in Base64 Encrypted version.
NSString const *kblizzardAuthPublicKey = @"MIGIAoGBAJVeS9mJ85F9LxVUSn4FBOude7Zrb4ov5HDkU8d5IA5eOtLkOgLQbErb2NMo8aQmuDZY6Iv9lJsq9OrzAFRnOhQZolD6TMEnjRKFW1slgY0WLG5u4qtKNQ1AHXj23bmXEecmJrSL2LWwt/Os+eo8ngAF/uWeGRNs23yD8quLCiqZAgIBAQ==";

NSString const *kenrollMentUrl = @"/enrollment/enroll.htm";
NSString const *kinitRestoreUrl = @"/enrollment/initiatePaperRestore.htm";
NSString const *kvalidateRestoreUrl = @"/enrollment/validatePaperRestore.htm";
NSString const *ktimeUrl = @"/enrollment/time.htm";

int const ktimeDataLength = 8;
long const kwatingTime = 30000;
int const ksercretCodeLength = 20;

#pragma mark - interface

@interface Auth () {
    NSString *serialCode;
    Byte secretCode[ksercretCodeLength];
    long long sync;
}

@end

@implementation Auth


#pragma mark - initialize



-(id)init{
    if ([super init]) {
        serialCode = nil;
        serialCode = nil;
        sync = 0;
    }
    return self;
}

-(id)initWithSerialCode:(NSString *)serial secretCode:(Byte [])secret {
    
    return self;
}

-(id)initWithRegion:(NSString *)region {
    if ([self init]) {
        return [self createNewAuthWithRegion:region];
    }
    return nil;
}

-(id)initWithRestoreCode:(NSString *)restoreCode SerialCode:(NSString *)serial {
    if ([self init]) {
        return [self restoreFromCode:restoreCode withSerial:serial];
    }
    return nil;
}

#pragma mark - create a new auth

-(Auth *)createNewAuthWithRegion:(NSString *)region{
    if ([self isAllowedRegion:region]) {
        //create Url
        region = [region uppercaseString];
        NSLog(@"%@",region);
        NSString *enrollUrl = [NSString stringWithFormat:@"%@%@",[self rootUrlWith:region],kenrollMentUrl];
        
        //create data
        NSString *randomKey = [self createRandomKeyWithSize:37];
        NSString *deviceModel = [@"IOS_CUSTOM_MOBILE_AUTH" substringWithRange:NSMakeRange(0, 16)];
        NSString *createdData = [NSString stringWithFormat:@"%c%@%@%@",1,randomKey,region,deviceModel];
        //encrypt data
        NSData *encryptedData = [self encryptWithData:createdData];
        
        //post data
        NSData *receivedData = [self postData:encryptedData withUrl:enrollUrl];
        
        //decrypt data
        [self decryptWithData:receivedData withKey:randomKey];
        
        //get serial number and secret number from the decrypted data
        [self syncTimeWithData:receivedData];
        
        
        NSLog(@"serial:%@",serialCode);
        
        return self;
    }
    return nil;
}


#pragma mark - restore from code

-(Auth *)restoreFromCode:(NSString *)code withSerial:(NSString *)serial{
    NSLog(@"restore code:%@,serial:%@",code,serial);
    //no line in serial
    serialCode = [serial stringByReplacingOccurrencesOfString:@"-" withString:@""];
    //get the region and check if it's right
    NSString *region = [[serialCode substringWithRange:NSMakeRange(0, 2)] uppercaseString];
    code = [code uppercaseString];
    if ([self isAllowedRegion:region]) {
        //send serial code to check if it can be restored
        NSString *initUrl = [NSString stringWithFormat:@"%@%@",[self rootUrlWith:region],kinitRestoreUrl];
        NSData *serialData = [serialCode dataUsingEncoding:NSUTF8StringEncoding];
        NSData *challenge = [self postData:serialData withUrl:initUrl];
        Byte *codeBytes = [self restoreCodeFromChar:code];
        NSMutableData *scdata = [NSMutableData dataWithData:serialData];
        [scdata appendData:challenge];
        Byte *scBytes = (Byte *)[scdata bytes];
        NSLog(@"%@",challenge);
        
        //HMac SHA1 serial+challenge as data codeBytes as key
        unsigned char cHmac[CC_SHA1_DIGEST_LENGTH];
        CCHmac(kCCHmacAlgSHA1, (char *)codeBytes, 10, (char *)scBytes, 46, cHmac);
        NSMutableData *created = [NSMutableData dataWithBytes:cHmac length:sizeof(cHmac)];
        
        //encrypt hmac + randomkey with rsa encyption
        NSString *randomKey = [self createRandomKeyWithSize:20];
        NSData *randomKeyData = [randomKey dataUsingEncoding:NSUTF8StringEncoding];
        [created appendData:randomKeyData];
        NSLog(@"scdata:%@",scdata);
        NSLog(@"created:%@",created);
        NSLog(@"randomkey:%@",randomKey);
        NSData *encrypted = [self encryptWithData:created];
        
        //send serial+encrypted data to validate url
        NSString *validUrl = [NSString stringWithFormat:@"%@%@",[self rootUrlWith:region],kvalidateRestoreUrl];
        NSMutableData *sendingData = [NSMutableData dataWithData:serialData];
        [sendingData appendData:encrypted];
        NSData *received = [self postData:sendingData withUrl:validUrl];
        NSLog(@"received:%@,length:%d",received,received.length);
        
        //decrypt received data
        [self decryptWithData:received withKey:randomKey];
        NSLog(@"secret:%s",secretCode);
    } else {
        NSLog(@"invilid serial code");
    }
    return nil;
}

-(Byte *)restoreCodeFromChar:(NSString *)code {
    Byte *bytes = malloc(10);
    for (int i=0; i<10; ++i) {
        int c = [code characterAtIndex:i];
        if (c > 47 && c < 58) {
            c -= 48;
        }else{
            c -= 55;
            if (c > 82) {
                --c; //S
            }
            if (c > 78) {
                --c; //O
            }
            if (c > 75) {
                --c; //L
            }
            if (c > 72) {
                --c; //I
            }
        }
        bytes[i] = c;
    }
    return  bytes;
}

#pragma mark - create restore code

#pragma mark - encrypt decrypt and connection with server

-(BOOL)isAllowedRegion:(NSString *)region{
    NSSet *allowedRegion = [NSSet setWithObjects:@"US",@"EU",@"CN", nil];
    for (NSString *str in allowedRegion) {
        if ([region isEqualToString:str]) {
            return true;
        }
    }
    NSLog(@"invilid region!");
    return false;
}

-(NSString *)rootUrlWith:(NSString *)region{
    return [NSString stringWithFormat:@"http://m.%@.mobileservice.blizzard.com",region];
}

-(NSString *)createRandomKeyWithSize:(int)size {
    NSString *result;
    NSMutableString *string = [NSMutableString stringWithFormat:@""];
    unsigned char digest[CC_SHA1_DIGEST_LENGTH];
    NSString *randomString = [NSString stringWithFormat:@"%d",(unsigned)arc4random()];
    NSData *randomData = [randomString dataUsingEncoding:NSUTF8StringEncoding];
    if (CC_SHA1([randomData bytes], [randomData length], digest)) {
        for (int i=0; i<CC_SHA1_DIGEST_LENGTH; ++i) {
            [string appendFormat:@"%02x",digest[i]];
        }
        result = [string substringWithRange:NSMakeRange(0, size)];
    }
    return result;
}

-(NSData *)encryptWithData:(id)data {
    return [RSAEncypt encryptString:data withKey:(NSString *)kblizzardAuthPublicKey identify:@"publicKey"];
}


-(NSData *)postData:(NSData *)data withUrl:(NSString *)Url{
    return [[[HttpPostOperator alloc]init]postData:data withUrl:Url];
}

-(void )decryptWithData:(NSData *)data withKey:(NSString *)key{
    NSString *dataString = [[NSString alloc]initWithData:data encoding:NSASCIIStringEncoding];
    NSString *asciiString;
    if (data.length == 37) {
         asciiString = [dataString substringFromIndex:8];
    } else {
        asciiString = [dataString copy];
    }
    NSMutableString *serialTemp = [NSMutableString stringWithFormat:@""];
    if (asciiString.length==key.length) {
        for (int i=0; i<key.length; ++i) {
            unichar c = [asciiString characterAtIndex:i];
            unichar k = [key characterAtIndex:i];
            
            //first 20 bytes should be stored into secret code byte array
            //last 17 bytes should be stored into serial string
            
            if (i<ksercretCodeLength) {
                secretCode[i] = c^k;
            } else {
                [serialTemp appendFormat:@"%c",c^k];
                serialCode = [serialTemp stringByReplacingOccurrencesOfString:@"-" withString:@""];
            }
        }
    } else {
        NSLog(@"invilid return data");
    }
}

#pragma mark - calculate auth number


-(void)syncTimeWithRegion:(NSString *)region {
    if ([self isAllowedRegion:region]) {
         NSData *serverTimeData = [[[HttpPostOperator alloc]init]postData:nil withUrl:[NSString stringWithFormat:@"%@%@",[self rootUrlWith:region],ktimeUrl]];
        [self syncTimeWithData:serverTimeData];
    }
}

-(void)syncTimeWithData:(NSData*)data {
    NSMutableString *temp = [NSMutableString stringWithFormat:@""];
    const unsigned char *dataBuf = data.bytes;
    for (int i=0; i<ktimeDataLength; ++i) {
        [temp appendFormat:@"%02x",(NSUInteger)dataBuf[i]];
    }
    NSString *serverTimeHex = [NSString stringWithFormat:@"%@",temp];
    NSScanner *scanner = [NSScanner scannerWithString:serverTimeHex];
    unsigned long long serverTime=0;
    [scanner scanHexLongLong:&serverTime];
    NSLog(@"serverTime:%lld",serverTime);
    unsigned long long localTime = [NSDate date].timeIntervalSince1970*1000;
    sync = serverTime - localTime;
    NSLog(@"sync:%lld",sync);
}

-(unsigned long long )servertime {
    return [NSDate date].timeIntervalSince1970*1000+sync;
}

-(NSString *)result {
    NSScanner *scanner;

    unsigned times = (unsigned)([self servertime]/kwatingTime);
    
    //transform time hex string into int and add it into byte array
    
    NSString *timeHexString = [NSString stringWithFormat:@"%016x",times];
    
    Byte timeBytes[8];
    
    for (int i=0; i<8; ++i) {
        unsigned timeInt=0;
        NSString *hexTemp = [timeHexString substringWithRange:NSMakeRange(2*i, 2)];
        scanner = [NSScanner scannerWithString:hexTemp];
        [scanner scanHexInt:&timeInt];
        timeBytes[i]=timeInt;
    }
    
    //HMac SHA1 timebytes as data secret code as key ,return hex string
    
    unsigned char cHmac[CC_SHA1_DIGEST_LENGTH];
    CCHmac(kCCHmacAlgSHA1, secretCode, sizeof(secretCode),timeBytes, sizeof(timeBytes),cHmac);
    
    NSMutableString *hmacString = [NSMutableString stringWithFormat:@""];
    
    for (int i=0; i<sizeof(cHmac); ++i) {
        [hmacString appendFormat:@"%02x",(int)cHmac[i]];
    }
    
    //the last one byte point to the start location

    NSString *startString = [hmacString substringWithRange:NSMakeRange(39, 1)];
    scanner = [NSScanner scannerWithString:startString];
    unsigned start = 0;
    [scanner scanHexInt:&start];
    
    //4 bytes is what we need
    NSString *macNeed = [hmacString substringWithRange:NSMakeRange(start*2, 8)];
    scanner = [NSScanner scannerWithString:macNeed];
    unsigned long long code = 0;
    [scanner scanHexLongLong:&code];
    code &= 0x7fffffff;
    code %= 100000000;

    return [NSString stringWithFormat:@"%08lld",code];
}

@end
