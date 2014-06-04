//
//  RSAEncypt.m
//  CustomAuth
//
//  Created by wangyanqing on 14-4-28.
//  Copyright (c) 2014年 twob. All rights reserved.
//

#import "RSAEncypt.h"

@implementation RSAEncypt

+(NSData *)encryptString:(id)string withKey:(NSString*)keyString identify:(NSString *)identify{
    NSData *publicKey = [[NSData alloc]initWithBase64EncodedString:keyString options:NSDataBase64DecodingIgnoreUnknownCharacters];
    SecKeyRef key = [self addPublicKey:publicKey withTag:identify];
    if ([string isKindOfClass:[NSData class]]) {
        return [self encryptRSAWithData:string key:key];
    }
    return [self encryptRSA:string key:key];
}

+(SecKeyRef)addPublicKey:(NSData *)publicKeyData withTag:(NSString *)tagString{
    //check the key
    if (publicKeyData==nil) {
        NSLog(@"publicKey is missing!");
        return nil;
    }
    
    //transform tag to NSData
    NSData *tagData = [NSData dataWithBytes:[tagString UTF8String] length:[tagString length]];
    
    //delete the old same tag item
    NSMutableDictionary *publicKey = [[NSMutableDictionary alloc]init];
    [publicKey setObject:(__bridge id) kSecClassKey forKey:(__bridge id)kSecClass];
    [publicKey setObject:(__bridge id) kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [publicKey setObject:tagData forKey:(__bridge id)kSecAttrApplicationTag];
    SecItemDelete((__bridge CFDictionaryRef)publicKey);
    
    //add new key with persistkey in return
    CFTypeRef persistKey = nil;
    
    [publicKey setObject:publicKeyData forKey:(__bridge id)kSecValueData];
    [publicKey setObject:(__bridge id) kSecAttrKeyClassPublic forKey:(__bridge id)kSecAttrKeyClass];
    [publicKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnPersistentRef];
    
    OSStatus secStatus = SecItemAdd((__bridge CFDictionaryRef)publicKey, &persistKey);
    
    //get the seckeyref version
    SecKeyRef keyRef;
    
    [publicKey removeObjectForKey:(__bridge id)kSecValueData];
    [publicKey removeObjectForKey:(__bridge id)kSecReturnPersistentRef];
    [publicKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnRef];
    [publicKey setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    
    secStatus = SecItemCopyMatching((__bridge CFDictionaryRef)publicKey, (CFTypeRef *)&keyRef);
    
    return keyRef;
}

+ (NSData *)encryptRSA:(NSString *)plainTextString key:(SecKeyRef)publicKey
{
    size_t cipherBufferSize = SecKeyGetBlockSize(publicKey);
    uint8_t *cipherBuffer = malloc(cipherBufferSize);
    uint8_t *nonce = (uint8_t *)[plainTextString UTF8String];
    for (int i =0; i<strlen((char *)nonce); ++i) {
        NSLog(@"nonce[%d]:%c",i,nonce[i]);
    }
    SecKeyEncrypt(publicKey,
                  kSecPaddingNone,
                  nonce,
                  strlen( (char*)nonce ),
                  &cipherBuffer[0],
                  &cipherBufferSize);
    NSData *encryptedData = [NSData dataWithBytes:cipherBuffer length:cipherBufferSize];
    /*
     NSUInteger capacity = encryptedData.length * 2;
    NSMutableString *stringBuf = [NSMutableString stringWithCapacity:capacity];
    const unsigned char *buf = encryptedData.bytes;
    for (NSInteger i=0; i<encryptedData.length; ++i) {
        [stringBuf appendFormat:@"%c",(int)buf[i]];
    }
    NSLog(@"stringbuf:%@",stringBuf);
     */
    return encryptedData;
}

+(NSData *)encryptRSAWithData:(NSData *)data key:(SecKeyRef)publicKey{
    size_t nonceLength = [data length];
    size_t cipherBufferSize = SecKeyGetBlockSize(publicKey);
    uint8_t *cipherBuffer = malloc(cipherBufferSize);
    //uint8_t *nonce;
    void * plain = malloc(nonceLength);
    [data getBytes:plain length:nonceLength];
    SecKeyEncrypt(publicKey,
                  kSecPaddingNone,
                  plain,
                  nonceLength,
                  &cipherBuffer[0],
                  &cipherBufferSize);
    NSData *encryptedData = [NSData dataWithBytes:cipherBuffer length:cipherBufferSize];
    
    NSLog(@"%@",encryptedData);
    //free(nonce);
    //free(cipherBuffer);
    return encryptedData;

}

@end
