//
//  ViewController.m
//  CustomAuth
//
//  Created by wangyanqing on 14-4-28.
//  Copyright (c) 2014年 twob. All rights reserved.
//

#import "ViewController.h"
#import "Auth.h"

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad
{
    [super viewDidLoad];
    
    Auth *auth = [[Auth alloc]initWithRegion:@"CN"];
    while (1) {
        NSLog(@"result:%@",auth.resultCode);
        sleep(10);
    }
    
    Auth *authrestore = [[Auth alloc]initWithRestoreCode:@"1WG00RREH7" SerialCode:@"CN-1406-0497-3811"];
    NSLog(@"result:%@",[authrestore resultCode]);
}

- (void)didReceiveMemoryWarning
{
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

@end
