//
//  Initialize.m
//  TestFramework
//
//  Created by JH on 2026/1/16.
//

#import <Foundation/Foundation.h>

__attribute__((constructor))
static void initializeTestFramework(void) {
    NSLog(@"Initialize TestFramework");
}
