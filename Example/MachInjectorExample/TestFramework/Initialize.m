//
//  Initialize.m
//  TestFramework
//
//  Created by JH on 2026/1/16.
//

#include "Initialize.h"

extern void swift_initializeTestFramework(void);

static void initializeTestFramework(void) {
    swift_initializeTestFramework();
}
