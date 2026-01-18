//
//  Initialize.h
//  MachInjectorExample
//
//  Created by JH on 2026/1/15.
//

#ifndef Initialize_h
#define Initialize_h

__attribute__((constructor, used))
static void initializeTestFramework(void);

#endif /* Initialize_h */
