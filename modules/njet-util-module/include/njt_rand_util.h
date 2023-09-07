
/*
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef NJET_MAIN_NJT_RAND_UTIL_H
#define NJET_MAIN_NJT_RAND_UTIL_H

#include <njt_core.h>

/*
 * get percentage probability by use random function
 * input: a integer, scope:[0,100]
 * output: 1 when hit percentage; else 0
 * eg: ration=99 means 99% probability
 *    
 * */
int njt_rand_percentage_sample(uint ration);

#endif //NJET_MAIN_NJT_RAND_UTIL_H
