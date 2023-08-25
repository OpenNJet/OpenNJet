/*
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */

#include <njt_rand_util.h>

int njt_rand_percentage_sample(uint ration){
    if(ration >= 100){
        return 1;
    }

    if(ration < 1){
        return 0;
    }
    
    long long r = random();
    double r2 = r * 100.0;
    double f = r2 / RAND_MAX;
    if (f > (100 - ration))
        return 1;
    return 0;
}
