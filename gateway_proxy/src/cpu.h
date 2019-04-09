#ifndef __CWMP_CPU_H__
#define __CWMP_CPU_H__

#include "type.h"

#ifdef  __cplusplus
extern "C" {
#endif

typedef struct cpu_frequency_st{
    int8 cur[32];
    int8 min[32];
    int8 max[32];
}cpu_frequency_t;

typedef struct cpuinfo_st{
    int8 utilization[32];
    int8 temperature[32];
    /*
    uint32 core_num;
    cpu_frequency_t core_freq[0];
    */
}cpuinfo_t;

void cpu_init(void);
void cpu_info_get(int8 *utilization);

#ifdef  __cplusplus
}
#endif

#endif /*__CWMP_CPU_H__*/
