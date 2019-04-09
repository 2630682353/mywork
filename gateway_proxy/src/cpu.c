#include "cpu.h"
#include "debug.h"
#include <stdio.h>
#include <strings.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

typedef struct cpu_status_st{
    int8 name[32];
    uint32 user;
    uint32 nice;
    uint32 system;
    uint32 idle;
    uint32 lowait;
    uint32 irq;
    uint32 softirq;
}cpu_status_t;

static cpu_status_t gs_cpu_status_arr[2];
static int32 first_index = 0;

static void cpu_status_get(cpu_status_t *cpu)
{
    FILE *pf = NULL;
    int8 buf[256];
    bzero(buf, sizeof(buf));
    pf = fopen("/proc/stat", "r");
    fgets(buf, sizeof(buf), pf);
    sscanf(buf, "%s %u %u %u %u %u %u %u", 
        cpu->name, &cpu->user, &cpu->nice,
        &cpu->system, &cpu->idle,&cpu->lowait,
        &cpu->irq,&cpu->softirq); 
    fclose(pf);
}

void cpu_init(void)
{
    bzero(gs_cpu_status_arr, sizeof(gs_cpu_status_arr));
    first_index = 0;
    cpu_status_get(&gs_cpu_status_arr[0]);
}

static void cpu_utilization_get(int8 *utilization)
{
    cpu_status_t *status1, *status2;
    uint64 sum1, sum2, sum;
    uint64 idle;
    uint64 use;
    uint64 integer;
    uint64 decimals;
    if (0 == first_index)
    {
        status1 = &gs_cpu_status_arr[0];
        status2 = &gs_cpu_status_arr[1];
        cpu_status_get(status2);
        first_index = 1;
    }
    else
    {
        status1 = &gs_cpu_status_arr[1];
        status2 = &gs_cpu_status_arr[0];
        cpu_status_get(status2);
        first_index = 0;
    }
    sum1 = status1->user + status1->nice 
        + status1->system + status1->idle 
        + status1->lowait + status1->irq 
        + status1->softirq;
    sum2 = status2->user + status2->nice 
        + status2->system + status2->idle 
        + status2->lowait + status2->irq 
        + status2->softirq;
    sum = sum2 - sum1;
    idle = status2->idle - status1->idle;
    use = sum - idle;
    integer = (use * 100) / sum;
    decimals = (((use * 100) % sum) * 100) / sum;
    sprintf(utilization, "%llu.%llu", integer, decimals);
}

/*
static void cpu_temperature_get(int8 *temperature)
{
#define CPU_TEMPERATURE_PATH    "/sys/class/thermal/thermal_zone0/temp"
    ASSERT(NULL != temperature);
    if (0 == access(CPU_TEMPERATURE_PATH, R_OK))
    {
        FILE *pf = NULL;
        int8 buf[32];
        uint32  temp;
        pf = fopen(CPU_TEMPERATURE_PATH,"r");
        ASSERT(NULL!=pf);
        bzero(buf, sizeof(buf));
        fread(buf, 1, sizeof(buf), pf);
        fclose(pf);
        temp = atoi(buf);
        sprintf(temperature, "%u.%u", temp/1000, temp%1000);
    }
    else
        strcpy(temperature, "unsupport");
}
*/

/*
uint32 cpu_core_num_get(void)
{
    uint32 core_num = 0;
#define CPU_ONLINE_PATH "/sys/devices/system/cpu/online"
    if (0 == access(CPU_ONLINE_PATH, R_OK))
    {
        FILE *pf = NULL;
        int8 buf[32];
        int8 *p = NULL;
        pf = fopen(CPU_ONLINE_PATH, "r");
        ASSERT(NULL!=pf);
        bzero(buf, sizeof(buf));
        fread(buf, 1, sizeof(buf), pf);
        fclose(pf);
        p = strchr(buf, '-');
        ASSERT(NULL!=p);
        core_num = atoi(p+1);
        core_num += 1;
    }
    return core_num;
}

static void cpu_frequency_get(const uint32 index,
                              cpu_frequency_t *freq)
{
    FILE *pf = NULL;
    int8 path_cur[128];
    int8 path_min[128];
    int8 path_max[128];
    int8 buf[32];
    int32 freq_tmp;
#define CPU_CUR_FREQUENCY_PATH  "/sys/devices/system/cpu/cpu%d/cpufreq/cpuinfo_cur_freq"
#define CPU_MIN_FREQUENCY_PATH  "/sys/devices/system/cpu/cpu%d/cpufreq/cpuinfo_min_freq"
#define CPU_MAX_FREQUENCY_PATH  "/sys/devices/system/cpu/cpu%d/cpufreq/cpuinfo_max_freq"
#define CPU_FREQUENCY_SHIFT_TO_KHZ  (1)
#define CPU_FREQUENCY_SHIFT_TO_MHZ  (1*1000)
#define CPU_FREQUENCY_SHIFT_TO_GHZ  (1*1000*1000)
    ASSERT(NULL!=freq);
    bzero(freq, sizeof(*freq));
    bzero(path_cur, sizeof(path_cur));
    bzero(path_min, sizeof(path_min));
    bzero(path_max, sizeof(path_max));
    snprintf(path_cur, sizeof(path_cur), CPU_CUR_FREQUENCY_PATH, index);
    snprintf(path_min, sizeof(path_min), CPU_MIN_FREQUENCY_PATH, index);
    snprintf(path_max, sizeof(path_max), CPU_MAX_FREQUENCY_PATH, index);
    if (0 == access(path_cur, R_OK))
    {
        pf = fopen(path_cur, "r");
        ASSERT(NULL!=pf);
        bzero(buf, sizeof(buf));
        fread(buf, 1, sizeof(buf), pf);
        fclose(pf);
        freq_tmp = atoi(buf);
        if ((freq_tmp / CPU_FREQUENCY_SHIFT_TO_GHZ) > 0)
            snprintf(freq->cur, sizeof(freq->cur), "%d.%dGHZ", 
                freq_tmp / CPU_FREQUENCY_SHIFT_TO_GHZ, 
                freq_tmp % CPU_FREQUENCY_SHIFT_TO_GHZ);
        else if ((freq_tmp / CPU_FREQUENCY_SHIFT_TO_MHZ) > 0)
            snprintf(freq->cur, sizeof(freq->cur), "%d.%dMHZ", 
                freq_tmp / CPU_FREQUENCY_SHIFT_TO_MHZ, 
                freq_tmp % CPU_FREQUENCY_SHIFT_TO_MHZ);
        else
            snprintf(freq->cur, sizeof(freq->cur), "%d.%dKHZ", 
                freq_tmp / CPU_FREQUENCY_SHIFT_TO_KHZ, 
                freq_tmp % CPU_FREQUENCY_SHIFT_TO_KHZ);
    }
    if (0 == access(path_min, R_OK))
    {
        pf = fopen(path_min, "r");
        ASSERT(NULL!=pf);
        bzero(buf, sizeof(buf));
        fread(buf, 1, sizeof(buf), pf);
        fclose(pf);
        freq_tmp = atoi(buf);
        if ((freq_tmp / CPU_FREQUENCY_SHIFT_TO_GHZ) > 0)
            snprintf(freq->min, sizeof(freq->min), "%d.%dGHZ", 
                freq_tmp / CPU_FREQUENCY_SHIFT_TO_GHZ, 
                freq_tmp % CPU_FREQUENCY_SHIFT_TO_GHZ);
        else if ((freq_tmp / CPU_FREQUENCY_SHIFT_TO_MHZ) > 0)
            snprintf(freq->min, sizeof(freq->min), "%d.%dMHZ", 
                freq_tmp / CPU_FREQUENCY_SHIFT_TO_MHZ, 
                freq_tmp % CPU_FREQUENCY_SHIFT_TO_MHZ);
        else
            snprintf(freq->min, sizeof(freq->min), "%d.%dKHZ", 
                freq_tmp / CPU_FREQUENCY_SHIFT_TO_KHZ, 
                freq_tmp % CPU_FREQUENCY_SHIFT_TO_KHZ);
    }
    if (0 == access(path_max, R_OK))
    {
        pf = fopen(path_max, "r");
        ASSERT(NULL!=pf);
        bzero(buf, sizeof(buf));
        fread(buf, 1, sizeof(buf), pf);
        fclose(pf);
        freq_tmp = atoi(buf);
        if ((freq_tmp / CPU_FREQUENCY_SHIFT_TO_GHZ) > 0)
            snprintf(freq->max, sizeof(freq->max), "%d.%dGHZ", 
                freq_tmp / CPU_FREQUENCY_SHIFT_TO_GHZ, 
                freq_tmp % CPU_FREQUENCY_SHIFT_TO_GHZ);
        else if ((freq_tmp / CPU_FREQUENCY_SHIFT_TO_MHZ) > 0)
            snprintf(freq->max, sizeof(freq->max), "%d.%dMHZ", 
                freq_tmp / CPU_FREQUENCY_SHIFT_TO_MHZ, 
                freq_tmp % CPU_FREQUENCY_SHIFT_TO_MHZ);
        else
            snprintf(freq->max, sizeof(freq->max), "%d.%dKHZ", 
                freq_tmp / CPU_FREQUENCY_SHIFT_TO_KHZ, 
                freq_tmp % CPU_FREQUENCY_SHIFT_TO_KHZ);
    }
}
*/

void cpu_info_get(int8 *utilization)
{
    //uint32 i = 0;
//    ASSERT(NULL != info);
//    bzero(info, sizeof(*info));
    cpu_utilization_get(utilization);
//    cpu_temperature_get(info->temperature);
    /*
    info->core_num = cpu_core_num_get();
    for (i=0; i<info->core_num; ++i)
        cpu_frequency_get(i, &(info->core_freq[i]));
    */
}