#include "log.h"

#include <syslog.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/stat.h>
#include <strings.h>
#include <string.h>
#include <unistd.h>

void my_log(char *file, const char *fmt, ...)
{
    va_list ap;
    FILE *fp = NULL;
    char bakfile[32] = {0,};

    fp = fopen(file, "a+");
    if (fp == NULL)
        return;
    va_start(ap, fmt);
    vfprintf(fp, fmt, ap);
    va_end(ap);
    if (ftell(fp) > 10*1024)
        snprintf(bakfile, sizeof(bakfile), "%s.bak", file);
    fclose(fp);
    if (bakfile[0])
        rename(file, bakfile);
}

