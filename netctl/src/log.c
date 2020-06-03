#include "log.h"

#include <syslog.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/stat.h>
#include <strings.h>
#include <string.h>
#include <unistd.h>

unsigned int log_leveljf = 1;

char *log_array[] = 
{
	"err",
	"warning",
	"info",
	"debug",
	NULL
};


void my_log(int logl, char *file, const char *fmt, ...)
{
	if (logl > log_leveljf)
		return;
    va_list ap;
    FILE *fp = NULL;
    char bakfile[32] = {0,};
    fp = fopen(file, "a+");
    if (fp == NULL)
    {
        return;
    }
    va_start(ap, fmt);
    vfprintf(fp, fmt, ap);
    va_end(ap);
    if (ftell(fp) > 10*1024)
    {
        snprintf(bakfile, sizeof(bakfile), "%s.bak", file);
    }
    fclose(fp);
    if (bakfile[0])
    {
        rename(file, bakfile);
    }
}

void write_file(char *file, const char *fmt, ...)
{
	va_list ap;
	FILE *fp = NULL;
    char bakfile[32] = {0,};
    fp = fopen(file, "a+");
    if (fp == NULL)
    {
        return;
    }
    va_start(ap, fmt);
    vfprintf(fp, fmt, ap);
    va_end(ap);
    if (ftell(fp) > 20*1024)
    {
        snprintf(bakfile, sizeof(bakfile), "%s.bak", file);
    }
    fclose(fp);
    if (bakfile[0])
    {
        rename(file, bakfile);
    }
}
