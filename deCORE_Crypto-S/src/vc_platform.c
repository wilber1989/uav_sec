#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "../include/vecent_se_platform_info.h"

#define BUFMAX (1024*1024) //1m log buffer
static char logBuf[BUFMAX] = {0};

s32 VC_LOG_D(const char * format, ...)
{
#if 0
    va_list ag;
    va_start(ag ,format);
    memset(logBuf, 0, sizeof(logBuf));
    vsnprintf(logBuf, BUFMAX, format, ag);
    printf("%s", logBuf);
    va_end(ag);
#endif
}

s32 VC_LOG_I(const char * format, ...)
{
#if 0
    va_list ag;
    va_start(ag ,format);
    memset(logBuf, 0, sizeof(logBuf));
    vsnprintf(logBuf, BUFMAX, format, ag);
    printf("%s", logBuf);
    va_end(ag);
#endif
}

s32 VC_LOG_E(const char * format, ...)
{
#if 1
    va_list ag;
    va_start(ag ,format);
    memset(logBuf, 0, sizeof(logBuf));
    vsnprintf(logBuf, BUFMAX, format, ag);
    printf("%s", logBuf);
    va_end(ag);
#endif
}

