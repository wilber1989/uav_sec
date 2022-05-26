#ifndef __PLATFORMINFO_H__
#define __PLATFORMINFO_H__
#include "unit.h"
#include <stdint.h>
#include "unit.h"
#include "vc_sw_crypt.h"
#define MAX_BUFF_LEN 1024


#define VC_SUCCESS 0
#define VC_FAILED -1

#define V2X_VECENT_PRINTF(A, ...) printf("%s:%d: "#A"\r\n", __FILE__, __LINE__, ##__VA_ARGS__);

//#define DEBUG 
#ifdef DEBUG
    #define CRUL_TEST
    #define V2X_VECEN_DEBUG_PRINTF(A, ...) printf("%s:%d: "#A"\r\n", __FILE__, __LINE__, ##__VA_ARGS__);
#else
    #define V2X_VECEN_DEBUG_PRINTF(A, ...)
#endif
#endif //__PLATFORMINFO_H__