#ifndef __VECENT_SE_PLATFORM_INFO_H__
#define __VECENT_SE_PLATFORM_INFO_H__

#define VECENT_DEBUG_ENABLE
/****************platform config begin********************/
#define VECENT_DEV_MAX_FSMI 0x01 //SPI BUFF SIZE VECENT_DEV_MAX_FSMI * 16

/*****platform feature begin******/
typedef signed char s8;
typedef signed int s32;
typedef unsigned short u16;
typedef unsigned char u8;
typedef unsigned int  u32;
typedef unsigned long long u64;

#define VECENT_PRINTF(M, ...) printf(M, ##__VA_ARGS__);
#ifdef VECENT_DEBUG_ENABLE
  #define VECENT_DEBUG_PRINTF VECENT_PRINTF
#else
 #define VECENT_DEBUG_PRINTF(M, ...)
#endif

#define VECENT_CHECK_M(condition, function , info) \
  if((condition))\
{\
  VECENT_PRINTF(#function" "#info" fail!\n");\
  res = VECENT_RET_FAIL;\
  goto tail;\
}

#define VECENT_CREAT_DELAY_M(waitTime) struct timeval (waitTime)
#define VECENT_SET_DELAY_M(waitTime,n) (waitTime).tv_sec=0;\
                                       (waitTime).tv_usec=(n)
#define VECENT_DELAY_F(waitTime) select(0, (void *)0, (void *)0, (void *)0, &(waitTime))
#define VECENT_CREAT_SYS_TICK_M(curTime, targTime) struct timeval (curTime);\
                                                   struct timeval (targTime);\
                                                   u32 tempus = 0
#define VECENT_MEMCPY_F(dest, source, len) memmove(dest, source, len)

/*****platform feature end******/

#define VECENT_EMPTY_POINTOR  ((void *)0)   //(NULL)
/****************platform config end********************/



/****************/
s32 VC_LOG_D(const char * format, ...);
s32 VC_LOG_I(const char * format, ...);
s32 VC_LOG_E(const char * format, ...);


/****************/


#endif //__VECENT_SE_PLATFORM_INFO_H__
