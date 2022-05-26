#ifndef __UNIT_H__
#define __UNIT_H__
#include <stdio.h>
#include <stdint.h>
#include "platformInfo.h"
extern void Hex_PRINTF(uint8_t *buf, int32_t len,uint8_t *tag);
extern int32_t HexStrSwitch2ByteArray(char s[],char bits[]);
#endif //__UNIT_H__