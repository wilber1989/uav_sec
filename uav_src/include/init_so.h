#ifndef _INIT_SO_H
#define _INIT_SO_H
#include "vc_sw_crypt.h"

typedef s32 (*vc_get_info)(vc_output_info *);
__attribute__ ((visibility("default")))
s32 init_so(vc_get_info f, vc_output_info* out);

#endif