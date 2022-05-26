#ifndef __VC_ENVELOPE_H__
#define __VC_ENVELOPE_H__
#include "../include/vc_sw_crypt_service.h"

s32 do_seal(vc_envelop_info *envIn, vc_input_info *input, vc_envelop_info *output);
s32 do_openseal(vc_envelop_info *envIn, vc_output_info *output);

#endif
