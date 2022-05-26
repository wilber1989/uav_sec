#ifndef __VC_MAC_H__
#define __VC_MAC_H__
#include "../include/vc_sw_crypt_service.h"

s32 do_CalcCmac(vc_input_info     *input,  vc_cmac_info *keyInfo, vc_output_info *cmac);
s32 do_VerifyCmac(vc_input_info     *input,  vc_cmac_st *keyInfo, vc_output_info *cmac);
s32 do_CalcHmac(vc_hmac_info *hmac_info, vc_input_info *input, vc_output_info *hmac);

#endif
