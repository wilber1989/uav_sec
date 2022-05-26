#ifndef __VC_AES_H__
#define __VC_AES_H__
#include "../include/vc_sw_crypt_service.h"

s32 do_aes_crypt(vc_aes_encdec_info* aesEncDecInfo, vc_output_info *keyInfo, vc_input_info* inputInfo, vc_output_info* outputInfo, s32 enc_mod);
s32 vc_aes_crypt(vc_aes_encdec_info* aesEncDecInfo, vc_input_info* inputInfo, vc_output_info* outputInfo, s32 enc_mod);

#endif