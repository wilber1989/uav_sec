#ifndef __VC_RSA_H__
#define __VC_RSA_H__
#include "../include/vc_sw_crypt_service.h"

s32 do_rsa_encrypt(vc_rsa_encdec_info* rsaEncDecInfo, vc_input_info* inputInfo, vc_output_info* outputInfo);
s32 do_rsa_decrypt(vc_rsa_encdec_info* rsaEncDecInfo, vc_input_info* inputInfo, vc_output_info* outputInfo);
s32 do_rsa_sign(vc_rsa_sigver_info * rsaSigVerInfo, void* inInfo, vc_output_info* outputInfo, s32 mod);
s32 do_rsa_verify(vc_rsa_sigver_info * rsaSigVerInfo, void* inInfo, vc_output_info* outputInfo, s32 mod);
s32 vc_gen_rsa_key(vc_gen_key_info *genKeyInfo,  vc_output_info *pubKey, vc_output_info *privKey);

#endif