#ifndef __VC_SM2_H__
#define __VC_SM2_H__
#include "../include/vc_sw_crypt_service.h"
#include "../include/openssl/pem.h"

s32 vc_gen_gm_key(vc_gen_key_info *genKeyInfo,  vc_output_info *pubKey, vc_output_info *privKey);
s32 do_sm2_enc(vc_sm2_encdec_info *encInfo,    vc_input_info *inputInfo, vc_output_info *outputInfo);
s32 do_sm2_dec(vc_sm2_encdec_info *encInfo,    vc_input_info *inputInfo, vc_output_info *outputInfo);
s32 do_sm2_sign(vc_sm2_sigver_info *encInfo,    vc_input_info *inputInfo, vc_output_info *outputInfo);
s32 do_sm2_verify(vc_sm2_sigver_info *encInfo,    vc_input_info *inputInfo, vc_output_info *outputInfo);


#endif
