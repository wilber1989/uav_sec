#ifndef __VC_ECC_H__
#define __VC_ECC_H__
#include "../include/vc_sw_crypt_service.h"

s32 vc_gen_ecc_key(vc_gen_key_info *genKeyInfo, vc_output_info *pubKey, vc_output_info *privKey);
s32 do_ecdsa_sign(vc_ecc_sigver_info *sigInfo, void* inInfo, vc_output_info* outputInfo1, vc_output_info* outputInfo2, s32 mod);
s32 do_ecdsa_verify(vc_ecc_sigver_info *sigInfo, void* inInfo, vc_output_info* outputInfo1, vc_output_info* outputInfo2 ,s32 mod);
s32 do_get_dhKey(vc_input_info *privInfo, vc_input_info *pubInfo , vc_output_info* outputInfo);
s32 vc_gen_ecdh_25519_key(vc_gen_key_info *genKeyInfo, vc_output_info *pubKey , vc_output_info *privKey);
s32 do_ecc_enc(vc_ecc_encdec_info *     keyInfo, vc_input_info *input, vc_output_info *output);
s32 do_ecc_dec(vc_ecc_encdec_info* keyInfo, vc_input_info *input, vc_output_info *output);


#endif
