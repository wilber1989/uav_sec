#ifndef __VC_KEY_H__
#define __VC_KEY_H__
#include "../include/vc_sw_crypt_service.h"


s32 vc_get_key_type(FILE *fp);
s32 vc_get_key_data(FILE *fp, vc_output_info *outdata);
s32 vc_get_tmp_key_type(u8 keyid);
s32 vc_get_tmp_key_data(u8 keyid, vc_output_info *outdata);
s32 vc_check_keyid(s32 keyid);
s32 vc_check_keymac(FILE *fp ,u8 *keyMac);
s32 vc_check_tmp_keymac(u8 keyid, u8 *keyMacIn);
s32 vc_set_keybit();
s32 do_storage_key(vc_storage_key_info *storageKeyInfo, s32 isDelete);
s32 do_storage_tmp_key(vc_storage_key_info *storageKeyInfo, s32 isDelete);
s32 do_export_key(vc_except_key *exceptKeyInfo,vc_output_info* outputInfo);
s32 do_hmac_genkey(vc_gen_key_info *genKeyInfo,  vc_output_info *outdata);
s32 do_sym_genkey(vc_gen_key_info *genKeyInfo,  vc_output_info *outdata);
s32 do_asym_genkey(vc_gen_key_info *genKeyInfo,  vc_output_info *pubKey, vc_output_info *privKey);

s32 do_gen_keymac(vc_input_info *keyInfo, u8 *keymac, u8 keyid);

#endif