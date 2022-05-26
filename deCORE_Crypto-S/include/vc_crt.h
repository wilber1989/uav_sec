#ifndef __VC_CRT_H__
#define __VC_CRT_H__
#include "../include/vc_sw_crypt_service.h"

s32 do_parse_crt_pubkey(vc_input_info *crtbuf, vc_output_info *outInfo);
s32 do_verify_crt(vc_input_info *crtInfo, vc_input_info *caInfo, vc_input_info *crlInfo, u8 *cn);
s32 do_gen_csr(vc_csr *csrInfo, vc_output_info *output);
s32 do_storage_crt(vc_storage_crt_info *crtInfo, s32 isDelete);
s32 do_export_crt(vc_except_crt *crtInfo,vc_output_info* outputInfo);
s32 do_get_crt(u8 crtID, vc_output_info *outInfo);


#endif
