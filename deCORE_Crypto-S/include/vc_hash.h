#ifndef __VC_HASH_H__
#define __VC_HASH_H__
#include "../include/vc_sw_crypt_service.h"
#ifdef SMENABLE
#include "../include/openssl/sm3.h"
#endif
void hash_file_sha1(FILE *fin, vc_output_info* outputInfo);
void hash_file_sha224(FILE *fin, vc_output_info* outputInfo, int is224);
void hash_file_sha384(FILE *fin, vc_output_info* outputInfo, int is384);
void hash_file_sm3(FILE *fin, vc_output_info* outputInfo);

#endif