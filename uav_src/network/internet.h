#ifndef SE_HTTPS_H
#define SE_HTTPS_H

#include <stdlib.h>
#include <stdint.h>
#include "vc_sw_crypt_service.h"
#include "platformInfo.h"
#ifdef CRUL_TEST


struct MemoryStruct
{
    char *memory;
    size_t size;
};

void freeMemoryStruct(struct MemoryStruct chunk);


int32_t https_request(const char * url, const char * method, const uint8_t * send_data,uint32_t send_data_len, struct MemoryStruct * chunkptr);
int32_t send_csr_get_cer_http_post(vc_input_info *send_info,vc_output_info *out_cert_info,uint8_t * ca_url);
int32_t get_crllist_http_post(vc_input_info *send_info,vc_output_info *response_info,uint8_t * crl_list_url);

#endif
#endif/*SE_HTTPS_H*/