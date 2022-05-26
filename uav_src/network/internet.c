
#include <stdio.h>
#include <stdlib.h>
#include <curl/curl.h>
#include <string.h>
#include "internet.h"
#include "platformInfo.h"
#include "vc_sw_crypt_service.h"
#include "cJSON.h"

//#define CRUL_TEST
#ifdef CRUL_TEST

#if 0
#define RA_URL "http://192.168.34.29:360"// "http://172.16.5.119:360/"
#define CA_URL "http://192.168.34.29:360"
#define CERT "/RA/service/api/cert"
#define CRLLIST "/xfile/ca.crl"


#define CERT_URL  RA_URL CERT
#define CRILIST_URL  CA_URL CRLLIST
#endif



static size_t
WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;

    mem->memory = realloc(mem->memory, mem->size + realsize + 1);
    if (mem->memory == NULL)
    {
        /* out of memory! */
        V2X_VECENT_PRINTF("not enough memory (realloc returned NULL)\n");
        return 0;
    }

    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;

    return realsize;
}

void freeMemoryStruct(struct MemoryStruct chunk)
{
    free(chunk.memory);
    chunk.memory = NULL;
}
/*
agrs method :"POST" or "GET"
*/

int32_t https_request(const char * url, const char * method, const uint8_t * send_data,uint32_t send_data_len, struct MemoryStruct * chunkptr)
{
    CURL *curl;
    CURLcode res;
    struct curl_slist *headers = NULL;
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();

    if (curl)
    {
        curl_easy_setopt(curl, CURLOPT_URL, url);
        //curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
        //curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method);
        //headers = curl_slist_append(headers, "Accept-Encoding:gzip,deflate");
	    headers = curl_slist_append(headers, "Content-Type:application/json;charset=UTF-8");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        if(send_data != NULL)
        {
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, send_data);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, send_data_len);
        }

        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);//callback获取到的返回数据
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)chunkptr); //设置 WriteMemoryCallback 的第四个参数的值
        /* Perform the request, res will get the return code */
        res = curl_easy_perform(curl);

        long HTTP_flag = 0;
        /* Check for errors */
        if (res != CURLE_OK)
            fprintf(stderr, "curl_easy_perform() failed: %s\n",
                    curl_easy_strerror(res));
        else {
            /*

                //添加获取post内容的函数,并释放chunkptr,如果外部函数无获取，可从此处获取
            */

            res = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &HTTP_flag);
            if(CURLE_OK == res)
            {
                if(HTTP_flag>200)
                {
                    V2X_VECENT_PRINTF("POST RESPONSE error code = %ld",HTTP_flag);
                    res = -1;
                }
            }

        }
        /* always cleanup */
        curl_easy_cleanup(curl);
        curl_slist_free_all(headers);
      }

    curl_global_cleanup();
    if(res != CURLE_OK)
    {
        return VC_FAILED;
    }
    return VC_SUCCESS;
}




int32_t send_csr_get_cer_http_post(vc_input_info *send_info,vc_output_info *out_cert_info,uint8_t * ca_url)
{
    int32_t res = VC_SUCCESS;
    struct MemoryStruct chunkptr = {0x00};
    chunkptr.memory = malloc(1);
    chunkptr.size = 0;
    V2X_VECEN_DEBUG_PRINTF("URL  = %s \n",ca_url);
    res =https_request(ca_url,"POST",send_info->data,send_info->dataSize,&chunkptr);
    if(res == VC_SUCCESS)
    {
        if(out_cert_info->dataSize < chunkptr.size)
        {
            V2X_VECENT_PRINTF("response_info->dataSize is small,return error");
            return VC_FAILED;
        }
        else
        {
            memcpy(out_cert_info->data,chunkptr.memory,chunkptr.size);
            out_cert_info->dataSize = chunkptr.size;
            Hex_PRINTF(out_cert_info->data,chunkptr.size,"response == ");
        }  
    }
    freeMemoryStruct(chunkptr);
    return res;
}



int32_t get_crllist_http_post(vc_input_info *send_info,vc_output_info *response_info,uint8_t * crl_list_url)
{
    int32_t res = VC_SUCCESS;
    struct MemoryStruct chunkptr = {0x00};
    chunkptr.memory = malloc(1);
    chunkptr.size = 0;
    res =https_request(crl_list_url,"GET",NULL,0,&chunkptr);

    V2X_VECEN_DEBUG_PRINTF("chunkptr.size = %ld, response_info->dataSize = %d\n",chunkptr.size,response_info->dataSize );
    if(res == VC_SUCCESS)
    {
        if(response_info->dataSize < chunkptr.size)
        {
            V2X_VECENT_PRINTF("response_info->dataSize is small,return error");
            return VC_FAILED;
        }
        else
        {
            memcpy(response_info->data,chunkptr.memory,chunkptr.size);
            response_info->dataSize = chunkptr.size;
            Hex_PRINTF(response_info->data,chunkptr.size,"response == ");
        }  
    }
    freeMemoryStruct(chunkptr);
    return res;
}

#endif