#include <stdio.h>
#include <stdint.h>
#include "platformInfo.h"
#include "cJSON.h"
#include "seInterface.h"
#include "internet.h"


extern s32 exportFileKey(vc_output_info* outputInfo);
#ifdef CRUL_TEST

#define RA_URL "http://192.168.34.29:360"//"http://172.16.5.119:360/"
#define CA_URL "http://192.168.34.29:360"//"http://172.16.5.119:350/"
#define CERT "/RA/service/api/cert"
#define CRLLIST "/xfile/ca.crl"


#define CERT_URL  RA_URL CERT
#define CRILIST_URL  CA_URL CRLLIST



int32_t testGetCert(vc_input_info *json_body_info ,vc_output_info *out_cert_output)
{
    int32_t ret = -1;
    ret = send_csr_get_cer_http_post(json_body_info,out_cert_output,CERT_URL);

    return ret;
}
#endif
int32_t isLocalDeviceCertFileExist()
{
    int32_t ret = -1;
    if(isDeviceCertFileExist()!=KEY_IS_NOT_EXIST)
    {
        ret = 0;
    }
    else
    {
        ret = -1;
    }
    
    return ret; 
}

int32_t parseAndSaveCert(vc_input_info *data_info)
{
    int32_t ret = -1;

    uint8_t *out;
    cJSON *json;
    if(data_info == NULL ||data_info->dataSize<=0)
    {
        V2X_VECENT_PRINTF("data_info error");
        return -1;
    }


    json=cJSON_Parse(data_info->data);

    out=cJSON_Print(json); 
    if(out == NULL)
    {
         V2X_VECENT_PRINTF(" out=NULL ,data_info->data = %s \n" ,data_info->data);
         V2X_VECENT_PRINTF("data_info->data error,json is null");
         return -1;
    }

    cJSON *item_error_code = cJSON_GetObjectItem(json,"errorCode");
    cJSON *item_cert = cJSON_GetObjectItem(json,"cert");
    if(item_error_code != NULL)
    {
        V2X_VECENT_PRINTF("errorCode = %s",item_error_code->valuestring);
        ret = -1;
    }

    cJSON *item_error_code_success = cJSON_GetObjectItem(json,"success");
    if(item_error_code_success != NULL)
    {
        if(item_error_code_success->type == cJSON_False)
        {
            cJSON *item_error_message = cJSON_GetObjectItem(json,"message");
            if(item_error_message != NULL)
            {
                V2X_VECENT_PRINTF("item_error_message == %s",item_error_message->valuestring);
            }
        }

    }
        

    if(item_cert!=NULL)
    {
        uint8_t cert_buff[4096] = {0x00};

        strncat(cert_buff, CERT_FORMAT_STATR_STR, strlen(CERT_FORMAT_STATR_STR));
        int32_t src_cert_len = strlen(item_cert->valuestring);
        int32_t src_offset = 0;
        do
        {
            if(src_cert_len - src_offset>=DEFAULT_STR_LINE_LEN)
            {
                strncat(cert_buff, item_cert->valuestring + src_offset, DEFAULT_STR_LINE_LEN);
                strcat(cert_buff, SEPARATOR_FLAG);
                src_offset += DEFAULT_STR_LINE_LEN;
            }
            else
            {
                strncat(cert_buff, item_cert->valuestring + src_offset, src_cert_len - src_offset);
                strcat(cert_buff, SEPARATOR_FLAG);
                break;
            }
            
        } 
        while (1);

        strncat(cert_buff, CERT_FORMAT_END_STR, strlen(CERT_FORMAT_END_STR));
        vc_input_info certInfo;
        certInfo.data = cert_buff;
        certInfo.dataSize = sizeof(cert_buff);
        storageCertAndKeyFile(&certInfo);
        V2X_VECEN_DEBUG_PRINTF("%s",cert_buff);
        ret = 0;
    }

    if(json!=NULL)
        cJSON_Delete(json);


    return ret;
}

/*
type:
11 平台证书，
12 用户证书，
13 设备证书。
*/
int32_t genCsrRequest(vc_output_info * csrData)
{
    int32_t ret = -1;

    if(isDeviceCertFileExist()!=KEY_IS_NOT_EXIST)
    {
        V2X_VECENT_PRINTF("Device cert is exist ,return ");
        return 0;
    }

    vc_output_info device_id_info;
    uint8_t device_buff[33] = {0x00};
    uint32_t device_buff_len = 33;
    device_id_info.data = device_buff;
    device_id_info.dataSize = device_buff_len;
    ret=t_get_deviceid_info(&device_id_info);
    if(ret != 0)
    {
        V2X_VECENT_PRINTF("get device error ");
        goto exit;
    }

    uint8_t subject[128]={0x00};
    sprintf(subject,"CN=%s,OU=IOT,O=CMCC,L=CD,ST=SC,C=CN",device_id_info.data);

    V2X_VECEN_DEBUG_PRINTF("subject data = %s",subject);

    vc_input_info subjectInfo;
    subjectInfo.data = subject;
    subjectInfo.dataSize = strlen(subject);

    vc_output_info csr_data_info;
    uint8_t csr_data_buf[2048] = {0x00};
    uint32_t csr_data_buf_len = 2048;
    csr_data_info.data = csr_data_buf;
    csr_data_info.dataSize = csr_data_buf_len;
    ret = GEN_CSR(&subjectInfo,&csr_data_info);
    if(ret != 0)
    {
        V2X_VECENT_PRINTF("GEN_CSR failed exit ");
        goto exit;
    }
    
    uint8_t response_data_buf[4096] = {0x00};
    uint32_t response_data_len = 4096;
    vc_output_info out_cert_output;
    out_cert_output.data = response_data_buf;
    out_cert_output.dataSize = response_data_len;


    cJSON *root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "type", 13);
    cJSON_AddStringToObject(root, "subject", subject);
    cJSON_AddStringToObject(root, "csr", csr_data_info.data);

    char *body = cJSON_Print(root);
    if(csrData->dataSize<strlen(body))
    {
        V2X_VECENT_PRINTF("send_data_info->dataSize is small ,%d",csrData->dataSize);
        cJSON_Delete(root);
        free(body);
        ret = -1;
        goto exit;
    }
    csrData->dataSize = strlen(body);
    memcpy(csrData->data,body,csrData->dataSize);
    cJSON_Delete(root);
    free(body);


    // if(0)
    // {
    //     vc_input_info json_body_info;
    //     json_body_info.data = csrData->data;
    //     json_body_info.dataSize = csrData->dataSize;

    //     ret = testGetCert(&json_body_info,&out_cert_output);
    //     if(ret != 0)
    //     {
    //         V2X_VECENT_PRINTF("testGetCert failed ,ret = %d",ret);
    //         goto exit;
    //     }
    //     parseAndSaveCert((vc_input_info *)&out_cert_output);
    // }


exit:

    return ret;
}



#ifdef CRUL_TEST

int32_t getCrlListAndSave(uint8_t * crl_list_url)
{
    if(crl_list_url == NULL)
    {
        V2X_VECENT_PRINTF("crl_list url is NULL,return ");
        return -1;
    }
    vc_output_info crllist_data_info;
    uint8_t csr_data_buf[8192] = {0x00};
    uint32_t csr_data_buf_len = 8192;
    crllist_data_info.data = csr_data_buf;
    crllist_data_info.dataSize = csr_data_buf_len;
    int32_t ret = get_crllist_http_post(NULL,&crllist_data_info,crl_list_url);
    if(ret == 0)
    {
        ret = storageCrlListCrt((vc_input_info *)(&crllist_data_info));

    }
    return ret;
}
#endif
int32_t readCacertAndSave()
{
    int32_t ret = -1;

    if(isCaCertFileExist() != KEY_IS_NOT_EXIST)
    {
        V2X_VECENT_PRINTF("CA CERT has imported,do not import other");
        return 0;

    }
    u8 filepath[] = "./ca-cert.pem";
    FILE*fp;
    fp = fopen(filepath, "rb");
    if (fp == NULL)
        V2X_VECENT_PRINTF("fopen ca file  %s\n", filepath);
    vc_input_info certInfo;
    uint8_t cert_buff[4096]={0x00};
    certInfo.data = cert_buff;
    certInfo.dataSize = 4096;
    certInfo.dataSize = fread (certInfo.data, 1, 4096, fp) + 1;
    ret = storageCaCertFile(&certInfo);

    return ret;
}


//gen and get device cert
//input ca
int32_t initDevice(vc_input_info  *device_info_ext)
{
    int32_t ret = -1;
    
    //每次进程起来后都必须先调用TST_INIT
    ret = initSourceInfo(device_info_ext);
    if(ret !=0)
    {
        V2X_VECENT_PRINTF("initSourceInfo failed");
        goto exit;
    }

    ret = genRsaDeviceKeyPair();

    if(ret !=0)
    {
        V2X_VECENT_PRINTF("genRsaDeviceKeyPair failed");
        goto exit;
    }

#if 0
    vc_output_info send_data_info;
    uint8_t data_buf[2048];
    send_data_info.data = data_buf;
    send_data_info.dataSize = 2048;
    ret = genCsrAndGetCert(&send_data_info);
    if(ret !=0)
    {
        V2X_VECENT_PRINTF("genCsrAndGetCert failed");
        goto exit;
    }
#endif
    //ret = readCacertAndSave();
exit:
    return ret;
}


int32_t getDevicePrivkey(vc_output_info * output_privkey_info)
{
    return exportFileKey(output_privkey_info);
}

int32_t getDeviceCert(vc_output_info * output_cert_info)
{
    return exportFileCert(output_cert_info);
}

int32_t getLocalCrlList(vc_output_info * output_cert_info)
{
    return exportCrlListFileCert(output_cert_info);
}

int32_t cleanTheDeviceCert()
{
    int32_t ret = -1;

    return ret;
}