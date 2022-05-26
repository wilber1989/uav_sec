#include <stdio.h>
#include <stdint.h>
#include "v2x_service.h"
#include "platformInfo.h"

#define BUFF_SIZE 2048


int32_t main()
{
    int32_t res = -1;
    uint8_t buff[BUFF_SIZE] = {0};  
    int32_t buff_len = 0;

    printf("start .........................  \n");
    if(0)
    {
        deleteAllKeyAndCert();
    }
    else
    {
        uint8_t *device_id= "01020304050607080900";//1-32 byte
        vc_input_info device_info;
        device_info.data = device_id;
        device_info.dataSize = strlen(device_id);

        res = initDevice(&device_info);
        if(res != 0)
            goto exit;

        if(isLocalDeviceCertFileExist() == 0)
            goto exit;


        vc_output_info request_data;
        memset(buff, 0,BUFF_SIZE);
        request_data.data = buff;
        request_data.dataSize = BUFF_SIZE;

        genCsrRequest(&request_data);


        vc_output_info out_cert_output;
        uint8_t certdata[BUFF_SIZE] = {0x00};
        out_cert_output.data = certdata;
        out_cert_output.dataSize = BUFF_SIZE;
        #ifdef CRUL_TEST
        testGetCert((vc_input_info *)&request_data ,&out_cert_output);
        #endif
        parseAndSaveCert((vc_input_info *)&out_cert_output);



        vc_output_info out_info;
        memset(buff, 0,BUFF_SIZE);
        out_info.data = buff;
        out_info.dataSize = BUFF_SIZE;
        res = getDevicePrivkey(&out_info);



        printf("device privkey \n");
        printf("%s",out_info.data);
        printf("\n");
        memset(buff,0,BUFF_SIZE);

        res = getDeviceCert(&out_info);
        if(res != 0)
            goto exit;
        printf("device cert is \n");
        printf("%s",out_info.data);
        printf("\n");

    }
exit:
    return 0;
}


