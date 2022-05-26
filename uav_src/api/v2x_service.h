#ifndef __V2X_SERVICE_H__
#define __V2X_SERVICE_H__
#include <stdint.h>
#include "platformInfo.h"
//#include "v2x_service.h"

/*******************************************************
*
* 函数命 ：initDevice
* 描述    : 
    1. 初始化密码模块,
    2. 如果不存在公私钥对，则生成并加密存储
* 参数     :
    @device_info_ext ,设备ID，最大32字节

* 返回值          ：0 成功  ,  -1 失败
**********************************************************/
int32_t initDevice(vc_input_info  *device_info_ext);

/*******************************************************
*
* 函数命 isLocalDeviceCertFileExist
* 描述    : 
    1. 获取证书是否已经存在，如果证书不存在，则后续需要申请证书,

* 参数     :

* 返回值          ：0 证书存在 ,  -1 证书不存在
**********************************************************/
int32_t isLocalDeviceCertFileExist();

/*******************************************************
*
* 函数命 genCsrRequest
* 描述    : 
    1. 获取证书申请请求数据csr,

* 参数     :
    @csrData ,获取csr的buff，需要2048字节

* 返回值          ：0 成功  ,  -1 失败
**********************************************************/
int32_t genCsrRequest(vc_output_info  *csrData);



/*******************************************************
*
* 函数命 parseAndSaveCert
* 描述    : 
    1. 解析服务器返回的证书数据，并加密保存证。
* 参数     :
    @data_info ,传入服务器返回的证书信息。

* 返回值          ：0 成功  ,  -1 失败
**********************************************************/
int32_t parseAndSaveCert(vc_input_info *data_info);




/*******************************************************
*
* 函数命 getDevicePrivkey
* 描述    : 
    1. 获取加密保存的设备私钥内容
* 参数     :
    @output_privkey_info ,获取私钥的buff，要求2048字节。

* 返回值          ：0 成功  ,  -1 失败
**********************************************************/

int32_t getDevicePrivkey(vc_output_info * output_privkey_info);

/*******************************************************
*
* 函数命 getDeviceCert
* 描述    : 
    1. 获取加密保存的设备证书内容
* 参数     :
    @output_cert_info ,获取证书的buff，要求2048字节。

* 返回值          ：0 成功  ,  -1 失败
**********************************************************/

int32_t getDeviceCert(vc_output_info * output_cert_info);



/*******************************************************
*
* 函数命 deleteAllKeyAndCert
* 描述    : 
    1. 删除所有的本地证书和密钥
* 参数     :

* 返回值          ：
**********************************************************/
void deleteAllKeyAndCert();


#endif/*__V2X_SERVICE_H__*/