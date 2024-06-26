#ifndef __IOTEX_DEVICE_CONNECT_CORE_H__
#define __IOTEX_DEVICE_CONNECT_CORE_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "./psa/crypto.h"
#include "./utils/iotex_dev_access.h"
#include "./utils/LowerS/LowerS.h"

#include "./jose/jose.h"
#include "./dids/dids.h"

#ifdef ARDUINO
#include "DeviceConnect_PAL.h"
#endif

#ifdef __cplusplus
extern "C"
{
#endif

#ifdef ARDUINO
int iotex_device_connect_mqtt_pub(unsigned char *topic, unsigned char *buf, unsigned int buflen, int qos);
uint8_t * iotex_deviceconnect_sdk_core_init(DevConn_Comm *commClient);
#else
uint8_t * iotex_deviceconnect_sdk_core_init(iotex_gettime get_time_func, iotex_mqtt_pub mqtt_pub, iotex_mqtt_sub mqtt_sub);
#endif
uint8_t * iotex_deviceconnect_sdk_core_get_public_key(void);
uint8_t * iotex_deviceconnect_sdk_core_get_eth_addr(void);

void iotex_ioconnect_core_init(void);

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
}
#endif

#endif
