/*
  File: main.c

  VSCP Wireless CAN4VSCP Gateway (VSCP-WCANG, Frankfurt-WiFi)

  This file is part of the VSCP (https://www.vscp.org)

  The MIT License (MIT)
  Copyright (C) 2021-2026 Ake Hedman, the VSCP project <info@vscp.org>

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in all
  copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
  SOFTWARE.
*/

#include <stdio.h>
#include <string.h>

#include <freertos/FreeRTOS.h>
#include <freertos/event_groups.h>
#include <freertos/queue.h>
#include <freertos/task.h>
#include "freertos/semphr.h"

#include <driver/gpio.h>
#include "esp_task_wdt.h"
#include <driver/twai.h>
#include <esp_event.h>
#include <esp_http_server.h>
#include <esp_log.h>
#include <esp_mac.h>
#include <esp_timer.h>
#include <esp_tls_crypto.h>
#include <esp_wifi.h>
#include <lwip/sockets.h>
#include <nvs_flash.h>

#include <wifi_provisioning/manager.h>

#ifdef CONFIG_WCANG_PROV_TRANSPORT_BLE
#include <wifi_provisioning/scheme_ble.h>
#endif /* CONFIG_WCANG_PROV_TRANSPORT_BLE */

#ifdef CONFIG_WCANG_PROV_TRANSPORT_SOFTAP
#include <wifi_provisioning/scheme_softap.h>
#endif /* CONFIG_WCANG_PROV_TRANSPORT_SOFTAP */
#include "qrcode.h"

#include "vscp.h"
#include "vscp-firmware-helper.h"

#include "can4vscp.h"
#include "tcpsrv.h"
#include "udpclient.h"
#include "udpsrv.h"
#include "websrv.h"

#include "main.h"

#include "vscp-compiler.h"
#include "vscp-projdefs.h"

static const char *TAG = "main";

/*
  VSCP firmware level 2 protocol configuration
  is done here. Config is defined in
  vscp-firmware-level2.h
*/
// static vscp_frmw2_firmware_config_t vscp_config = {
//   .m_level = VSCP_LEVEL1, // Level I
//   .m_puserdata = NULL,     // No user data
// };

// * * * Globals * * *

// Handle for nvs storage
nvs_handle_t g_nvsHandle;

// Persistent configuration defaults  g_persistent.guid
node_persistent_config_t g_persistent = { .nodeName = DEFAULT_NODE_NAME,
                                          .guid     = { 0 }, // Default GUID is constructed from MAC address
                                          .bootCnt  = 0,
                                          .pmkLen   = 16,    // AES128 (for future use)
                                          .pmk      = { 0 }, // Default key is all nills

                                          .logType      = DEFAULT_LOG_TYPE,    // Log type
                                          .logLevel     = DEFAULT_LOG_LEVEL,   // Log level
                                          .logRetries   = DEFAULT_LOG_RETRIES, // Number of retries for log message send
                                          .logPort      = DEFAULT_LOG_PORT,    // Log server port
                                          .logUrl       = DEFAULT_LOG_URL,     // Log server address
                                          .logMqttTopic = DEFAULT_MQTT_LOG_PUBLISH_TOPIC, // MQTT topic for log messages
                                          .logwrite2Stdout = DEFAULT_LOG_WRITE2STDOUT,    // Write log to stdout

                                          .webPort     = DEFAULT_WEBSERVER_PORT,
                                          .webUser     = DEFAULT_WEBSERVER_USER,
                                          .webPassword = DEFAULT_WEBSERVER_PASSWORD,

                                          .enableVscpLink   = DEFAULT_VSCP_LINK_ENABLE,
                                          .vscplinkPort     = DEFAULT_VSCP_LINK_PORT,
                                          .vscplinkUser     = DEFAULT_VSCP_LINK_USER,
                                          .vscplinkPassword = DEFAULT_VSCP_LINK_PASSWORD,

                                          .enableMqtt   = DEFAULT_MQTT_ENABLE,
                                          .mqttUrl      = DEFAULT_MQTT_URL,
                                          .mqttPort     = DEFAULT_MQTT_PORT,
                                          .mqttUser     = DEFAULT_MQTT_USER,
                                          .mqttPassword = DEFAULT_MQTT_PASSWORD,
                                          .mqttPub      = DEFAULT_MQTT_PUBLISH,
                                          .mqttSub      = DEFAULT_MQTT_SUBSCRIBE,
                                          .mqttPubLog = DEFAULT_MQTT_LOG_PUBLISH_TOPIC, // Set in logging configuration
                                          .mqttClientId = DEFAULT_MQTT_CLIENT_ID,

                                          // Multicast
                                          .enableMulticast = DEFAULT_MULTICAST_ENABLE,
                                          .multicastUrl    = DEFAULT_MULTICAST_URL,
                                          .multicastPort   = DEFAULT_MULTICAST_PORT,
                                          .multicastTtl    = DEFAULT_MULTICAST_TTL,

                                          // UDP
                                          .enableUdp   = DEFAULT_UDP_ENABLE,
                                          .enableUdpRx = DEFAULT_UDP_RX_ENABLE,
                                          .enableUdpTx = DEFAULT_UDP_TX_ENABLE,
                                          .udpUrl      = DEFAULT_UDP_URL,
                                          .udpPort     = DEFAULT_UDP_PORT };

transport_t tr_tcpsrv[MAX_TCP_CONNECTIONS] = {}; // tcp/ip (VSCP link protocol)
transport_t tr_mqtt                        = {}; // MQTT
transport_t tr_multicast                   = {}; // Multicast
transport_t tr_udp                         = {}; // UDP

SemaphoreHandle_t ctrl_task_sem;

// CAN/TWAI

// static const twai_timing_config_t t_config = TWAI_TIMING_CONFIG_125KBITS();
// static const twai_filter_config_t f_config = TWAI_FILTER_CONFIG_ACCEPT_ALL();
// static const twai_general_config_t g_config = TWAI_GENERAL_CONFIG_DEFAULT(TX_GPIO_NUM, RX_GPIO_NUM,
// TWAI_MODE_NORMAL);

static QueueHandle_t tr_twai_tx;
static QueueHandle_t tr_twai_rx;

// Web server
static httpd_handle_t server = NULL;

#if CONFIG_WCANG_PROV_SECURITY_VERSION_2

#if CONFIG_WCANG_PROV_SEC2_DEV_MODE
#define WCANG_PROV_SEC2_USERNAME "testuser"
#define WCANG_PROV_SEC2_PWD      "testpassword"

/* This salt,verifier has been generated for username = "testuser" and password = "testpassword"
 * IMPORTANT NOTE: For production cases, this must be unique to every device
 * and should come from device manufacturing partition.*/
static const char sec2_salt[] = { 0x2f, 0x3d, 0x3c, 0xf8, 0x0d, 0xbd, 0x0c, 0xa9,
                                  0x6f, 0x30, 0xb4, 0x4d, 0x89, 0xd5, 0x2f, 0x0e };

// 24*16 = 384 * 8 = 3072
static const char sec2_verifier[] = {
  0xf2, 0x9f, 0xc1, 0xf5, 0x28, 0x4a, 0x11, 0x74, 0xb4, 0x24, 0x09, 0x23, 0xd8, 0x27, 0xb7, 0x5a, 0x95, 0x3a, 0x99,
  0xed, 0xf4, 0x6e, 0xe9, 0x8c, 0x4f, 0x07, 0xf2, 0xf5, 0x43, 0x3d, 0x7f, 0x9a, 0x11, 0x60, 0x66, 0xaf, 0xcd, 0xa5,
  0xf6, 0xfa, 0xcb, 0x06, 0xe9, 0xc5, 0x3f, 0x4d, 0x77, 0x16, 0x4c, 0x68, 0x6d, 0x7f, 0x7c, 0xd7, 0xc7, 0x5a, 0x83,
  0xc0, 0xfb, 0x94, 0x2d, 0xa9, 0x60, 0xf0, 0x09, 0x11, 0xa0, 0xe1, 0x95, 0x33, 0xd1, 0x30, 0x7f, 0x82, 0x1b, 0x1b,
  0x0f, 0x6d, 0xf1, 0xdc, 0x93, 0x1c, 0x20, 0xa7, 0xc0, 0x8d, 0x48, 0x38, 0xff, 0x46, 0xb9, 0xaf, 0xf7, 0x93, 0x78,
  0xae, 0xff, 0xb8, 0x3b, 0xdf, 0x99, 0x7b, 0x64, 0x47, 0x02, 0xba, 0x01, 0x39, 0x0f, 0x5c, 0xd8, 0x4e, 0x6f, 0xc8,
  0xd0, 0x82, 0x7f, 0x2d, 0x33, 0x1a, 0x09, 0x65, 0x77, 0x85, 0xbc, 0x8a, 0x84, 0xe0, 0x46, 0x7e, 0x3b, 0x0e, 0x6e,
  0x3b, 0xdf, 0x70, 0x17, 0x70, 0x0a, 0xbc, 0x84, 0x67, 0xfa, 0xf9, 0x84, 0x53, 0xda, 0xb4, 0xca, 0x38, 0x71, 0xe4,
  0x06, 0xf6, 0x7d, 0xc8, 0x32, 0xbb, 0x91, 0x0c, 0xe7, 0xd3, 0x59, 0xb6, 0x03, 0xed, 0x8e, 0x0d, 0x91, 0x9c, 0x09,
  0xd7, 0x6f, 0xd5, 0xca, 0x55, 0xc5, 0x58, 0x0f, 0x95, 0xb5, 0x83, 0x65, 0x6f, 0x2d, 0xbc, 0x94, 0x0f, 0xbb, 0x0f,
  0xd3, 0x42, 0xa5, 0xfe, 0x15, 0x7f, 0xf9, 0xa8, 0x16, 0xe6, 0x58, 0x9b, 0x4c, 0x0f, 0xd3, 0x83, 0x2c, 0xac, 0xe4,
  0xbf, 0xa3, 0x96, 0x1e, 0xb6, 0x6f, 0x59, 0xe6, 0xd1, 0x0e, 0xd4, 0x27, 0xb6, 0x05, 0x34, 0xec, 0x8c, 0xf8, 0x72,
  0xbb, 0x04, 0x7b, 0xa4, 0x49, 0x3d, 0x6d, 0xa9, 0x99, 0xfc, 0x0a, 0x2b, 0xd8, 0x46, 0xa8, 0xd1, 0x46, 0x61, 0x5c,
  0x96, 0xd2, 0x43, 0xcd, 0xea, 0x7f, 0x6a, 0x50, 0x59, 0x0d, 0x0e, 0xa1, 0xb3, 0x94, 0x5a, 0x34, 0xe0, 0x1e, 0x95,
  0x56, 0x68, 0xb4, 0xbc, 0xf1, 0x08, 0x54, 0xcb, 0x42, 0x41, 0xc6, 0x78, 0xad, 0x71, 0x84, 0x1c, 0x29, 0xb8, 0x33,
  0x79, 0x1c, 0x10, 0xdd, 0x07, 0xc8, 0x91, 0x21, 0x85, 0x89, 0x76, 0xd7, 0x37, 0xdf, 0x5b, 0x19, 0x33, 0x4e, 0x17,
  0x67, 0x02, 0x0f, 0x1b, 0xb9, 0x2f, 0xa4, 0xdc, 0xdd, 0x75, 0x32, 0x96, 0x87, 0xdd, 0x66, 0xc3, 0x33, 0xc1, 0xfc,
  0x4c, 0x27, 0x63, 0xb9, 0x14, 0x72, 0x76, 0x65, 0xb8, 0x90, 0x2b, 0xeb, 0x7a, 0xde, 0x71, 0x97, 0xf3, 0x6b, 0xc9,
  0x8e, 0xdf, 0xfc, 0x6e, 0x13, 0xcc, 0x1b, 0x2b, 0x54, 0x1a, 0x6e, 0x3d, 0xe6, 0x1c, 0xec, 0x5d, 0xa1, 0xf1, 0xd4,
  0x86, 0x9d, 0xcd, 0xb9, 0xe8, 0x98, 0xf1, 0xe5, 0x16, 0xa5, 0x48, 0xe5, 0xec, 0x12, 0xe8, 0x17, 0xe2, 0x55, 0xb5,
  0xb3, 0x7c, 0xce, 0xfd
};
#endif

///////////////////////////////////////////////////////////////////////////////
// wcang_get_sec2_salt
//

static esp_err_t
wcang_get_sec2_salt(const char **salt, uint16_t *salt_len)
{
#if CONFIG_WCANG_PROV_SEC2_DEV_MODE
  ESP_LOGI(TAG, "Development mode: using hard coded salt");
  *salt     = sec2_salt;
  *salt_len = sizeof(sec2_salt);
  return ESP_OK;
#elif CONFIG_WCANG_PROV_SEC2_PROD_MODE
  ESP_LOGE(TAG, "Not implemented!");
  return ESP_FAIL;
#endif
}

///////////////////////////////////////////////////////////////////////////////
// wcang_get_sec2_verifier
//

static esp_err_t
wcang_get_sec2_verifier(const char **verifier, uint16_t *verifier_len)
{
#if CONFIG_WCANG_PROV_SEC2_DEV_MODE
  ESP_LOGI(TAG, "Development mode: using hard coded verifier");
  *verifier     = sec2_verifier;
  *verifier_len = sizeof(sec2_verifier);
  return ESP_OK;
#elif CONFIG_WCANG_PROV_SEC2_PROD_MODE
  /* This code needs to be updated with appropriate implementation to provide verifier */
  ESP_LOGE(TAG, "Not implemented!");
  return ESP_FAIL;
#endif
}
#endif

///////////////////////////////////////////////////////////////////////////////
// initPersistentStorage (NVS)
//

void
initPersistentStorage(void)
{
  esp_err_t rv;
  size_t length;

  rv = nvs_open("config", NVS_READWRITE, &g_nvsHandle);
  if (rv != ESP_OK) {
    ESP_LOGE(TAG, "Error (%s) opening NVS handle!", esp_err_to_name(rv));
  }
  else {

    // * * * Module persistent configuration * * *

    NVS_GET_OR_SET_DEFAULT(u32, nvs_get_u32, nvs_set_u32, g_nvsHandle, "bootCnt", g_persistent.bootCnt, 0, TAG, "%d");

    ESP_LOGD(TAG, "Updating restart counter in NVS ... ");
    g_persistent.bootCnt++;

    // Write updated counter value to nvs
    rv = nvs_set_u32(g_nvsHandle, "restart_counter", g_persistent.bootCnt);
    if (rv != ESP_OK) {
      ESP_LOGI(TAG, "Failed to read restart counter!");
    }

    // Node name
    NVS_GET_OR_SET_DEFAULT_STR(g_nvsHandle, "nodeName", g_persistent.nodeName, DEFAULT_NODE_NAME, TAG);

    // Get GUID
    length = 16;
    rv     = nvs_get_blob(g_nvsHandle, "guid", g_persistent.guid, &length);
    switch (rv) {
      case ESP_OK:
        ESP_LOGI(TAG,
                 "GUID: %02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X",
                 g_persistent.guid[0],
                 g_persistent.guid[1],
                 g_persistent.guid[2],
                 g_persistent.guid[3],
                 g_persistent.guid[4],
                 g_persistent.guid[5],
                 g_persistent.guid[6],
                 g_persistent.guid[7],
                 g_persistent.guid[8],
                 g_persistent.guid[9],
                 g_persistent.guid[10],
                 g_persistent.guid[11],
                 g_persistent.guid[12],
                 g_persistent.guid[13],
                 g_persistent.guid[14],
                 g_persistent.guid[15]);
        break;

      case ESP_ERR_NVS_NOT_FOUND:
        ESP_LOGI(TAG, "GUID not found in nvs, writing default\n");
        memset(g_persistent.guid, 0, 16);
        break;

      default:
        ESP_LOGI(TAG, "Error (%s) reading GUID from nvs!\n", esp_err_to_name(rv));
        break;
    }

    // If GUID is all zero construct GUID
    if (!(g_persistent.guid[0] | g_persistent.guid[1] | g_persistent.guid[2] | g_persistent.guid[3] |
          g_persistent.guid[4] | g_persistent.guid[5] | g_persistent.guid[6] | g_persistent.guid[7] |
          g_persistent.guid[8] | g_persistent.guid[9] | g_persistent.guid[10] | g_persistent.guid[11] |
          g_persistent.guid[12] | g_persistent.guid[13] | g_persistent.guid[14] | g_persistent.guid[15])) {
      g_persistent.guid[0] = 0xff;
      g_persistent.guid[1] = 0xff;
      g_persistent.guid[2] = 0xff;
      g_persistent.guid[3] = 0xff;
      g_persistent.guid[4] = 0xff;
      g_persistent.guid[5] = 0xff;
      g_persistent.guid[6] = 0xff;
      g_persistent.guid[7] = 0xfe;
      rv                   = esp_efuse_mac_get_default(g_persistent.guid + 8);
      rv                   = nvs_set_blob(g_nvsHandle, "guid", g_persistent.guid, 16);
      ESP_LOGI(TAG,
               "Constructed GUID: %02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X",
               g_persistent.guid[0],
               g_persistent.guid[1],
               g_persistent.guid[2],
               g_persistent.guid[3],
               g_persistent.guid[4],
               g_persistent.guid[5],
               g_persistent.guid[6],
               g_persistent.guid[7],
               g_persistent.guid[8],
               g_persistent.guid[9],
               g_persistent.guid[10],
               g_persistent.guid[11],
               g_persistent.guid[12],
               g_persistent.guid[13],
               g_persistent.guid[14],
               g_persistent.guid[15]);
    }
  }

  // Primary key pmk
  length = 16;
  rv     = nvs_get_blob(g_nvsHandle, "pmk", g_persistent.pmk, &length);
  switch (rv) {
    case ESP_OK:
      ESP_LOGI(TAG, "Primary key: xxxxxxxxx reading from nvs");
      break;

    case ESP_ERR_NVS_NOT_FOUND:
      ESP_LOGI(TAG, "Primary key not found in nvs, writing default\n");
      memset(g_persistent.pmk, 0, 16);
      if (-1 != vscp_fwhlp_hex2bin(g_persistent.pmk, DEFAULT_KEY_LEN, VSCP_DEFAULT_KEY16)) {
        rv = nvs_set_blob(g_nvsHandle, "pmk", g_persistent.pmk, 16);
        if (rv != ESP_OK) {
          ESP_LOGE(TAG, "Failed to write primary key to nvs!");
        }
        else {
          ESP_LOGI(TAG, "Primary key set to default value");
        }
      }
      break;

    default:
      ESP_LOGI(TAG, "Error (%s) reading Primary key from nvs!\n", esp_err_to_name(rv));
      break;
  }

  // * * * Log persistent configuration * * *

  NVS_GET_OR_SET_DEFAULT(u8,
                         nvs_get_u8,
                         nvs_set_u8,
                         g_nvsHandle,
                         "logType",
                         g_persistent.logType,
                         DEFAULT_LOG_TYPE,
                         TAG,
                         "%d");

  NVS_GET_OR_SET_DEFAULT(u8,
                         nvs_get_u8,
                         nvs_set_u8,
                         g_nvsHandle,
                         "logRetries",
                         g_persistent.logRetries,
                         DEFAULT_LOG_RETRIES,
                         TAG,
                         "%d");

  NVS_GET_OR_SET_DEFAULT(u8,
                         nvs_get_u8,
                         nvs_set_u8,
                         g_nvsHandle,
                         "logLevel",
                         g_persistent.logLevel,
                         DEFAULT_LOG_LEVEL,
                         TAG,
                         "%d");

  NVS_GET_OR_SET_DEFAULT(u16,
                         nvs_get_u16,
                         nvs_set_u16,
                         g_nvsHandle,
                         "logPort",
                         g_persistent.logPort,
                         DEFAULT_LOG_PORT,
                         TAG,
                         "%d");

  NVS_GET_OR_SET_DEFAULT_STR(g_nvsHandle, "logUrl", g_persistent.logUrl, DEFAULT_LOG_URL, TAG);
  NVS_GET_OR_SET_DEFAULT_STR(g_nvsHandle,
                             "logMqttTopic",
                             g_persistent.logMqttTopic,
                             DEFAULT_MQTT_LOG_PUBLISH_TOPIC,
                             TAG);

  NVS_GET_OR_SET_DEFAULT(u8,
                         nvs_get_u8,
                         nvs_set_u8,
                         g_nvsHandle,
                         "logwrite2Stdout",
                         g_persistent.logwrite2Stdout,
                         DEFAULT_LOG_WRITE2STDOUT,
                         TAG,
                         "%d");

  // * * * Web server persistent configuration * * *

  NVS_GET_OR_SET_DEFAULT(u16,
                         nvs_get_u16,
                         nvs_set_u16,
                         g_nvsHandle,
                         "webPort",
                         g_persistent.webPort,
                         DEFAULT_WEBSERVER_PORT,
                         TAG,
                         "%d");

  NVS_GET_OR_SET_DEFAULT_STR(g_nvsHandle, "webUser", g_persistent.webUser, DEFAULT_WEBSERVER_USER, TAG);
  NVS_GET_OR_SET_DEFAULT_STR(g_nvsHandle, "webPassword", g_persistent.webPassword, DEFAULT_WEBSERVER_PASSWORD, TAG);

  // * * * VSCP link persistent configuration * * *
  NVS_GET_OR_SET_DEFAULT(u8,
                         nvs_get_u8,
                         nvs_set_u8,
                         g_nvsHandle,
                         "enableVscpLink",
                         g_persistent.enableVscpLink,
                         DEFAULT_VSCP_LINK_ENABLE,
                         TAG,
                         "%d");

  NVS_GET_OR_SET_DEFAULT(u16,
                         nvs_get_u16,
                         nvs_set_u16,
                         g_nvsHandle,
                         "vscplinkPort",
                         g_persistent.vscplinkPort,
                         DEFAULT_VSCP_LINK_PORT,
                         TAG,
                         "%d");

  NVS_GET_OR_SET_DEFAULT_STR(g_nvsHandle, "vscplinkUser", g_persistent.vscplinkUser, DEFAULT_VSCP_LINK_USER, TAG);
  NVS_GET_OR_SET_DEFAULT_STR(g_nvsHandle,
                             "vscplinkPassword",
                             g_persistent.vscplinkPassword,
                             DEFAULT_VSCP_LINK_PASSWORD,
                             TAG);

  // * * * MQTT persistent configuration * * *

  NVS_GET_OR_SET_DEFAULT(u8,
                         nvs_get_u8,
                         nvs_set_u8,
                         g_nvsHandle,
                         "enableMqtt",
                         g_persistent.enableMqtt,
                         DEFAULT_MQTT_ENABLE,
                         TAG,
                         "%d");

  NVS_GET_OR_SET_DEFAULT(u16,
                         nvs_get_u16,
                         nvs_set_u16,
                         g_nvsHandle,
                         "mqttPort",
                         g_persistent.mqttPort,
                         DEFAULT_MQTT_PORT,
                         TAG,
                         "%d");

  NVS_GET_OR_SET_DEFAULT_STR(g_nvsHandle, "mqttUrl", g_persistent.mqttUrl, DEFAULT_MQTT_URL, TAG);
  NVS_GET_OR_SET_DEFAULT_STR(g_nvsHandle, "mqttUser", g_persistent.mqttUser, DEFAULT_MQTT_USER, TAG);
  NVS_GET_OR_SET_DEFAULT_STR(g_nvsHandle, "mqttPassword", g_persistent.mqttPassword, DEFAULT_MQTT_PASSWORD, TAG);

  NVS_GET_OR_SET_DEFAULT_STR(g_nvsHandle, "mqttPub", g_persistent.mqttPub, DEFAULT_MQTT_PUBLISH, TAG);
  NVS_GET_OR_SET_DEFAULT_STR(g_nvsHandle, "mqttSub", g_persistent.mqttSub, DEFAULT_MQTT_SUBSCRIBE, TAG);
  NVS_GET_OR_SET_DEFAULT_STR(g_nvsHandle, "mqttPubLog", g_persistent.mqttPubLog, DEFAULT_MQTT_LOG_PUBLISH_TOPIC, TAG);
  NVS_GET_OR_SET_DEFAULT_STR(g_nvsHandle, "mqttClientId", g_persistent.mqttClientId, DEFAULT_MQTT_CLIENT_ID, TAG);

  // * * * Multicast persistent configuration * * *
  NVS_GET_OR_SET_DEFAULT(u8,
                         nvs_get_u8,
                         nvs_set_u8,
                         g_nvsHandle,
                         "enableMulticast",
                         g_persistent.enableMulticast,
                         DEFAULT_MULTICAST_ENABLE,
                         TAG,
                         "%d");

  NVS_GET_OR_SET_DEFAULT(u16,
                         nvs_get_u16,
                         nvs_set_u16,
                         g_nvsHandle,
                         "multicastPort",
                         g_persistent.multicastPort,
                         DEFAULT_MULTICAST_PORT,
                         TAG,
                         "%d");

  NVS_GET_OR_SET_DEFAULT(u8,
                         nvs_get_u8,
                         nvs_set_u8,
                         g_nvsHandle,
                         "multicastTtl",
                         g_persistent.multicastTtl,
                         DEFAULT_MULTICAST_TTL,
                         TAG,
                         "%d");

  // * * * UDP persistent configuration * * *

  NVS_GET_OR_SET_DEFAULT(u8,
                         nvs_get_u8,
                         nvs_set_u8,
                         g_nvsHandle,
                         "enableUdp",
                         g_persistent.enableUdp,
                         DEFAULT_UDP_ENABLE,
                         TAG,
                         "%d");

  NVS_GET_OR_SET_DEFAULT(u8,
                         nvs_get_u8,
                         nvs_set_u8,
                         g_nvsHandle,
                         "enableUdpRx",
                         g_persistent.enableUdpRx,
                         DEFAULT_UDP_RX_ENABLE,
                         TAG,
                         "%d");

  NVS_GET_OR_SET_DEFAULT(u8,
                         nvs_get_u8,
                         nvs_set_u8,
                         g_nvsHandle,
                         "enableUdpTx",
                         g_persistent.enableUdpTx,
                         DEFAULT_UDP_TX_ENABLE,
                         TAG,
                         "%d");

  NVS_GET_OR_SET_DEFAULT(u16,
                         nvs_get_u16,
                         nvs_set_u16,
                         g_nvsHandle,
                         "udpPort",
                         g_persistent.udpPort,
                         DEFAULT_UDP_PORT,
                         TAG,
                         "%d");

  NVS_GET_OR_SET_DEFAULT_STR(g_nvsHandle, "udpUrl", g_persistent.udpUrl, "255.255.255.255", TAG);

  //////////////////////////////////////////////////////////////////////////////////////
  // Commit written value.
  // After setting any values, nvs_commit() must be called to ensure changes are written
  // to flash storage. Implementations may write to storage at other times,
  // but this is not guaranteed.
  /////////////////////////////////////////////////////////////////////////////////////
  printf("Committing updates in NVS ... ");
  rv = nvs_commit(g_nvsHandle);
  if (rv != ESP_OK) {
    ESP_LOGE(TAG, "NVS commit faild at startup (%s)!", esp_err_to_name(rv));
  }
}

/* Signal Wi-Fi events on this event-group */
const int WIFI_CONNECTED_EVENT = BIT0;
static EventGroupHandle_t wifi_event_group;

#define PROV_QR_VERSION       "v1"
#define PROV_TRANSPORT_SOFTAP "softap"
#define PROV_TRANSPORT_BLE    "ble"
#define QRCODE_BASE_URL       "https://espressif.github.io/esp-jumpstart/qrcode.html"

///////////////////////////////////////////////////////////////////////////////
// startOTA
//

void
startOTA(void)
{
  ESP_LOGI(TAG, "Starting OTA firmware update...");

  // vscp_fwhlp_initiate_ota_update("http://firmware.vscp.org/firmware/vscp-din-wireless-esp32-can-z102-latest.bin");
}

///////////////////////////////////////////////////////////////////////////////
// app_initiate_firmware_upload
//

int
app_initiate_firmware_upload(const char *url)
{
  ESP_LOGI(TAG, "Starting firmware update from URL: %s", url);

  // vscp_fwhlp_initiate_ota_update(url);

  return VSCP_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// getMilliSeconds
//

uint32_t
getMilliSeconds(void)
{
  return (esp_timer_get_time() / 1000);
};

///////////////////////////////////////////////////////////////////////////////
// validate_user
//

bool
validate_user(const char *user, const char *pw)
{
  esp_err_t rv;
  size_t length;
  char username[VSCP_LINK_MAX_USER_NAME_LENGTH];
  char password[VSCP_LINK_MAX_PASSWORD_LENGTH];

  length = sizeof(username);
  rv     = nvs_get_str(g_nvsHandle, "username", username, &length);
  switch (rv) {

    case ESP_OK:
      break;

    case ESP_ERR_NVS_NOT_FOUND:
      ESP_LOGI(TAG, "Username not found in nvs\n");
      return false;

    default:
      ESP_LOGI(TAG, "Error (%s) reading username from nvs!\n", esp_err_to_name(rv));
      return false;
  }

  length = sizeof(password);
  rv     = nvs_get_str(g_nvsHandle, "password", password, &length);
  switch (rv) {

    case ESP_OK:
      break;

    case ESP_ERR_NVS_NOT_FOUND:
      ESP_LOGI(TAG, "Password not found in nvs\n");
      return false;

    default:
      ESP_LOGI(TAG, "Error (%s) reading password from nvs!\n", esp_err_to_name(rv));
      return false;
  }

  ESP_LOGI(TAG, "Credentials: %s=%s - %s=%s", username, user, password, pw);
  if (0 == strcmp(username, user) && 0 == strcmp(password, pw)) {
    return true;
  }

  return false;
}

bool
get_device_guid(uint8_t *pguid)
{
  esp_err_t rv;
  size_t length = 16;

  // Ceck pointer
  if (NULL == pguid) {
    return false;
  }

  rv = nvs_get_blob(g_nvsHandle, "guid", pguid, &length);
  switch (rv) {

    case ESP_OK:
      break;

    case ESP_ERR_NVS_NOT_FOUND:
      ESP_LOGW(TAG, "guid not found in nvs\n");
      return false;

    default:
      ESP_LOGI(TAG, "Error (%s) reading guid from nvs!\n", esp_err_to_name(rv));
      return false;
  }

  return true;
}

///////////////////////////////////////////////////////////////////////////////
// event_handler
//
// Event handler for catching system events
//

static void
event_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data)
{
#ifdef CONFIG_WCANG_RESET_PROV_MGR_ON_FAILURE
  static int retries;
#endif
  if (event_base == WIFI_PROV_EVENT) {
    switch (event_id) {
      case WIFI_PROV_START:
        ESP_LOGI(TAG, "Provisioning started");
        break;
      case WIFI_PROV_CRED_RECV: {
        wifi_sta_config_t *wifi_sta_cfg = (wifi_sta_config_t *) event_data;
        ESP_LOGI(TAG,
                 "Received Wi-Fi credentials"
                 "\n\tSSID     : %s\n\tPassword : %s",
                 (const char *) wifi_sta_cfg->ssid,
                 (const char *) wifi_sta_cfg->password);
        break;
      }
      case WIFI_PROV_CRED_FAIL: {
        wifi_prov_sta_fail_reason_t *reason = (wifi_prov_sta_fail_reason_t *) event_data;
        ESP_LOGE(TAG,
                 "Provisioning failed!\n\tReason : %s"
                 "\n\tPlease reset to factory and retry provisioning",
                 (*reason == WIFI_PROV_STA_AUTH_ERROR) ? "Wi-Fi station authentication failed"
                                                       : "Wi-Fi access-point not found");
#ifdef CONFIG_WCANG_RESET_PROV_MGR_ON_FAILURE
        retries++;
        if (retries >= CONFIG_WCANG_PROV_MGR_MAX_RETRY_CNT) {
          ESP_LOGI(TAG, "Failed to connect with provisioned AP, reseting provisioned credentials");
          wifi_prov_mgr_reset_sm_state_on_failure();
          retries = 0;
        }
#endif
        break;
      }
      case WIFI_PROV_CRED_SUCCESS:
        ESP_LOGI(TAG, "Provisioning successful");
#ifdef CONFIG_WCANG_RESET_PROV_MGR_ON_FAILURE
        retries = 0;
#endif
        break;
      case WIFI_PROV_END:
        /* De-initialize manager once provisioning is finished */
        wifi_prov_mgr_deinit();
        break;
      default:
        break;
    }
  }
  else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
    esp_wifi_connect();
  }
  else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
    ip_event_got_ip_t *event = (ip_event_got_ip_t *) event_data;
    ESP_LOGI(TAG, "Connected with IP Address:" IPSTR, IP2STR(&event->ip_info.ip));
    /* Signal main application to continue execution */
    xEventGroupSetBits(wifi_event_group, WIFI_CONNECTED_EVENT);
  }
  else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
    ESP_LOGI(TAG, "Disconnected. Connecting to the AP again...");
    esp_wifi_connect();
  }
}

///////////////////////////////////////////////////////////////////////////////
// wifi_init_sta
//

static void
wifi_init_sta(void)
{
  /* Start Wi-Fi in station mode */
  ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
  ESP_ERROR_CHECK(esp_wifi_start());
}

///////////////////////////////////////////////////////////////////////////////
// get_device_service_name
//

static void
get_device_service_name(char *service_name, size_t max)
{
  uint8_t eth_mac[6];
  const char *ssid_prefix = "PROV_";
  esp_wifi_get_mac(WIFI_IF_STA, eth_mac);
  snprintf(service_name, max, "%s%02X%02X%02X", ssid_prefix, eth_mac[3], eth_mac[4], eth_mac[5]);
}

///////////////////////////////////////////////////////////////////////////////
// custom_prov_data_handler
//
// Handler for the optional provisioning endpoint registered by the application.
// The data format can be chosen by applications. Here, we are using plain ascii text.
// Applications can choose to use other formats like protobuf, JSON, XML, etc.
//

esp_err_t
custom_prov_data_handler(uint32_t session_id,
                         const uint8_t *inbuf,
                         ssize_t inlen,
                         uint8_t **outbuf,
                         ssize_t *outlen,
                         void *priv_data)
{
  if (inbuf) {
    ESP_LOGI(TAG, "Received data: %.*s", inlen, (char *) inbuf);
  }

  char response[] = "SUCCESS";
  *outbuf         = (uint8_t *) strdup(response);

  if (*outbuf == NULL) {
    ESP_LOGE(TAG, "System out of memory");
    return ESP_ERR_NO_MEM;
  }

  *outlen = strlen(response) + 1; /* +1 for NULL terminating byte */

  return ESP_OK;
}

///////////////////////////////////////////////////////////////////////////////
// wifi_prov_print_qr
//

static void
wifi_prov_print_qr(const char *name, const char *username, const char *pop, const char *transport)
{
  if (!name || !transport) {
    ESP_LOGW(TAG, "Cannot generate QR code payload. Data missing.");
    return;
  }
  char payload[150] = { 0 };
  if (pop) {
#if CONFIG_WCANG_PROV_SECURITY_VERSION_1
    snprintf(payload,
             sizeof(payload),
             "{\"ver\":\"%s\",\"name\":\"%s\""
             ",\"pop\":\"%s\",\"transport\":\"%s\"}",
             PROV_QR_VERSION,
             name,
             pop,
             transport);
#elif CONFIG_WCANG_PROV_SECURITY_VERSION_2
    snprintf(payload,
             sizeof(payload),
             "{\"ver\":\"%s\",\"name\":\"%s\""
             ",\"username\":\"%s\",\"pop\":\"%s\",\"transport\":\"%s\"}",
             PROV_QR_VERSION,
             name,
             username,
             pop,
             transport);
#endif
  }
  else {
    snprintf(payload,
             sizeof(payload),
             "{\"ver\":\"%s\",\"name\":\"%s\""
             ",\"transport\":\"%s\"}",
             PROV_QR_VERSION,
             name,
             transport);
  }
#ifdef CONFIG_WCANG_PROV_SHOW_QR
  ESP_LOGI(TAG, "Scan this QR code from the provisioning application for Provisioning.");
  esp_qrcode_config_t cfg = ESP_QRCODE_CONFIG_DEFAULT();
  esp_qrcode_generate(&cfg, payload);
#endif /* CONFIG_APP_WIFI_PROV_SHOW_QR */
  ESP_LOGI(TAG,
           "If QR code is not visible, copy paste the below URL in a browser.\n%s?data=%s",
           QRCODE_BASE_URL,
           payload);
}

///////////////////////////////////////////////////////////////////////////////
// app_main
//

void
app_main(void)
{
  // Initialize NVS partition
  esp_err_t rv = nvs_flash_init();
  if (rv == ESP_ERR_NVS_NO_FREE_PAGES || rv == ESP_ERR_NVS_NEW_VERSION_FOUND) {

    // NVS partition was truncated
    // and needs to be erased
    ESP_ERROR_CHECK(nvs_flash_erase());

    // Retry nvs_flash_init
    ESP_ERROR_CHECK(nvs_flash_init());
  }

  // Create microsecond timer
  // ESP_ERROR_CHECK(esp_timer_create());

  // Start timer
  // esp_timer_start_periodic();

  // Initialize TCP/IP
  ESP_ERROR_CHECK(esp_netif_init());

  // Initialize the event loop
  ESP_ERROR_CHECK(esp_event_loop_create_default());
  wifi_event_group = xEventGroupCreate();

  gpio_config_t io_conf = {};

  // Disable interrupt
  io_conf.intr_type = GPIO_INTR_DISABLE;

  // Set as output mode
  io_conf.mode = GPIO_MODE_OUTPUT;

  // Bit mask of the pins that you want to be able to set
  io_conf.pin_bit_mask = GPIO_OUTPUT_PIN_SEL;

  // Disable pull-down mode
  io_conf.pull_down_en = 0;

  // Disable pull-up mode
  io_conf.pull_up_en = 0;

  // Configure GPIO with the given settings
  gpio_config(&io_conf);

  gpio_set_level(CONNECTED_LED_GPIO_NUM, 1);
  gpio_set_level(ACTIVE_LED_GPIO_NUM, 1);

  // TWAI message buffers
  tr_twai_rx = xQueueCreate(10, sizeof(twai_message_t)); // Incoming CAN
  tr_twai_tx = xQueueCreate(40, sizeof(twai_message_t)); // Outgoing CAN (All fills)
  for (int i = 0; i < MAX_TCP_CONNECTIONS; i++) {
    tr_tcpsrv[i].msg_queue = xQueueCreate(10, sizeof(twai_message_t)); // tcp/ip link channel i
  }
  tr_mqtt.msg_queue = xQueueCreate(10, sizeof(twai_message_t)); // MQTT empties
  // QueueHandle_t test = xQueueCreate(10, sizeof( twai_message_t) );

  tr_multicast.msg_queue = xQueueCreate(10, sizeof(twai_message_t)); // Multicast empties
  tr_udp.msg_queue       = xQueueCreate(10, sizeof(twai_message_t)); // UDP empties

  ctrl_task_sem = xSemaphoreCreateBinary();

  // Register our event handler for Wi-Fi, IP and Provisioning related events
  ESP_ERROR_CHECK(esp_event_handler_register(WIFI_PROV_EVENT, ESP_EVENT_ANY_ID, &event_handler, NULL));
  ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &event_handler, NULL));
  ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &event_handler, NULL));

  // Initialize Wi-Fi including netif with default config
  esp_netif_create_default_wifi_sta();

#ifdef CONFIG_WCANG_PROV_TRANSPORT_SOFTAP
  esp_netif_create_default_wifi_ap();
#endif // CONFIG_WCANG_PROV_TRANSPORT_SOFTAP

  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  ESP_ERROR_CHECK(esp_wifi_init(&cfg));

  // --------------------------------------------------------
  //                      Provisioning
  // --------------------------------------------------------

  // Configuration for the provisioning manager
  wifi_prov_mgr_config_t config = {
  // What is the Provisioning Scheme that we want ?
  // wifi_prov_scheme_softap or wifi_prov_scheme_ble
#ifdef CONFIG_WCANG_PROV_TRANSPORT_BLE
    .scheme = wifi_prov_scheme_ble,
#endif // CONFIG_WCANG_PROV_TRANSPORT_BLE
#ifdef CONFIG_WCANG_PROV_TRANSPORT_SOFTAP
    .scheme = wifi_prov_scheme_softap,
#endif // CONFIG_WCANG_PROV_TRANSPORT_SOFTAP

  /*
   * Any default scheme specific event handler that you would
   * like to choose. Since our example application requires
   * neither BT nor BLE, we can choose to release the associated
   * memory once provisioning is complete, or not needed
   * (in case when device is already provisioned). Choosing
   * appropriate scheme specific event handler allows the manager
   * to take care of this automatically. This can be set to
   * WIFI_PROV_EVENT_HANDLER_NONE when using wifi_prov_scheme_softap
   */
#ifdef CONFIG_WCANG_PROV_TRANSPORT_BLE
    .scheme_event_handler = WIFI_PROV_SCHEME_BLE_EVENT_HANDLER_FREE_BTDM
#endif /* CONFIG_WCANG_PROV_TRANSPORT_BLE */
#ifdef CONFIG_WCANG_PROV_TRANSPORT_SOFTAP
                              .scheme_event_handler = WIFI_PROV_EVENT_HANDLER_NONE
#endif /* CONFIG_WCANG_PROV_TRANSPORT_SOFTAP */
  };

  /*
   * Initialize provisioning manager with the
   * configuration parameters set above
   */
  ESP_ERROR_CHECK(wifi_prov_mgr_init(config));

  bool provisioned = false;
#ifdef CONFIG_WCANG_RESET_PROVISIONED
  wifi_prov_mgr_reset_provisioning();
#else
  /* Let's find out if the device is provisioned */
  ESP_ERROR_CHECK(wifi_prov_mgr_is_provisioned(&provisioned));

#endif

  /* If device is not yet provisioned start provisioning service */
  if (!provisioned) {

    ESP_LOGI(TAG, "Starting provisioning");

    /*
     * What is the Device Service Name that we want
     *
     * This translates to :
     *     - Wi-Fi SSID when scheme is wifi_prov_scheme_softap
     *     - device name when scheme is wifi_prov_scheme_ble
     */
    char service_name[12];
    get_device_service_name(service_name, sizeof(service_name));

#ifdef CONFIG_WCANG_PROV_SECURITY_VERSION_1
    /*
     * What is the security level that we want (0, 1, 2):
     *
     *   - WIFI_PROV_SECURITY_0 is simply plain text communication.
     *   - WIFI_PROV_SECURITY_1 is secure communication which consists of secure handshake
     *      using X25519 key exchange and proof of possession (pop) and AES-CTR
     *      for encryption/decryption of messages.
     *   - WIFI_PROV_SECURITY_2 SRP6a based authentication and key exchange
     *      + AES-GCM encryption/decryption of messages
     */
    wifi_prov_security_t security = WIFI_PROV_SECURITY_1;

    /*
     * Do we want a proof-of-possession (ignored if Security 0 is selected):
     *   - this should be a string with length > 0
     *   - NULL if not used
     */
    const char *pop = "VSCP-CAN4VSCP-GATEWAY-WiFi";
    /*
     * If the pop is allocated dynamically, then it should be valid till
     * the provisioning process is running.
     * it can be only freed when the WIFI_PROV_END event is triggered
     */

    /*
     * This is the structure for passing security parameters
     * for the protocomm security 1.
     * This does not need not be static i.e. could be dynamically allocated
     */
    wifi_prov_security1_params_t *sec_params = pop;

    const char *username = NULL;

#elif CONFIG_WCANG_PROV_SECURITY_VERSION_2
    wifi_prov_security_t security = WIFI_PROV_SECURITY_2;
    // The username must be the same one, which has been used in the generation of salt and verifier

#if CONFIG_WCANG_PROV_SEC2_DEV_MODE
    /*
     * This pop field represents the password that will be used to generate salt and verifier.
     * The field is present here in order to generate the QR code containing password.
     * In production this password field shall not be stored on the device
     */
    const char *username = WCANG_PROV_SEC2_USERNAME;
    const char *pop      = WCANG_PROV_SEC2_PWD;
#elif CONFIG_WCANG_PROV_SEC2_PROD_MODE
    /*
     * The username and password shall not be embedded in the firmware,
     * they should be provided to the user by other means.
     * e.g. QR code sticker
     */
    const char *username = NULL;
    const char *pop      = NULL;
#endif
    /*
     * This is the structure for passing security parameters
     * for the protocomm security 2.
     * This does not need not be static i.e. could be dynamically allocated
     */
    wifi_prov_security2_params_t sec2_params = {};

    ESP_ERROR_CHECK(wcang_get_sec2_salt(&sec2_params.salt, &sec2_params.salt_len));
    ESP_ERROR_CHECK(wcang_get_sec2_verifier(&sec2_params.verifier, &sec2_params.verifier_len));

    wifi_prov_security2_params_t *sec_params = &sec2_params;
#endif

    /*
     * What is the service key (could be NULL)
     * This translates to :
     *     - Wi-Fi password when scheme is wifi_prov_scheme_softap
     *          (Minimum expected length: 8, maximum 64 for WPA2-PSK)
     *     - simply ignored when scheme is wifi_prov_scheme_ble
     */
    const char *service_key = NULL;

#ifdef CONFIG_WCANG_PROV_TRANSPORT_BLE
    /*
     * This step is only useful when scheme is wifi_prov_scheme_ble. This will
     * set a custom 128 bit UUID which will be included in the BLE advertisement
     * and will correspond to the primary GATT service that provides provisioning
     * endpoints as GATT characteristics. Each GATT characteristic will be
     * formed using the primary service UUID as base, with different auto assigned
     * 12th and 13th bytes (assume counting starts from 0th byte). The client side
     * applications must identify the endpoints by reading the User Characteristic
     * Description descriptor (0x2901) for each characteristic, which contains the
     * endpoint name of the characteristic
     */
    uint8_t custom_service_uuid[] = {
      /*
       * LSB <---------------------------------------
       * ---------------------------------------> MSB
       */
      0xb4, 0xdf, 0x5a, 0x1c, 0x3f, 0x6b, 0xf4, 0xbf, 0xea, 0x4a, 0x82, 0x03, 0x04, 0x90, 0x1a, 0x02,
    };

    /*
     * If your build fails with linker errors at this point, then you may have
     * forgotten to enable the BT stack or BTDM BLE settings in the SDK (e.g. see
     * the sdkconfig.defaults in the example project)
     */
    wifi_prov_scheme_ble_set_service_uuid(custom_service_uuid);
#endif /* CONFIG_WCANG_PROV_TRANSPORT_BLE */

    /*
     * An optional endpoint that applications can create if they expect to
     * get some additional custom data during provisioning workflow.
     * The endpoint name can be anything of your choice.
     * This call must be made before starting the provisioning.
     */
    wifi_prov_mgr_endpoint_create("VSCP-WCANG");

    /* Start provisioning service */
    ESP_ERROR_CHECK(wifi_prov_mgr_start_provisioning(security, (const void *) sec_params, service_name, service_key));

    /*
     * The handler for the optional endpoint created above.
     * This call must be made after starting the provisioning, and only if the endpoint
     * has already been created above.
     */
    wifi_prov_mgr_endpoint_register("VSCP-WCANG", custom_prov_data_handler, NULL);

    /*
     * Uncomment the following to wait for the provisioning to finish and then release
     * the resources of the manager. Since in this case de-initialization is triggered
     * by the default event loop handler, we don't need to call the following
     */
    // wifi_prov_mgr_wait();
    // wifi_prov_mgr_deinit();

    /* Print QR code for provisioning */
#ifdef CONFIG_WCANG_PROV_TRANSPORT_BLE
    wifi_prov_print_qr(service_name, username, pop, PROV_TRANSPORT_BLE);
#else  /* CONFIG_WCANG_PROV_TRANSPORT_SOFTAP */
    wifi_prov_print_qr(service_name, username, pop, PROV_TRANSPORT_SOFTAP);
#endif /* CONFIG_WCANG_PROV_TRANSPORT_BLE */
  }
  else {
    ESP_LOGI(TAG, "Already provisioned, starting Wi-Fi STA");

    /*
     * We don't need the manager as device is already provisioned,
     * so let's release it's resources
     */
    wifi_prov_mgr_deinit();

    /* Start Wi-Fi station */
    wifi_init_sta();
  }

  /* Wait for Wi-Fi connection */
  xEventGroupWaitBits(wifi_event_group, WIFI_CONNECTED_EVENT, false, true, portMAX_DELAY);

  initPersistentStorage();

  // First start of web server
  server = start_webserver();

  // ***************************************************************************
  //                                   TWAI
  // ***************************************************************************

  // Install TWAI driver
  // ESP_ERROR_CHECK(twai_driver_install(&g_config, &t_config, &f_config));
  // ESP_LOGI(TAG, "Driver installed");

  // Start TWAI
  can4vscp_init(CAN4VSCP_125K);

  // if (config_server_get_can_mode() == VSCP2CAN_NORMAL) {
  // 	can4vscp_set_silent(0);
  // }
  // else
  // {
  // 	can4vscp_set_silent(1);
  // }

  can4vscp_setBitrate(CAN4VSCP_125K);
  can4vscp_enable();

  xTaskCreate(twai_receive_task, "can4vscp", 4096, &tr_twai_rx, 5, NULL);
  xSemaphoreGive(ctrl_task_sem);

  // Start the tcp/ip link server
  xTaskCreate(tcpsrv_task, "tcpsrv", 4096, (void *) AF_INET, 5, NULL);

#ifdef CONFIG_EXAMPLE_IPV6
  xTaskCreate(tcpsrv_task, "tcpsrv", 4096, (void *) AF_INET6, 5, NULL);
#endif

  // If the TWDT was not initialized automatically on startup, manually intialize it now
  esp_task_wdt_config_t wdconfig = {
    .timeout_ms     = 2000,
    .idle_core_mask = (1 << CONFIG_FREERTOS_NUMBER_OF_CORES) - 1, // Bitmask of all cores
    .trigger_panic  = false,

  };
  // esp_task_wdt_init(&wdconfig);

  /*
    Start main application loop now
  */

  while (1) {

    // esp_task_wdt_reset();

    twai_message_t msg = {};

    // Check if there is a TWAI message in the receive queue
    if (xQueueReceive(tr_twai_rx, &msg, portMAX_DELAY) == pdPASS) {

      ESP_LOGI(TAG, "--> Event fetched %X", (unsigned int) msg.identifier);
      UBaseType_t cnt = uxQueueMessagesWaiting(tr_twai_rx);
      ESP_LOGE(TAG, "count=%u %d", cnt, rv);

      // Now put the message in all open client queues
    }

    xSemaphoreTake(ctrl_task_sem, portMAX_DELAY);

    // ESP_LOGI(TAG, "Loop");
    xSemaphoreGive(ctrl_task_sem);
    vTaskDelay(1000 / portTICK_PERIOD_MS);
  }

  // Clean up

  // Close
  nvs_close(g_nvsHandle);
}
