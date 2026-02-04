#include <esp_log.h>
#include <nvs.h>

/*
  VSCP Wireless CAN4VSCP Gateway (VSCP-WCANG)

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

#ifndef __VSCP_WCANG_H__
#define __VSCP_WCANG_H__

#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <freertos/queue.h>

#include "vscp.h"
#include "can4vscp.h"

#define TWAI_TX_GPIO_NUM GPIO_NUM_9  // CONFIG_EXAMPLE_TX_GPIO_NUM
#define TWAI_RX_GPIO_NUM GPIO_NUM_10 // GPIO_NUM_3 CONFIG_EXAMPLE_RX_GPIO_NUM

#define CONNECTED_LED_GPIO_NUM 0
#define ACTIVE_LED_GPIO_NUM    1
#define GPIO_OUTPUT_PIN_SEL    ((1ULL << CONNECTED_LED_GPIO_NUM) | (1ULL << ACTIVE_LED_GPIO_NUM))

#define DEV_BUFFER_LENGTH 64

// nvs macros

/*
NVS_GET_OR_SET_DEFAULT(
    u16, nvs_get_u16, nvs_set_u16,
    g_nvsHandle, "mqttPort", g_persistent.mqttPort, 1883, TAG, "%d"
);
*/
#define NVS_GET_OR_SET_DEFAULT(type, nvs_get_fn, nvs_set_fn, handle, key, var, defval, logtag, valfmt)                 \
  do {                                                                                                                 \
    esp_err_t _rv = nvs_get_fn((handle), (key), &(var));                                                               \
    switch (_rv) {                                                                                                     \
      case ESP_OK:                                                                                                     \
        ESP_LOGI((logtag), key ": " valfmt, (var));                                                                    \
        break;                                                                                                         \
      case ESP_ERR_NVS_NOT_FOUND:                                                                                      \
        ESP_LOGI((logtag), key " not found in nvs, writing default");                                                  \
        (var) = (defval);                                                                                              \
        nvs_set_fn((handle), (key), (defval));                                                                         \
        break;                                                                                                         \
      default:                                                                                                         \
        ESP_LOGI((logtag), "Error (%s) reading " key " from nvs!", esp_err_to_name(_rv));                              \
        break;                                                                                                         \
    }                                                                                                                  \
  } while (0)

/*
NVS_GET_OR_SET_DEFAULT_STR(g_nvsHandle, "webUser", g_persistent.webUser, "vscp", TAG);
*/
#define NVS_GET_OR_SET_DEFAULT_STR(handle, key, var, defval, logtag)                                                   \
  do {                                                                                                                 \
    size_t _len   = sizeof(var);                                                                                       \
    esp_err_t _rv = nvs_get_str((handle), (key), (var), &_len);                                                        \
    switch (_rv) {                                                                                                     \
      case ESP_OK:                                                                                                     \
        ESP_LOGI((logtag), key ": %s", (var));                                                                         \
        break;                                                                                                         \
      case ESP_ERR_NVS_NOT_FOUND:                                                                                      \
        ESP_LOGI((logtag), key " not found in nvs, writing default");                                                  \
        strncpy((var), (defval), sizeof(var));                                                                         \
        nvs_set_str((handle), (key), (defval));                                                                        \
        break;                                                                                                         \
      default:                                                                                                         \
        ESP_LOGI((logtag), "Error (%s) reading " key " from nvs!", esp_err_to_name(_rv));                              \
        break;                                                                                                         \
    }                                                                                                                  \
  } while (0)

// Defaults

typedef enum {
  CH_LINK = 0, // tcp/ip link protocol
  CH_CAN,      // CAN
  CH_WS,       // websocket I & II
  CH_UDP,      // UDP
  CH_MULTI,    // Multicast
  CH_MQTT,     // MQTT
  CH_BLE,      // BLE
  CH_UART      // UART
} dev_channel_t;

// All transports use this structure for state

typedef struct {
  union {
    struct {
      uint32_t active : 1;    /**< Transport active if set to one */
      uint32_t open : 1;      /**< Transport open if set to one */
      uint32_t reserved : 30; /**< Reserved bits */
    };
    uint32_t flags; /**< Don't use */
  };
  QueueHandle_t msg_queue; /**< Message queue for transport */
  uint32_t overruns;       /**< Queue overrun counter */

} transport_t;

/*!
  Default values stored in non volatile memory
  on start up.
*/

#define DEFAULT_KEY_LEN 32 // AES256
#define DEFAULT_GUID    "" // Empty constructs from MAC, "-" all nills, "xx:yy:..." set GUID

// BLE
#define DEFAULT_BLE_ENABLE       true
#define DEFAULT_ADVERTISE_ENABLE true

// TWAI
#define DEFAULT_TWAI_MODE  0 // CAN4VSCP_NORMAL
#define DEFAULT_TWAI_SPEED CAN4VSCP_125K
// #define TX_GPIO_NUM        GPIO_NUM_9  // CONFIG_EXAMPLE_TX_GPIO_NUM
// #define RX_GPIO_NUM        GPIO_NUM_10 // GPIO_NUM_3 CONFIG_EXAMPLE_RX_GPIO_NUM

// SMTP
#define DEFAULT_SMTP_ENABLE false

// OTA
#define DEFAULT_APP_OTA_URL_MAX_SIZE 128
#define DEFAULT_APP_OTA_URL          "http://vscp.org/firmware/vscp-can4vscp-gw/firmware.bin"

#define DEFAULT_TCPIP_VER 4 // Ipv6 = 6 or Ipv4 = 4
#define TCPSRV_WELCOME_MSG                                                                                             \
  "Welcome to the VSCP CAN4VSCP Gateway\r\n"                                                                           \
  "Copyright (C) 2000-2026 Grodans Paradis AB\r\n"                                                                     \
  "https://www.grodansparadis.com\r\n"                                                                                 \
  "+OK\r\n"

// Log types
#define LOG_TYPE_NONE 0
#define LOG_TYPE_STD  1
#define LOG_TYPE_UDP  2
#define LOG_TYPE_TCP  3
#define LOG_TYPE_HTTP 4
#define LOG_TYPE_MQTT 5
#define LOG_TYPE_VSCP 6

// Log levels
#define LOG_LEVEL_NONE    0 // No logging
#define LOG_LEVEL_ERROR   1 // Errors only
#define LOG_LEVEL_WARNING 2 // Warnings
#define LOG_LEVEL_INFO    3 // Information
#define LOG_LEVEL_DEBUG   4 // Debugging
#define LOG_LEVEL_VERBOSE 5 // Verbose debugging

// System defaults

#define DEFAULT_NODE_NAME "VSCP CAN4VSCP Gateway"
#define DEFAULT_LOG_URL   " "
#define DEFAULT_LOG_PORT  514

#define DEFAULT_LOG_TYPE         LOG_TYPE_STD
#define DEFAULT_LOG_LEVEL        0
#define DEFAULT_LOG_RETRIES      3
#define DEFAULT_LOG_WRITE2STDOUT false

#define DEFAULT_WEBSERVER_PORT     80
#define DEFAULT_WEBSERVER_USER     "vscp"
#define DEFAULT_WEBSERVER_PASSWORD "secret"

#define DEFAULT_VSCP_LINK_ENABLE   true
#define DEFAULT_VSCP_LINK_PORT     9598
#define DEFAULT_VSCP_LINK_USER     "vscp"
#define DEFAULT_VSCP_LINK_PASSWORD "secret"

#define DEFAULT_MQTT_ENABLE            false
#define DEFAULT_MQTT_URL               "mqtt://"
#define DEFAULT_MQTT_PORT              1883
#define DEFAULT_MQTT_USER              ""
#define DEFAULT_MQTT_PASSWORD          ""
#define DEFAULT_MQTT_PUBLISH           "vscp/{{guid}}/{{class}}/{{type}}/{{sindex}}"
#define DEFAULT_MQTT_SUBSCRIBE         "can4vscpgw/{{guid}}"
#define DEFAULT_MQTT_LOG_PUBLISH_TOPIC "can4vscpgw/{{guid}}/log"
#define DEFAULT_MQTT_CLIENT_ID         "vscp-can4vscpgw"

#define DEFAULT_MULTICAST_ENABLE false
#define DEFAULT_MULTICAST_URL    "224.0.23.158"
#define DEFAULT_MULTICAST_PORT   9598
#define DEFAULT_MULTICAST_TTL    10

#define DEFAULT_UDP_ENABLE    false
#define DEFAULT_UDP_RX_ENABLE false
#define DEFAULT_UDP_TX_ENABLE false
#define DEFAULT_UDP_URL       "255.255.255.255" // Broadcast
#define DEFAULT_UDP_PORT      9598

typedef struct {

  // Module
  char nodeName[32]; // User name for node
  uint8_t guid[16];  // GUID for node (default: Constructed from MAC address)
  uint8_t pmk[16];   // System security key for encryption (AES128)
  uint8_t pmkLen;    // For future use, Now always 16 (AES128)
  uint32_t bootCnt;  // Number of restarts (not editable)

  // Log
  uint8_t logType;         // Log type
  uint8_t logLevel;        // Log level
  uint8_t logRetries;      // Number of retries for log message send
  uint16_t logPort;        // Log server port
  char logUrl[80];         // Log server address
  char logMqttTopic[80];   // MQTT topic for log messages
  uint8_t logwrite2Stdout; // Write log to stdout

  // web server
  uint16_t webPort;     // Web server port
  char webUser[32];     // Web server user
  char webPassword[32]; // Web server password

  // VSCP link protocol
  uint8_t enableVscpLink;    // Enable VSCP link protocol
  uint16_t vscplinkPort;     // VSCP link protocol port
  char vscplinkUser[32];     // VSCP link protocol user
  char vscplinkPassword[32]; // VSCP link protocol password

  // MQTT
  uint8_t enableMqtt;    // Enable MQTT
  char mqttUrl[80];      // MQTT URL
  uint16_t mqttPort;     // MQTT port
  char mqttUser[32];     // MQTT username
  char mqttPassword[32]; // MQTT password
  char mqttPub[80];      // MQTT publish topic
  char mqttSub[80];      // MQTT subscribe topic
  char mqttPubLog[80];   // MQTT topic for log messages
  char mqttClientId[32]; // MQTT client ID

  // Multicast interface
  uint8_t enableMulticast; // Enable multicast
  char multicastUrl[20];   // Multicast IP address
  uint16_t multicastPort;  // Multicast port
  uint8_t multicastTtl;    // Multicast TTL

  // UDP interface
  uint8_t enableUdp;   // Enable UDP interface
  uint8_t enableUdpRx; // Enable UDP receive
  uint8_t enableUdpTx; // Enable UDP transmit
  char udpUrl[32];     // UDP IP address
  uint16_t udpPort;    // UDP port
} node_persistent_config_t;

/*!
 * @brief Initialize persistent storage (NVS)
 */
void
initPersistentStorage(void);

/**
 * @brief Read processor on chip temperature
 * @return Temperature as floating point value
 */
float
read_onboard_temperature(void);

/**
 * @fn getMilliSeconds
 * @brief Get system time in Milliseconds
 *
 * @return Systemtime in milliseconds
 */
uint32_t
getMilliSeconds(void);

/**
 * @fn validate_user
 * @brief Validate user
 *
 * @param user Username to check
 * @param password Password to check
 * @return True if user is valid, False if not.
 */
bool
validate_user(const char *user, const char *password);

#endif