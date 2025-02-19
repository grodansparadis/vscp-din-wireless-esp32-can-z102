/*
  File: main.c

  VSCP Wireless CAN4VSCP Gateway (VSCP-WCANG, Frankfurt-WiFi)

  This file is part of the VSCP (https://www.vscp.org)

  The MIT License (MIT)
  Copyright © 2022-2025 Ake Hedman, the VSCP project <info@vscp.org>

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
#include <driver/temperature_sensor.h>
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

#include "can4vscp.h"
#include "tcpsrv.h"
#include "udpclient.h"
#include "udpsrv.h"
#include "websrv.h"

#include "main.h"

static const char *TAG = "main";

/**!
 * Configer temperature sensor
 */
temperature_sensor_config_t cfgTempSensor = {
  .range_min = 20,
  .range_max = 50,
};

// Handle for nvs storage
nvs_handle_t nvsHandle;

// GUID for unit
uint8_t g_node_guid[16];

// transport_t tr_twai_tx = {};    // TWAI output
// transport_t tr_twai_rx = {};    // TWAI input
transport_t tr_tcpsrv[MAX_TCP_CONNECTIONS] = {};
// transport_t tr_tcpsrv0 = {};    // VSCP tcp/ip link protocol - channel 0
// transport_t tr_tcpsrv1 = {};    // VSCP tcp/ip link protocol - channel 1
transport_t tr_udpsrv    = {}; // UDP server
transport_t tr_udpclient = {}; // UDP client
transport_t tr_mqtt      = {}; // MQTT
transport_t tr_ws        = {}; // Websockets
transport_t tr_ble       = {}; // BLE
transport_t tr_uart      = {}; // UART

SemaphoreHandle_t ctrl_task_sem;

// static xdev_buffer ucTCP_RX_Buffer;
// static xdev_buffer ucTCP_TX_Buffer;

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

/* Signal Wi-Fi events on this event-group */
const int WIFI_CONNECTED_EVENT = BIT0;
static EventGroupHandle_t wifi_event_group;

#define PROV_QR_VERSION       "v1"
#define PROV_TRANSPORT_SOFTAP "softap"
#define PROV_TRANSPORT_BLE    "ble"
#define QRCODE_BASE_URL       "https://espressif.github.io/esp-jumpstart/qrcode.html"

///////////////////////////////////////////////////////////////////////////////
// read_onboard_temperature
//

float
read_onboard_temperature(void)
{
  // TODO
  return 0;
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
  rv     = nvs_get_str(nvsHandle, "username", username, &length);
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
  rv     = nvs_get_str(nvsHandle, "password", password, &length);
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

  ESP_LOGI(TAG, "Credentials: %s %s - %s %s", username, user, password, pw);
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

  rv = nvs_get_blob(nvsHandle, "guid", pguid, &length);
  switch (rv) {

    case ESP_OK:
      break;

    case ESP_ERR_NVS_NOT_FOUND:
      printf("guid not found in nvs\n");
      return false;

    default:
      printf("Error (%s) reading guid from nvs!\n", esp_err_to_name(rv));
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
  // static uint8_t uid[33];

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
  // tr_twai_rx.msg_queue = xQueueCreate(10, sizeof( twai_message_t) );    // Incoming CAN
  // tr_twai_tx.msg_queue = xQueueCreate(40, sizeof( twai_message_t) );    // Outgoing CAN (All fills)
  for (int i = 0; i < MAX_TCP_CONNECTIONS; i++) {
    tr_tcpsrv[i].msg_queue = xQueueCreate(10, sizeof(twai_message_t)); // tcp/ip link channel i
  }
  // tr_tcpsrv0.msg_queue = xQueueCreate(10, sizeof( twai_message_t) );     // tcp/ip link channel 0
  // tr_tcpsrv1.msg_queue = xQueueCreate(10, sizeof( twai_message_t) );     // tcp/ip link channel 1
  tr_udpsrv.msg_queue    = xQueueCreate(10, sizeof(twai_message_t)); // UDP srv
  tr_udpclient.msg_queue = xQueueCreate(10, sizeof(twai_message_t)); // UDP client
  tr_mqtt.msg_queue      = xQueueCreate(10, sizeof(twai_message_t)); // MQTT empties
  tr_ws.msg_queue        = xQueueCreate(10, sizeof(twai_message_t)); // websocket empties
  tr_ble.msg_queue       = xQueueCreate(10, sizeof(twai_message_t)); // BLE empties
  // QueueHandle_t test = xQueueCreate(10, sizeof( twai_message_t) );

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
    const char *pop = "VSCP-Frankfurt-WiFi";
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

  // **************************************************************************
  //                        NVS - Persistent storage
  // **************************************************************************

  // Init persistent storage

  rv = nvs_open("config", NVS_READWRITE, &nvsHandle);
  if (rv != ESP_OK) {
    printf("Error (%s) opening NVS handle!\n", esp_err_to_name(rv));
  }
  else {

    // Read
    printf("Reading restart counter from NVS ... ");
    int32_t restart_counter = 0; // value will default to 0, if not set yet in NVS

    rv = nvs_get_i32(nvsHandle, "restart_counter", &restart_counter);
    switch (rv) {

      case ESP_OK:
        printf("Restart counter = %d\n", (int) restart_counter);
        break;

      case ESP_ERR_NVS_NOT_FOUND:
        printf("The value is not initialized yet!\n");
        break;

      default:
        printf("Error (%s) reading!\n", esp_err_to_name(rv));
    }

    // Write
    printf("Updating restart counter in NVS ... ");
    restart_counter++;
    rv = nvs_set_i32(nvsHandle, "restart_counter", restart_counter);
    printf((rv != ESP_OK) ? "Failed!\n" : "Done\n");

    // Commit written value.
    // After setting any values, nvs_commit() must be called to ensure changes are written
    // to flash storage. Implementations may write to storage at other times,
    // but this is not guaranteed.
    printf("Committing updates in NVS ... ");
    rv = nvs_commit(nvsHandle);
    printf((rv != ESP_OK) ? "Failed!\n" : "Done\n");

    // TODO remove !!!!
    char username[32];
    char password[32];
    size_t length = sizeof(username);
    rv            = nvs_get_str(nvsHandle, "username", username, &length);
    switch (rv) {

      case ESP_OK:
        ESP_LOGI(TAG, "Username: %s", username);
        break;

      case ESP_ERR_NVS_NOT_FOUND:
        ESP_LOGI(TAG, "Username not found in nvs, writing default\n");
        rv = nvs_set_str(nvsHandle, "username", "vscp");
        break;

      default:
        ESP_LOGI(TAG, "Error (%s) reading username from nvs!\n", esp_err_to_name(rv));
        break;
    }

    length = sizeof(password);
    rv     = nvs_get_str(nvsHandle, "password", password, &length);
    switch (rv) {

      case ESP_OK:
        ESP_LOGI(TAG, "Password: %s", password);
        rv = nvs_set_str(nvsHandle, "password", "secret");
        break;

      case ESP_ERR_NVS_NOT_FOUND:
        ESP_LOGI(TAG, "Password not found in nvs, writing default\n");
        break;

      default:
        ESP_LOGI(TAG, "Error (%s) reading password from nvs!\n", esp_err_to_name(rv));
        break;
    }

    length = 16;
    rv     = nvs_get_blob(nvsHandle, "guid", g_node_guid, &length);
    switch (rv) {

      case ESP_OK:
        ESP_LOGI(TAG,
                 "GUID: %02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X",
                 g_node_guid[0],
                 g_node_guid[1],
                 g_node_guid[2],
                 g_node_guid[3],
                 g_node_guid[4],
                 g_node_guid[5],
                 g_node_guid[6],
                 g_node_guid[7],
                 g_node_guid[8],
                 g_node_guid[9],
                 g_node_guid[10],
                 g_node_guid[11],
                 g_node_guid[12],
                 g_node_guid[13],
                 g_node_guid[14],
                 g_node_guid[15]);
        break;

      case ESP_ERR_NVS_NOT_FOUND:
        ESP_LOGI(TAG, "GUID not found in nvs, writing default\n");
        memset(g_node_guid, 0, 16);
        break;

      default:
        ESP_LOGI(TAG, "Error (%s) reading GUID from nvs!\n", esp_err_to_name(rv));
        break;
    }

    // If GUID is all zero construct GUID
    if (!(g_node_guid[0] | g_node_guid[1] | g_node_guid[2] | g_node_guid[3] | g_node_guid[4] | g_node_guid[5] |
          g_node_guid[6] | g_node_guid[7] | g_node_guid[8] | g_node_guid[9] | g_node_guid[10] | g_node_guid[11] |
          g_node_guid[12] | g_node_guid[13] | g_node_guid[14] | g_node_guid[15])) {
      g_node_guid[0] = 0xff;
      g_node_guid[1] = 0xff;
      g_node_guid[2] = 0xff;
      g_node_guid[3] = 0xff;
      g_node_guid[4] = 0xff;
      g_node_guid[5] = 0xff;
      g_node_guid[6] = 0xff;
      g_node_guid[7] = 0xfe;
      rv             = esp_efuse_mac_get_default(g_node_guid + 8);
      rv             = nvs_set_blob(nvsHandle, "guid", g_node_guid, 16);
      ESP_LOGI(TAG,
               "Constructed GUID: %02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X",
               g_node_guid[0],
               g_node_guid[1],
               g_node_guid[2],
               g_node_guid[3],
               g_node_guid[4],
               g_node_guid[5],
               g_node_guid[6],
               g_node_guid[7],
               g_node_guid[8],
               g_node_guid[9],
               g_node_guid[10],
               g_node_guid[11],
               g_node_guid[12],
               g_node_guid[13],
               g_node_guid[14],
               g_node_guid[15]);
    }
  }

  // First start of web server
  server = start_webserver();

  // ***************************************************************************
  //                                   TWAI
  // ***************************************************************************

  // Install TWAI driver
  // ESP_ERROR_CHECK(twai_driver_install(&g_config, &t_config, &f_config));
  // ESP_LOGI(EXAMPLE_TAG, "Driver installed");

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

  xTaskCreate(twai_receive_task, "can4vscp", 4096, NULL /*&tr_twai_rx*/, 5, NULL);
  xSemaphoreGive(ctrl_task_sem);

  // Start UDP server
  // xTaskCreate(udpsrv_task, "udpsrv", 4096, (void*)AF_INET, 5, NULL);

  // Start the tcp/ip link server
  xTaskCreate(tcpsrv_task, "tcpsrv", 4096, (void *) AF_INET, 5, NULL);

#ifdef CONFIG_EXAMPLE_IPV6
  xTaskCreate(udpsrv_task, "udpsrv", 4096, (void *) AF_INET6, 5, NULL);
  xTaskCreate(tcpsrv_task, "tcpsrv", 4096, (void *) AF_INET6, 5, NULL);
#endif

  esp_task_wdt_config_t wdconfig;
  // If the TWDT was not initialized automatically on startup, manually intialize it now
  esp_task_wdt_config_t twdt_config = {
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
    // if( xQueueReceive( tr_twai_rx.msg_queue,
    //                      &msg,
    //                      portMAX_DELAY) == pdPASS ) {

    //   ESP_LOGI(TAG, "--> Event fetched %X", (unsigned int)msg.identifier);
    //   UBaseType_t cnt = uxQueueMessagesWaiting(tr_twai_rx.msg_queue);
    //   ESP_LOGI(TAG,"count=%u %d",cnt,rv);

    //   // Now put the message in all open client queues

    // }

    // xSemaphoreTake(ctrl_task_sem, portMAX_DELAY);

    // ESP_LOGI(TAG, "Loop");
    // xSemaphoreGive(ctrl_task_sem);
    // vTaskDelay(1000 / portTICK_PERIOD_MS);
  }

  // Clean up

  // Close
  nvs_close(nvsHandle);
}
