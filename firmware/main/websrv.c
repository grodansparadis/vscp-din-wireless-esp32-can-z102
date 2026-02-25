/*
  Web Server

  This file is part of the VSCP (https://www.vscp.org)

  The MIT License (MIT)
  Copyright (C) 2022-2026 Ake Hedman, the VSCP project <info@vscp.org>

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
#include <sys/param.h>
#include <sys/unistd.h>
#include <sys/stat.h>
#include <dirent.h>

#include <esp_system.h>
#include <esp_chip_info.h>
#include <esp_flash_spi_init.h>
#include <esp_flash.h>
#include <esp_wifi.h>
#include <esp_mac.h>
#include <esp_ota_ops.h>
#include <esp_timer.h>
#include <esp_err.h>
#include <esp_log.h>
#include <nvs_flash.h>

#include <esp_event_base.h>
#include <esp_tls_crypto.h>
#include <esp_vfs.h>
#include <esp_spiffs.h>
#include <esp_http_server.h>
#include <wifi_provisioning/manager.h>

#include <vscp.h>
#include <vscp-firmware-helper.h>

#include "urldecode.h"

#include "mqtt.h"
#include "main.h"
#include "websrv.h"

#ifdef CONFIG_EXAMPLE_PROV_TRANSPORT_BLE
#include <wifi_provisioning/scheme_ble.h>
#endif /* PROV_EXAMPLE_TRANSPORT_BLE */

#ifdef CONFIG_EXAMPLE_PROV_TRANSPORT_SOFTAP
#include <wifi_provisioning/scheme_softap.h>
#endif /* PROV_EXAMPLE_TRANSPORT_SOFTAP */

// #define MIN(a, b) (((a) < (b)) ? (a) : (b))
// #define MAX(a, b) (((a) > (b)) ? (a) : (b))

// From app_main
void
startOTA(void);
int
app_initiate_firmware_upload(const char *url);

// External from main
extern nvs_handle_t g_nvsHandle;
extern node_persistent_config_t g_persistent;
extern vprintf_like_t g_stdLogFunc;
#define TAG __func__

// Max length a file path can have on storage
#define FILE_PATH_MAX (ESP_VFS_PATH_MAX + CONFIG_SPIFFS_OBJ_NAME_LEN)

// Chunk buffer size
#define CHUNK_BUFSIZE 8192

#define IS_FILE_EXT(filename, ext) (strcasecmp(&filename[strlen(filename) - sizeof(ext) + 1], ext) == 0)

// Prototypes

//-----------------------------------------------------------------------------
//                               Start Basic Auth
//-----------------------------------------------------------------------------

///////////////////////////////////////////////////////////////////////////////
// http_auth_basic
//

static char *
http_auth_basic(const char *username, const char *password)
{
  int out;
  char *user_info = NULL;
  char *digest    = NULL;
  size_t n        = 0;
  asprintf(&user_info, "%s:%s", username, password);
  if (!user_info) {
    ESP_LOGE(TAG, "No enough memory for user information");
    return NULL;
  }
  esp_crypto_base64_encode(NULL, 0, &n, (const unsigned char *) user_info, strlen(user_info));

  /* 6: The length of the "Basic " string
   * n: Number of bytes for a base64 encode format
   * 1: Number of bytes for a reserved which be used to fill zero
   */
  digest = calloc(6 + n + 1, 1);
  if (digest) {
    strcpy(digest, "Basic ");
    esp_crypto_base64_encode((unsigned char *) digest + 6,
                             n,
                             (size_t *) &out,
                             (const unsigned char *) user_info,
                             strlen(user_info));
  }
  free(user_info);
  return digest;
}

///////////////////////////////////////////////////////////////////////////////
// info_get_handler
//
// HTTP GET handler for info page
//

static esp_err_t
info_get_handler(httpd_req_t *req)
{
  // esp_err_t rv;
  char *buf;
  char *temp;

  buf = (char *) calloc(CHUNK_BUFSIZE, 1);
  if (NULL == buf) {
    return ESP_ERR_NO_MEM;
  }

  temp = (char *) calloc(80, 1);
  if (NULL == temp) {
    return ESP_ERR_NO_MEM;
  }

  esp_chip_info_t chip_info;
  esp_chip_info(&chip_info);

  const esp_app_desc_t *appDescr = esp_app_get_description();

  sprintf(buf, WEBPAGE_START_TEMPLATE, g_persistent.nodeName, "Technical Node Info");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "<table style='width:100%%;margin-left: auto; margin-right: auto;'>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  // * * * system * * *);
  sprintf(buf, "<tr><td class='infoheader'>System</td><td></td></tr>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "<tr style='padding: 25px;'><td class=\"name\">Chip type:</td>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
  switch (chip_info.model) {

    case CHIP_ESP32:
      // printf("ESP32\n");
      sprintf(buf, "<td class=\"prop\">ESP32</td></tr>");
      break;

    case CHIP_ESP32S2:
      // printf("ESP32-S2\n");
      sprintf(buf, "<td class=\"prop\">ESP32-S2</td></tr>");
      break;

    case CHIP_ESP32S3:
      // printf("ESP32-S3\n");
      sprintf(buf, "<td class=\"prop\">ESP32-S3</td></tr>");
      break;

    case CHIP_ESP32C3:
      // printf("ESP32-C3\n");
      sprintf(buf, "<td class=\"prop\">ESP32-C3</td></tr>");
      break;

    case CHIP_ESP32H2:
      // printf("ESP32-H2\n");
      sprintf(buf, "<td class=\"prop\">ESP32-H2</td></tr>");
      break;

    case CHIP_ESP32C2:
      // printf("ESP32-C2\n");
      sprintf(buf, "<td class=\"prop\">ESP32-C2</td></tr>");
      break;

    default:
      // printf("Unknown\n");
      sprintf(buf, "<td class=\"prop\">Unknown</td></tr>");
      break;
  }
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "<tr><td class=\"name\">Number of cores:</td><td class=\"prop\">%d</td></tr>", chip_info.cores);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  // printf("Number of cores: %d \n", chip_info.cores);

  // Chip comm features
  sprintf(temp,
          "%s%s%s%s",
          (chip_info.features & CHIP_FEATURE_WIFI_BGN) ? "WiFi " : "",
          (chip_info.features & CHIP_FEATURE_BT) ? "BT " : "",
          (chip_info.features & CHIP_FEATURE_BLE) ? "BLE " : "",
          (chip_info.features & CHIP_FEATURE_IEEE802154) ? "802.15.4 " : "");
  sprintf(buf, "<tr><td class=\"name\">Chip comm features:</td><td class=\"prop\">%s</td></tr>", temp);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  wifi_country_t country;
  esp_wifi_get_country(&country);
  // printf("Wifi country code: %c%c%c\n", country.cc[0],country.cc[1],country.cc[2]);
  sprintf(buf,
          "<tr><td class=\"name\">Wifi country code:</td><td class=\"prop\">%c%c%c</td></tr>",
          country.cc[0],
          country.cc[1],
          country.cc[2]);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(temp, "%s", (chip_info.features & CHIP_FEATURE_EMB_FLASH) ? "Yes" : "No");
  sprintf(buf, "<tr><td class=\"name\">Embedded flash:</td><td class=\"prop\">%s</td></tr>", temp);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(temp, "%s", (chip_info.features & CHIP_FEATURE_EMB_PSRAM) ? "Yes" : "No");
  sprintf(buf, "<tr><td class=\"name\">Embedded psram:</td><td class=\"prop\">%s</td></tr>", temp);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  // sprintf(temp, "%d", chip_info.revision);
  sprintf(buf, "<tr><td class=\"name\">Silicon revision:</td><td class=\"prop\">%d</td></tr>", chip_info.revision);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  uint32_t chipId;
  esp_flash_read_id(NULL, &chipId);
  // printf("Flash chip id: %04lX\n", chipId);
  sprintf(buf, "<tr><td class=\"name\">Flash chip id:</td><td class=\"prop\">%04lX</td></tr>", chipId);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  uint64_t uniqueId;
  esp_flash_read_unique_chip_id(NULL, &uniqueId);
  // printf("Unique flash chip id: %08llX\n", uniqueId);
  sprintf(buf, "<tr><td class=\"name\">Unique flash chip id:</td><td class=\"prop\">%08llX</td></tr>", uniqueId);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  uint32_t sizeFlash;
  esp_flash_get_size(NULL, &sizeFlash);
  sprintf(temp, "%s", (chip_info.features & CHIP_FEATURE_EMB_FLASH) ? "(embedded)" : "(external)");
  // printf("%luMB %s flash\n",
  //        sizeFlash / (1024 * 1024),
  //        (chip_info.features & CHIP_FEATURE_EMB_FLASH) ? "embedded" : "external");
  sprintf(buf,
          "<tr><td class=\"name\">Flash size:</td><td class=\"prop\">%s %lu MB</td></tr>",
          temp,
          sizeFlash / (1024 * 1024));
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  // get chip id
  // chipId = String((uint32_t) ESP.getEfuseMac(), HEX);
  // chipId.toUpperCase();
  // printf("Chip id: %s\n", chipId.c_str());

  // printf("esp-idf version: %s\n", esp_get_idf_version());
  sprintf(buf, "<tr><td class=\"name\">esp-idf version:</td><td class=\"prop\">%s</td></tr>", esp_get_idf_version());
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  // printf("Free heap size: %lu\n", esp_get_free_heap_size());
  sprintf(buf,
          "<tr><td class=\"name\">Free heap size:</td><td class=\"prop\">%lu kB (%lu)</td></tr>",
          esp_get_free_heap_size() / 1024,
          esp_get_free_heap_size());
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  // printf("Min free heap size: %lu\n", esp_get_minimum_free_heap_size());
  sprintf(buf,
          "<tr><td class=\"name\">Min free heap size:</td><td class=\"prop\">%lu kB (%lu)</td></tr>",
          esp_get_minimum_free_heap_size() / 1024,
          esp_get_minimum_free_heap_size());
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  // printf("Last reset reson: ");
  switch (esp_reset_reason()) {
    case ESP_RST_POWERON:
      sprintf(temp, "Reset due to power-on event.\n");
      break;
    case ESP_RST_EXT:
      sprintf(temp, "Reset by external pin (not applicable for ESP32.\n");
      break;
    case ESP_RST_SW:
      sprintf(temp, "Software reset via esp_restart.\n");
      break;
    case ESP_RST_PANIC:
      sprintf(temp, "Software reset due to exception/panic.\n");
      break;
    case ESP_RST_INT_WDT:
      sprintf(temp, "Reset (software or hardware) due to interrupt watchdog.\n");
      break;
    case ESP_RST_TASK_WDT:
      sprintf(temp, "Reset due to task watchdog.\n");
      break;
    case ESP_RST_WDT:
      sprintf(temp, "Reset due to other watchdogs.\n");
      break;
    case ESP_RST_DEEPSLEEP:
      sprintf(temp, "Reset after exiting deep sleep mode.\n");
      break;
    case ESP_RST_BROWNOUT:
      sprintf(temp, "Brownout reset (software or hardware.\n");
      break;
    case ESP_RST_SDIO:
      sprintf(temp, "Reset over SDIO.\n");
      break;
    case ESP_RST_UNKNOWN:
    default:
      sprintf(temp, "Reset reason can not be determined.\n");
      break;
  }
  sprintf(buf, "<tr><td class=\"name\">Last reset reson:</td><td class=\"prop\">%s</td></tr>", temp);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "<tr><td class=\"name\">Number of reboots:</td><td class=\"prop\">%lu</td></tr>", g_persistent.bootCnt);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  char *bufguid = (char *) calloc(50, 1);
  if (NULL != bufguid) {
    vscp_fwhlp_writeGuidToString(bufguid, g_persistent.guid);
    sprintf(buf, "<tr><td class=\"name\">GUID:</td><td class=\"prop\">%s<br>%s</td></tr>", bufguid, /*temp + 24*/ "1");
    httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
    free(bufguid);
  }

  // -------------------------------------------------------------------------

  // * * *  Application * * *
  // sprintf(buf, "<tr><td>Application</td><td></td></tr>");
  sprintf(buf, "<tr><td class='infoheader'>Application</td><td></td></tr>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  int time = esp_timer_get_time();
  sprintf(buf,
          "<tr><td class=\"name\">Uptime:</td><td class=\"prop\">%dT%02d:%02d:%02d</td></tr>",
          ((time / 1000000) / (3600 * 24)),
          ((time / 1000000) / 3600),
          ((time / 1000000) / 60),
          (time / 1000000));
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  if (NULL != appDescr) {
    // sprintf(temp,"%s",appDescr->project_name);
    sprintf(buf, "<tr><td class=\"name\">Application:</td><td class=\"prop\">%s</td></tr>", appDescr->project_name);
    httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

    // sprintf(temp,"Application ver: %s\n",appDescr->version);
    sprintf(buf, "<tr><td class=\"name\">Application ver:</td><td class=\"prop\">%s</td></tr>", appDescr->version);
    httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

    // sprintf(temp,"Application ver: %s %s\n",appDescr->date,appDescr->time);
    sprintf(buf,
            "<tr><td class=\"name\">Compile time:</td><td class=\"prop\">%s %s</td></tr>",
            appDescr->date,
            appDescr->time);
    httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

    // sprintf(temp,"idf ver: %s\n",appDescr->idf_ver);
    sprintf(buf, "<tr><td class=\"name\">Compiled w/ idf ver:</td><td class=\"prop\">%s</td></tr>", appDescr->idf_ver);
    httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
  }

  // * * *  CAN/TWAI * * *
  sprintf(buf, "<tr><td class='infoheader'>CAN/TWAI Interface</td><td></td></tr>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  // CAN Mode
  const char *canModeStr = (g_persistent.canMode == 0) ? "Normal" : "Listen Only";
  sprintf(buf, "<tr><td class=\"name\">CAN Mode:</td><td class=\"prop\">%s</td></tr>", canModeStr);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  // CAN Speed
  const char *canSpeedStr;
  switch (g_persistent.canSpeed) {
    case 0:
      canSpeedStr = "5 Kbps";
      break;
    case 1:
      canSpeedStr = "10 Kbps";
      break;
    case 2:
      canSpeedStr = "20 Kbps";
      break;
    case 3:
      canSpeedStr = "25 Kbps";
      break;
    case 4:
      canSpeedStr = "50 Kbps";
      break;
    case 5:
      canSpeedStr = "100 Kbps";
      break;
    case 6:
      canSpeedStr = "125 Kbps";
      break;
    case 7:
      canSpeedStr = "250 Kbps";
      break;
    case 8:
      canSpeedStr = "500 Kbps";
      break;
    case 9:
      canSpeedStr = "800 Kbps";
      break;
    case 10:
      canSpeedStr = "1000 Kbps";
      break;
    default:
      canSpeedStr = "Unknown";
      break;
  }
  sprintf(buf, "<tr><td class=\"name\">CAN Speed:</td><td class=\"prop\">%s</td></tr>", canSpeedStr);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  // CAN Filter
  sprintf(buf,
          "<tr><td class=\"name\">CAN Filter:</td><td class=\"prop\">0x%08X</td></tr>",
          (unsigned int) g_persistent.canFilter);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  // Messages Sent
  sprintf(buf,
          "<tr><td class=\"name\">Messages Sent:</td><td class=\"prop\">%u</td></tr>",
          (unsigned int) g_persistent.nSent);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  // Messages Received
  sprintf(buf,
          "<tr><td class=\"name\">Messages Received:</td><td class=\"prop\">%u</td></tr>",
          (unsigned int) g_persistent.nRecv);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  // Total Errors
  sprintf(buf,
          "<tr><td class=\"name\">Total Errors:</td><td class=\"prop\">%u</td></tr>",
          (unsigned int) g_persistent.nErr);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  // Last Error Code
  sprintf(buf,
          "<tr><td class=\"name\">Last Error Code:</td><td class=\"prop\">0x%08X</td></tr>",
          (unsigned int) g_persistent.lastError);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  // * * *  Connection * * *
  sprintf(buf, "<tr><td class='infoheader'>Connection</td><td></td></tr>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  wifi_mode_t mode;
  esp_wifi_get_mode(&mode);
  switch (mode) {

    case WIFI_MODE_STA:
      sprintf(temp, "STA\n");
      break;

    case WIFI_MODE_AP:
      sprintf(temp, "AP\n");
      break;

    case WIFI_MODE_APSTA:
      sprintf(temp, "APSTA\n");
      break;

    case WIFI_MODE_NULL:
    default:
      sprintf(temp, "unknown\n");
      break;
  };
  // sprintf(temp,"Wifi mode: ");
  sprintf(buf, "<tr><td class=\"name\">Wifi mode:</td><td class=\"prop\">%s</td></tr>", temp);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  wifi_sta_list_t sta;
  esp_wifi_ap_get_sta_list(&sta);
  // printf("Stations: %d\n",sta.num);
  sprintf(buf, "<tr><td class=\"name\">Stations:</td><td class=\"prop\">%d</td></tr>", sta.num);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  wifi_ap_record_t ap_info;
  esp_wifi_sta_get_ap_info(&ap_info);
  // printf("bssid: " MACSTR "\n", MAC2STR(ap_info.bssid));
  sprintf(buf, "<tr><td class=\"name\">bssid:</td><td class=\"prop\">" MACSTR "</td></tr>", MAC2STR(ap_info.bssid));
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  // printf("ssid: %s\n", ap_info.ssid);
  sprintf(buf, "<tr><td class=\"name\">ssid:</td><td class=\"prop\">%s</td></tr>", ap_info.ssid);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  // printf("channel: %d (%d)\n", ap_info.primary, ap_info.second);
  sprintf(buf,
          "<tr><td class=\"name\">channel:</td><td class=\"prop\">%d (%d)</td></tr>",
          ap_info.primary,
          ap_info.second);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  // printf("signal strength: %d\n", ap_info.rssi);
  if (ap_info.rssi > -30) {
    sprintf(temp, "Perfect");
  }
  else if (ap_info.rssi > -50) {
    sprintf(temp, "Excellent");
  }
  else if (ap_info.rssi > -60) {
    sprintf(temp, "Good");
  }
  else if (ap_info.rssi > -67) {
    sprintf(temp, "Limited");
  }
  else if (ap_info.rssi > -70) {
    sprintf(temp, "Poor");
  }
  else if (ap_info.rssi > -80) {
    sprintf(temp, "Unstable");
  }
  else {
    sprintf(temp, "Unusable");
  }

  sprintf(buf,
          "<tr><td class=\"name\">signal strength:</td><td class=\"prop\">%d dBm ( %d%% = %s)</td></tr>",
          ap_info.rssi,
          (2 * (ap_info.rssi + 100)),
          temp);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  // printf("Mode: 11%s%s%s %s %s",
  //           ap_info.phy_11b ? "b" : "",
  //           ap_info.phy_11g ? "g" : "",
  //           ap_info.phy_11n ? "n" : "",
  //           ap_info.phy_lr ? "lr" : "",
  //           ap_info.wps ? "wps" : "");
  // printf("\nAuth mode of AP: ");
  switch (ap_info.authmode) {

    case WIFI_AUTH_OPEN:
      sprintf(temp, "open\n");
      break;

    case WIFI_AUTH_WEP:
      sprintf(temp, "wep\n");
      break;

    case WIFI_AUTH_WPA_PSK:
      sprintf(temp, "wpa-psk\n");
      break;

    case WIFI_AUTH_WPA2_PSK:
      sprintf(temp, "wpa2-psk\n");
      break;

    case WIFI_AUTH_WPA_WPA2_PSK:
      sprintf(temp, "wpa-wpa2-psk\n");
      break;

    case WIFI_AUTH_WPA2_ENTERPRISE:
      sprintf(temp, "wpa2-enterprise\n");
      break;

    case WIFI_AUTH_WPA3_PSK:
      sprintf(temp, "wpa3-psk\n");
      break;

    case WIFI_AUTH_WPA2_WPA3_PSK:
      sprintf(temp, "wpa2-wpa3-psk\n");
      break;

    case WIFI_AUTH_WAPI_PSK:
      sprintf(temp, "wpa2-wapi-psk\n");
      break;

    case WIFI_AUTH_OWE:
      sprintf(temp, "wpa2-wapi-psk\n");
      break;

    default:
      sprintf(temp, "unknown\n");
      break;
  }

  sprintf(buf, "<tr><td class=\"name\">Auth mode of AP:</td><td class=\"prop\">%s</td></tr>", temp);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  uint8_t mac[6];
  esp_wifi_get_mac(ESP_IF_WIFI_STA, mac);
  // printf("Wifi STA MAC address: " MACSTR "\n", MAC2STR(mac));
  sprintf(buf,
          "<tr><td class=\"name\">Wifi STA MAC address:</td><td class=\"prop\">" MACSTR "</td></tr>",
          MAC2STR(mac));
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  esp_wifi_get_mac(ESP_MAC_WIFI_SOFTAP, mac);
  // printf("Wifi SOFTAP MAC address: " MACSTR "\n", MAC2STR(mac));
  sprintf(buf,
          "<tr><td class=\"name\">Wifi SOFTAP MAC address:</td><td class=\"prop\">" MACSTR "</td></tr>",
          MAC2STR(mac));
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  esp_netif_t *netif = NULL;
  netif              = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
  esp_netif_ip_info_t ifinfo;
  if (NULL != netif) {
    esp_netif_get_ip_info(netif, &ifinfo);
    // printf("IP address (wifi): " IPSTR "\n", IP2STR(&ifinfo.ip));
    sprintf(buf,
            "<tr><td class=\"name\">IP address (wifi):</td><td class=\"prop\">" IPSTR "</td></tr>",
            IP2STR(&ifinfo.ip));
    httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

    // printf("Subnet Mask: " IPSTR "\n", IP2STR(&ifinfo.netmask));
    sprintf(buf,
            "<tr><td class=\"name\">Subnet Mask:</td><td class=\"prop\">" IPSTR "</td></tr>",
            IP2STR(&ifinfo.netmask));
    httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

    // printf("Gateway: " IPSTR "\n", IP2STR(&ifinfo.gw));
    sprintf(buf, "<tr><td class=\"name\">Gateway:</td><td class=\"prop\">" IPSTR "</td></tr>", IP2STR(&ifinfo.gw));
    httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

    esp_netif_dns_info_t dns;
    esp_netif_get_dns_info(netif, ESP_NETIF_DNS_MAIN, &dns);
    // printf("DNS DNS Server1: " IPSTR "\n", IP2STR(&dns.ip.u_addr.ip4));
    sprintf(buf,
            "<tr><td class=\"name\">DNS Server1:</td><td class=\"prop\">" IPSTR "</td></tr>",
            IP2STR(&dns.ip.u_addr.ip4));
    httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
    esp_netif_get_dns_info(netif, ESP_NETIF_DNS_BACKUP, &dns);

    // printf("DNS Server2: " IPSTR "\n", IP2STR(&dns.ip.u_addr.ip4));
    sprintf(buf,
            "<tr><td class=\"name\">DNS Server2:</td><td class=\"prop\">" IPSTR "</td></tr>",
            IP2STR(&dns.ip.u_addr.ip4));
    httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
  }

  sprintf(buf, "</table>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, WEBPAGE_END_TEMPLATE, appDescr->version, g_persistent.nodeName);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  httpd_resp_send_chunk(req, NULL, 0);

  free(buf);
  free(temp);

  return ESP_OK;
}

// URI handler for getting uploaded files
httpd_uri_t info = { .uri = "/info", .method = HTTP_GET, .handler = info_get_handler, .user_ctx = NULL };

///////////////////////////////////////////////////////////////////////////////
// reset_get_handler
//
// HTTP GET handler for reset of machine
//

static esp_err_t
reset_get_handler(httpd_req_t *req)
{
  const char *resp_str = "<html><head><meta charset='utf-8'><meta http-equiv=\"refresh\" content=\"2;url=index.html\" "
                         "/></head><body><h1>The system is restarting...</h1></body></html>";
  httpd_resp_send(req, resp_str, HTTPD_RESP_USE_STRLEN);

  // Let content render
  vTaskDelay(2000 / portTICK_PERIOD_MS);

  // esp_wifi_disconnect();
  // vTaskDelay(2000 / portTICK_PERIOD_MS);
  esp_restart();
  return ESP_OK;
}

httpd_uri_t reset = { .uri = "/reset", .method = HTTP_GET, .handler = reset_get_handler, .user_ctx = NULL };

///////////////////////////////////////////////////////////////////////////////
// upgrade_get_handler
//
// HTTP GET handler for update of firmware
//
// - Server upgrade
// - Local upgrade
//

static esp_err_t
upgrade_get_handler(httpd_req_t *req)
{
  // esp_err_t rv;
  char *buf;
  char *temp;

  buf = (char *) calloc(CHUNK_BUFSIZE, 1);
  if (NULL == buf) {
    return ESP_ERR_NO_MEM;
  }

  temp = (char *) calloc(80, 1);
  if (NULL == temp) {
    return ESP_ERR_NO_MEM;
  }

  esp_chip_info_t chip_info;
  esp_chip_info(&chip_info);

  const esp_app_desc_t *appDescr = esp_app_get_description();

  sprintf(buf, WEBPAGE_START_TEMPLATE, g_persistent.nodeName, "Upgrade firmware");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "<h3>Upgrade from web server</h3>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "<div><form id=but3 class=\"button\" action='/upgrdsrv' method='get'><fieldset>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "OTA URL:<input type=\"text\"  id=\"url\" name=\"url\" value=\"%s\" >", DEFAULT_APP_OTA_URL);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "<button class=\"bgrn bgrn:hover\" >Start Upgrade</button></fieldset></form></div>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  // ----- Local -----

  sprintf(buf,
          "<h3>Upgrade from local file</h3><div> <span style=\"color:red;font-family:verdana;font-size:300%%;\" "
          "id=\"progress\" /></div>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "<div><fform id=but3 class=\"button\" action='/upgrdlocal' method='post'><fieldset>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf,
          "<label for=\"otafile\">OTA firmware file:</label><input type=\"file\" id=\"otafile\" name=\"otafile\" />");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf,
          "<button class=\"bgrn bgrn:hover\" id=\"upload\" onclick=\"startUpload();\">Start "
          "Upgrade</button></fieldset></fform></div>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, WEBPAGE_END_TEMPLATE, appDescr->version, g_persistent.nodeName);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  httpd_resp_send_chunk(req, NULL, 0);

  free(buf);
  free(temp);

  return ESP_OK;
}

// httpd_uri_t upgrade = { .uri = "/upgrade", .method = HTTP_GET, .handler = upgrade_get_handler, .user_ctx = NULL };

///////////////////////////////////////////////////////////////////////////////
// upgrdsrv_get_handler
//

static esp_err_t
upgrdsrv_get_handler(httpd_req_t *req)
{
  esp_err_t ret;
  char *buf = NULL;
  char *req_buf;
  size_t req_buf_len;

  buf = (char *) calloc(CHUNK_BUFSIZE, 1);
  if (NULL == buf) {
    return ESP_ERR_NO_MEM;
  }

  // Read URL query string length and allocate memory for length + 1,
  // extra byte for null termination
  req_buf_len = httpd_req_get_url_query_len(req) + 1;
  if (req_buf_len > 1) {
    req_buf = (char *) malloc(req_buf_len);
    if (httpd_req_get_url_query_str(req, req_buf, req_buf_len) == ESP_OK) {

      ESP_LOGD(TAG, "Found URL query => %s", req_buf);
      char *param = (char *) malloc(WEBPAGE_PARAM_SIZE);
      if (NULL == param) {
        free(req_buf);
        free(buf);
        return ESP_ERR_NO_MEM;
      }

      // URL
      if (ESP_OK == (ret = httpd_query_key_value(req_buf, "url", param, WEBPAGE_PARAM_SIZE))) {
        ESP_LOGD(TAG, "Found query parameter => url=%s", param);
      }
      else {
        ESP_LOGE(TAG, "Error getting url => rv=%d", ret);
      }

      free(param);
    }

    free(req_buf);
  }

  free(buf);

  const char *resp_str = "<html><head><meta charset='utf-8'><meta http-equiv=\"refresh\" content=\"10;url=index.html\" "
                         "/></head><body><h1>Firmware upgrade in progress...</h1></body></html>";
  httpd_resp_send(req, resp_str, HTTPD_RESP_USE_STRLEN);

  // Let content render
  vTaskDelay(2000 / portTICK_PERIOD_MS);

  printf("Start OTA\n");

  // Start the OTA task
  startOTA();

  return ESP_OK;
}

///////////////////////////////////////////////////////////////////////////////
// upgrdlocal_post_handler
//
// Handle OTA file upload
// https://github.com/Jeija/esp32-softap-ota
//

esp_err_t
upgrdlocal_post_handler(httpd_req_t *req)
{
  char buf[1000];
  esp_ota_handle_t ota_handle;
  int remaining = req->content_len;

  const esp_partition_t *ota_partition = esp_ota_get_next_update_partition(NULL);
  ESP_ERROR_CHECK(esp_ota_begin(ota_partition, OTA_SIZE_UNKNOWN, &ota_handle));

  while (remaining > 0) {

    ESP_LOGD(TAG, "OTA remaining %d", remaining);

    int recv_len = httpd_req_recv(req, buf, MIN(remaining, sizeof(buf)));

    // Timeout Error: Just retry
    if (recv_len == HTTPD_SOCK_ERR_TIMEOUT) {
      continue;
    }
    else if (recv_len <= 0) {
      // Serious Error: Abort OTA
      ESP_LOGE(TAG, "OTA aborted due to protocol error");
      httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Protocol Error");
      return ESP_FAIL;
    }

    // Successful Upload: Flash firmware chunk
    if (esp_ota_write(ota_handle, (const void *) buf, recv_len) != ESP_OK) {
      ESP_LOGE(TAG, "OTA aborted due to flash error");
      httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Flash Error");
      return ESP_FAIL;
    }

    remaining -= recv_len;
  }

  // Validate and switch to new OTA image and reboot
  if (esp_ota_end(ota_handle) != ESP_OK || esp_ota_set_boot_partition(ota_partition) != ESP_OK) {
    ESP_LOGE(TAG, "OTA failed due to image activation error");
    httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Validation / Activation Error");
    return ESP_FAIL;
  }

  ESP_LOGD(TAG, "OTA finished");

  // httpd_resp_sendstr(req, "Firmware update complete, rebooting now!\n");
  const char *resp_str = "<html><head><meta charset='utf-8'><meta http-equiv=\"refresh\" content=\"2;url=index.html\" "
                         "/></head><body><h1>Firmware update complete, rebooting now!...</h1></body></html>";
  httpd_resp_send(req, resp_str, HTTPD_RESP_USE_STRLEN);

  // Let content render
  vTaskDelay(500 / portTICK_PERIOD_MS);
  esp_restart();

  return ESP_OK;
}

static const httpd_uri_t upgrdlocal = { .uri      = "/upgrdlocal",
                                        .method   = HTTP_POST,
                                        .handler  = upgrdlocal_post_handler,
                                        .user_ctx = NULL };

///////////////////////////////////////////////////////////////////////////////
// upgrdsibling_get_handler
//
static esp_err_t
upgrdsibling_get_handler(httpd_req_t *req)
{
  esp_err_t ret;
  char *buf = NULL;
  char *req_buf;
  size_t req_buf_len;
  char url[DEFAULT_APP_OTA_URL_MAX_SIZE];

  buf = (char *) calloc(CHUNK_BUFSIZE, 1);
  if (NULL == buf) {
    return ESP_ERR_NO_MEM;
  }

  // Read URL query string length and allocate memory for length + 1,
  // extra byte for null termination
  req_buf_len = httpd_req_get_url_query_len(req) + 1;
  if (req_buf_len > 1) {
    req_buf = (char *) malloc(req_buf_len);
    if (httpd_req_get_url_query_str(req, req_buf, req_buf_len) == ESP_OK) {

      ESP_LOGD(TAG, "Found URL query => %s", req_buf);
      char *param = (char *) malloc(WEBPAGE_PARAM_SIZE);
      if (NULL == param) {
        free(req_buf);
        free(buf);
        return ESP_ERR_NO_MEM;
      }

      // URL
      if (ESP_OK == (ret = httpd_query_key_value(req_buf, "url", param, WEBPAGE_PARAM_SIZE))) {

        char *pdecoded = urlDecode(param);
        if (NULL == pdecoded) {
          free(param);
          free(req_buf);
          free(buf);
          return ESP_ERR_NO_MEM;
        }

        memset(url, 0, DEFAULT_APP_OTA_URL_MAX_SIZE);
        strncpy(url, pdecoded, MIN(strlen(pdecoded), (DEFAULT_APP_OTA_URL_MAX_SIZE - 1)));

        ESP_LOGD(TAG, "Found query parameter => url=%s", url);

        free(pdecoded);
      }
      else {
        ESP_LOGE(TAG, "Error getting url => rv=%d", ret);
      }

      free(param);
    }

    free(req_buf);
  }

  free(buf);

  const char *resp_str = "<html><head><meta charset='utf-8'><meta http-equiv=\"refresh\" content=\"10;url=index.html\" "
                         "/></head><body><h1>Firmware upgrade of sibling in progress...</h1></body></html>";
  httpd_resp_send(req, resp_str, HTTPD_RESP_USE_STRLEN);

  // Let content render
  vTaskDelay(2000 / portTICK_PERIOD_MS);

  printf("Start OTA update of beta/gamma node(s)  url=%s\n", url);

  // Start the OTA task

  ret = app_initiate_firmware_upload(url);
  if (ESP_OK != ret) {
    ESP_LOGE(TAG, "Initiation of sibling firmware upload failed ret=%x", ret);
    return ret;
  }

  return ESP_OK;
}

///////////////////////////////////////////////////////////////////////////////
// upgrdlocal_post_handler
//
// Handle OTA file upload
// https://github.com/Jeija/esp32-softap-ota
//

esp_err_t
upgrdSiblingslocal_post_handler(httpd_req_t *req)
{
  char buf[1000];
  uint8_t sha_256[32] = { 0 };
  esp_ota_handle_t ota_handle;
  int remaining = req->content_len;

  const esp_partition_t *ota_partition = esp_ota_get_next_update_partition(NULL);
  ESP_ERROR_CHECK(esp_ota_begin(ota_partition, OTA_SIZE_UNKNOWN, &ota_handle));

  while (remaining > 0) {

    ESP_LOGD(TAG, "OTA remaining %d", remaining);

    taskYIELD();

    int recv_len = httpd_req_recv(req, buf, MIN(remaining, sizeof(buf)));

    // Timeout Error: Just retry
    if (recv_len == HTTPD_SOCK_ERR_TIMEOUT) {
      continue;
    }
    else if (recv_len <= 0) {
      // Serious Error: Abort OTA
      ESP_LOGE(TAG, "OTA aborted due to protocol error");
      httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Protocol Error");
      return ESP_FAIL;
    }

    // Successful Upload: Flash firmware chunk
    if (esp_ota_write(ota_handle, (const void *) buf, recv_len) != ESP_OK) {
      ESP_LOGE(TAG, "OTA aborted due to flash error");
      httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Flash Error");
      return ESP_FAIL;
    }

    remaining -= recv_len;
  }

  // Validate and switch to new OTA image and reboot
  if (esp_ota_end(ota_handle) != ESP_OK /*|| esp_ota_set_boot_partition(ota_partition) != ESP_OK*/) {
    ESP_LOGE(TAG, "OTA failed due to image activation error");
    httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Validation / Activation Error");
    return ESP_FAIL;
  }

  ESP_LOGD(TAG, "Send OTA to sibling(s)");

  esp_partition_get_sha256(ota_partition, sha_256);

  // Send new firmware to clients
  // app_firmware_send(req->content_len, sha_256);

  ESP_LOGD(TAG, "Images sent to sibling(s)");

  // httpd_resp_sendstr(req, "Firmware update complete, rebooting now!\n");
  const char *resp_str = "<html><head><meta charset='utf-8'><meta http-equiv=\"refresh\" content=\"2;url=index.html\" "
                         "/></head><body><h1>Firmware update complete, rebooting now!...</h1></body></html>";
  httpd_resp_send(req, resp_str, HTTPD_RESP_USE_STRLEN);

  return ESP_OK;
}

static const httpd_uri_t upgrdsiblinglocal = { .uri      = "/upgrdSiblingLocal",
                                               .method   = HTTP_POST,
                                               .handler  = upgrdSiblingslocal_post_handler,
                                               .user_ctx = NULL };

///////////////////////////////////////////////////////////////////////////////
// hello_get_handler
//
// Copies the full path into destination buffer and returns
// pointer to path (skipping the preceding base path)
//

static const char *
get_path_from_uri(char *dest, const char *base_path, const char *uri, size_t destsize)
{
  const size_t base_pathlen = strlen(base_path);
  size_t pathlen            = strlen(uri);

  const char *quest = strchr(uri, '?');
  if (quest) {
    pathlen = MIN(pathlen, quest - uri);
  }
  const char *hash = strchr(uri, '#');
  if (hash) {
    pathlen = MIN(pathlen, hash - uri);
  }

  if (base_pathlen + pathlen + 1 > destsize) {
    // Full path string won't fit into destination buffer
    return NULL;
  }

  // Construct full path (base + path)
  strcpy(dest, base_path);
  strlcpy(dest + base_pathlen, uri, pathlen + 1);

  // Return pointer to path, skipping the base
  return dest + base_pathlen;
}

///////////////////////////////////////////////////////////////////////////////
// hello_get_handler
//
// An HTTP GET handler
//

static esp_err_t
hello_get_handler(httpd_req_t *req)
{
  char *buf;
  size_t buf_len;

  // Get header value string length and allocate memory for length + 1,
  // extra byte for null termination
  buf_len = httpd_req_get_hdr_value_len(req, "Host") + 1;
  if (buf_len > 1) {
    buf = (char *) malloc(buf_len);
    // Copy null terminated value string into buffer
    if (httpd_req_get_hdr_value_str(req, "Host", buf, buf_len) == ESP_OK) {
      ESP_LOGD(TAG, "Found header => Host: %s", buf);
    }
    free(buf);
  }

  buf_len = httpd_req_get_hdr_value_len(req, "Test-Header-2") + 1;
  if (buf_len > 1) {
    buf = (char *) malloc(buf_len);
    if (NULL == buf) {
      return ESP_ERR_NO_MEM;
    }
    if (httpd_req_get_hdr_value_str(req, "Test-Header-2", buf, buf_len) == ESP_OK) {
      ESP_LOGD(TAG, "Found header => Test-Header-2: %s", buf);
    }
    free(buf);
  }

  buf_len = httpd_req_get_hdr_value_len(req, "Test-Header-1") + 1;
  if (buf_len > 1) {
    buf = (char *) malloc(buf_len);
    if (httpd_req_get_hdr_value_str(req, "Test-Header-1", buf, buf_len) == ESP_OK) {
      ESP_LOGD(TAG, "Found header => Test-Header-1: %s", buf);
    }
    free(buf);
  }

  // Read URL query string length and allocate memory for length + 1,
  // extra byte for null termination
  buf_len = httpd_req_get_url_query_len(req) + 1;
  if (buf_len > 1) {
    buf = (char *) malloc(buf_len);
    if (NULL == buf) {
      return ESP_ERR_NO_MEM;
    }
    if (httpd_req_get_url_query_str(req, buf, buf_len) == ESP_OK) {
      ESP_LOGD(TAG, "Found URL query => %s", buf);
      char param[32];
      // Get value of expected key from query string
      if (httpd_query_key_value(buf, "query1", param, sizeof(param)) == ESP_OK) {
        ESP_LOGD(TAG, "Found URL query parameter => query1=%s", param);
      }
      if (httpd_query_key_value(buf, "query3", param, sizeof(param)) == ESP_OK) {
        ESP_LOGD(TAG, "Found URL query parameter => query3=%s", param);
      }
      if (httpd_query_key_value(buf, "query2", param, sizeof(param)) == ESP_OK) {
        ESP_LOGD(TAG, "Found URL query parameter => query2=%s", param);
      }
    }
    free(buf);
  }

  // Set some custom headers
  httpd_resp_set_hdr(req, "Custom-Header-1", "Custom-Value-1");
  httpd_resp_set_hdr(req, "Custom-Header-2", "Custom-Value-2");

  // Send response with custom headers and body set as the
  // string passed in user context
  const char *resp_str = "Hi there mister m!"; //(const char *) req->user_ctx;
  httpd_resp_send(req, resp_str, HTTPD_RESP_USE_STRLEN);

  // After sending the HTTP response the old HTTP request
  // headers are lost. Check if HTTP request headers can be read now.
  if (httpd_req_get_hdr_value_len(req, "Host") == 0) {
    ESP_LOGD(TAG, "Request headers lost");
  }

  return ESP_OK;
}

static const httpd_uri_t hello = { .uri     = "/hello",
                                   .method  = HTTP_GET,
                                   .handler = hello_get_handler,
                                   // Let's pass response string in user
                                   // context to demonstrate it's usage
                                   .user_ctx = "Hello World!" };

///////////////////////////////////////////////////////////////////////////////
// mainpg_get_handler
//
// Mainpage for web interface
//

static esp_err_t
mainpg_get_handler(httpd_req_t *req)
{
  char *buf;

  char *req_buf;
  size_t req_buf_len;

  buf = (char *) calloc(CHUNK_BUFSIZE, 1);
  if (NULL == buf) {
    return ESP_ERR_NO_MEM;
  }

  // Get application info data
  const esp_app_desc_t *appDescr = esp_app_get_description();

  // Get header value string length and allocate memory for length + 1,
  // extra byte for null termination
  req_buf_len = httpd_req_get_hdr_value_len(req, "Host") + 1;
  if (req_buf_len > 1) {
    req_buf = (char *) malloc(req_buf_len);
    // Copy null terminated value string into buffer
    if (httpd_req_get_hdr_value_str(req, "Host", req_buf, req_buf_len) == ESP_OK) {
      ESP_LOGD(TAG, "Found header => Host: %s", req_buf);
    }
    free(req_buf);
  }

  sprintf(buf, WEBPAGE_START_TEMPLATE, g_persistent.nodeName, "Main Page");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf,
          "<p><form id=but1 class=\"button\" action='config' method='get'><button>Configuration</button></form></p>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf,
          "<p><form id=but2 class=\"button\" action='info' method='get'><button>Node Information</button></form></p>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf,
          "<p><form id=but3 class=\"button\" action='upgrade' method='get'><button>Firmware "
          "Upgrade</button></form></p>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf,
          "<p><form id=but5 class=\"button\" action='reset' method='get'><button name='rst' class='button "
          "bred'>Restart</button></form></p>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, WEBPAGE_END_TEMPLATE, appDescr->version, g_persistent.nodeName);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  httpd_resp_send_chunk(req, NULL, 0);

  free(buf);

  return ESP_OK;
}

// static const httpd_uri_t mainpg = { .uri     = "/index.html",
//                                    .method  = HTTP_GET,
//                                    .handler = mainpg_get_handler,
//                                    .user_ctx = NULL };

///////////////////////////////////////////////////////////////////////////////
// config_get_handler
//

static esp_err_t
config_get_handler(httpd_req_t *req)
{
  // esp_err_t rv;
  char *buf;
  // char *temp;

  char *req_buf;
  size_t req_buf_len;

  buf = (char *) calloc(CHUNK_BUFSIZE, 1);
  if (NULL == buf) {
    return ESP_ERR_NO_MEM;
  }

  // Get application info data
  const esp_app_desc_t *appDescr = esp_app_get_description();

  // Get header value string length and allocate memory for length + 1,
  // extra byte for null termination
  req_buf_len = httpd_req_get_hdr_value_len(req, "Host") + 1;
  if (req_buf_len > 1) {
    req_buf = (char *) malloc(req_buf_len);
    // Copy null terminated value string into buffer
    if (httpd_req_get_hdr_value_str(req, "Host", req_buf, req_buf_len) == ESP_OK) {
      ESP_LOGD(TAG, "Found header => Host: %s", req_buf);
    }
    free(req_buf);
  }

  sprintf(buf, WEBPAGE_START_TEMPLATE, g_persistent.nodeName, "Configuration");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "<p><form id=but1 class=\"button\" action='cfgmodule' method='get'><button>Module</button></form></p>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "<p><form id=but3 class=\"button\" action='cfgcan' method='get'><button>CAN/TWAI</button></form></p>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf,
          "<p><form id=but3 class=\"button\" action='cfgweb' method='get'><button>Web interface</button></form></p>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(
    buf,
    "<p><form id=but3 class=\"button\" action='cfgvscplink' method='get'><button>VSCP Link Srv</button></form></p>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "<p><form id=but3 class=\"button\" action='cfgmqtt' method='get'><button>MQTT</button></form></p>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf,
          "<p><form id=but3 class=\"button\" action='cfgmulticast' method='get'><button>Multicast</button></form></p>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "<p><form id=but3 class=\"button\" action='cfgudp' method='get'><button>UDP</button></form></p>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(
    buf,
    "<p><form id=but3 class=\"button\" action='cfgwebsockets' method='get'><button>Websockets</button></form></p>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "<p><form id=but3 class=\"button\" action='cfglog' method='get'><button>Logging</button></form></p>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "<p><form id=but2 class=\"button\" action='cfgwifi' method='get'><button>WiFi</button></form></p>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(
    buf,
    "<hr /><p><form id=but4 class=\"button\" action='cfgfactorydefaults' method='get'><button name='rst' class='button "
    "bred'>Set factory Defaults</button></form></p>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
  sprintf(buf,
          "<p><form id=but3 class=\"button\" action='cfgbackup' method='get'><button class='button "
          "bgrn'>Backup</button></form></p>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
  sprintf(buf,
          "<p><form id=but3 class=\"button\" action='cfgrestore' method='get'><button class='button "
          "bgrn'>Restore</button></form></p>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, WEBPAGE_END_TEMPLATE, appDescr->version, g_persistent.nodeName);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  httpd_resp_send_chunk(req, NULL, 0);

  free(buf);

  return ESP_OK;
}

// static const httpd_uri_t config = { .uri     = "/config",
//                                    .method  = HTTP_GET,
//                                    .handler = config_get_handler,
//                                    .user_ctx = NULL };

///////////////////////////////////////////////////////////////////////////////
// config_can_get_handler
//

static esp_err_t
config_can_get_handler(httpd_req_t *req)
{
  char *buf;
  char *req_buf;
  size_t req_buf_len;

  buf = (char *) calloc(CHUNK_BUFSIZE, 1);
  if (NULL == buf) {
    return ESP_ERR_NO_MEM;
  }

  // Get application info data
  const esp_app_desc_t *appDescr = esp_app_get_description();

  // Get header value string length and allocate memory for length + 1,
  // extra byte for null termination
  req_buf_len = httpd_req_get_hdr_value_len(req, "Host") + 1;
  if (req_buf_len > 1) {
    req_buf = (char *) malloc(req_buf_len);
    // Copy null terminated value string into buffer
    if (httpd_req_get_hdr_value_str(req, "Host", req_buf, req_buf_len) == ESP_OK) {
      ESP_LOGD(TAG, "Found header => Host: %s", req_buf);
    }
    free(req_buf);
  }

  sprintf(buf, WEBPAGE_START_TEMPLATE, g_persistent.nodeName, "CAN/TWAI Configuration");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "<div><form id=but3 class=\"button\" action='/docfgcan' method='get'><fieldset>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  // CAN Mode
  sprintf(buf, "CAN Mode:<select name=\"mode\">");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "<option value=\"0\" %s>Normal</option>", (g_persistent.canMode == 0) ? "selected" : "");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "<option value=\"1\" %s>Listen Only</option>", (g_persistent.canMode == 1) ? "selected" : "");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "</select>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  // CAN Speed
  sprintf(buf, "<br><br>CAN Speed:<select name=\"speed\">");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "<option value=\"0\" %s>5 Kbps</option>", (g_persistent.canSpeed == 0) ? "selected" : "");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "<option value=\"1\" %s>10 Kbps</option>", (g_persistent.canSpeed == 1) ? "selected" : "");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "<option value=\"2\" %s>20 Kbps</option>", (g_persistent.canSpeed == 2) ? "selected" : "");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "<option value=\"3\" %s>25 Kbps</option>", (g_persistent.canSpeed == 3) ? "selected" : "");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "<option value=\"4\" %s>50 Kbps</option>", (g_persistent.canSpeed == 4) ? "selected" : "");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "<option value=\"5\" %s>100 Kbps</option>", (g_persistent.canSpeed == 5) ? "selected" : "");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "<option value=\"6\" %s>125 Kbps (CAN4VSCP)</option>", (g_persistent.canSpeed == 6) ? "selected" : "");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "<option value=\"7\" %s>250 Kbps</option>", (g_persistent.canSpeed == 7) ? "selected" : "");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "<option value=\"8\" %s>500 Kbps</option>", (g_persistent.canSpeed == 8) ? "selected" : "");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "<option value=\"9\" %s>800 Kbps</option>", (g_persistent.canSpeed == 9) ? "selected" : "");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "<option value=\"10\" %s>1000 Kbps</option>", (g_persistent.canSpeed == 10) ? "selected" : "");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "</select>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  // CAN Filter (hex format)
  sprintf(buf,
          "<br><br>CAN Filter (hex):<input type=\"text\" name=\"filter\" value=\"%08X\" maxlength=\"8\" size=\"10\">",
          (unsigned int) g_persistent.canFilter);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  // Statistics (read-only)
  sprintf(buf, "<br><br><fieldset><legend>Statistics (read-only)</legend>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "Messages Sent: %u<br>", (unsigned int) g_persistent.nSent);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "Messages Received: %u<br>", (unsigned int) g_persistent.nRecv);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "Errors: %u<br>", (unsigned int) g_persistent.nErr);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "Last Error Code: 0x%08X", (unsigned int) g_persistent.lastError);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "</fieldset>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "<br><button class=\"bgrn bgrn:hover\">Save</button></fieldset></form></div>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, WEBPAGE_CONFIG_END_TEMPLATE, appDescr->version, g_persistent.nodeName);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  httpd_resp_send_chunk(req, NULL, 0);

  free(buf);

  return ESP_OK;
}

///////////////////////////////////////////////////////////////////////////////
// config_module_get_handler
//

static esp_err_t
config_module_get_handler(httpd_req_t *req)
{
  // esp_err_t rv;
  char *buf;
  // char *temp;

  char *req_buf;
  size_t req_buf_len;

  buf = (char *) calloc(CHUNK_BUFSIZE, 1);
  if (NULL == buf) {
    return ESP_ERR_NO_MEM;
  }

  // Get application info data
  const esp_app_desc_t *appDescr = esp_app_get_description();

  // Get header value string length and allocate memory for length + 1,
  // extra byte for null termination
  req_buf_len = httpd_req_get_hdr_value_len(req, "Host") + 1;
  if (req_buf_len > 1) {
    req_buf = (char *) malloc(req_buf_len);
    // Copy null terminated value string into buffer
    if (httpd_req_get_hdr_value_str(req, "Host", req_buf, req_buf_len) == ESP_OK) {
      ESP_LOGD(TAG, "Found header => Host: %s", req_buf);
    }
    free(req_buf);
  }

  sprintf(buf, WEBPAGE_START_TEMPLATE, g_persistent.nodeName, "Module Configuration");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "<div><form id=but3 class=\"button\" action='/docfgmodule' method='get'><fieldset>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf,
          "Module name:<input type=\"text\" name=\"node_name\" maxlength=\"32\" size=\"20\" value=\"%s\" >",
          g_persistent.nodeName);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  // TODO
  // char *pmkstr = (char *)malloc(65);
  // for (int i = 0; i < sizeof(g_persistent.pmk); i++) {
  //   sprintf(pmkstr + 2 * i, "%02X", g_persistent.pmk[i]);
  // }
  // sprintf(buf,
  //         "Primay key (32 bytes hex):<input type=\"password\" name=\"key\" maxlength=\"64\" size=\"20\" value=\"%s\"
  //         >",
  //         >", pmkstr);
  // httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
  // free(pmkstr);

  // sprintf(buf,
  //         "Startup delay:<input type=\"text\" name=\"strtdly\" value=\"%d\" maxlength=\"2\" size=\"4\">",
  //         g_persistent.startDelay);
  // httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  // Encryption level
  sprintf(buf, "<br>Encryption level:<select name=\"encryptlvl\">");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf,
          "<option value=\"0\" %s>None</option>",
          (g_persistent.encryptLvl == VSCP_ENCRYPTION_NONE) ? "selected" : "");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf,
          "<option value=\"1\" %s>AES-128</option>",
          (g_persistent.encryptLvl == VSCP_ENCRYPTION_AES128) ? "selected" : "");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "<option value=\"2\" %s>AES-192</option>", (g_persistent.encryptLvl == 2) ? "selected" : "");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf,
          "<option value=\"3\" %s>AES-256</option>",
          (g_persistent.encryptLvl == VSCP_ENCRYPTION_AES256) ? "selected" : "");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "</select>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  char *pmkstr = (char *) calloc(sizeof(g_persistent.pmk) * 2 + 1, 1);
  for (int i = 0; i < sizeof(g_persistent.pmk); i++) {
    sprintf(pmkstr + 2 * i, "%02X", g_persistent.pmk[i]);
  }
  sprintf(
    buf,
    "Primary security key (16/24/32 hex bytes):<input type=\"password\" name=\"key\" maxlength=\"32\" value=\"%s\" >",
    pmkstr);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
  free(pmkstr);

  sprintf(buf,
          "Module name:<input type=\"text\" name=\"zone\" maxlength=\"32\" size=\"20\" value=\"%d\" >",
          g_persistent.nodeZone);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf,
          "Module sub-zone:<input type=\"text\" name=\"subzone\" maxlength=\"32\" size=\"20\" value=\"%d\" >",
          g_persistent.nodeSubzone);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "<button class=\"bgrn bgrn:hover\">Save</button></fieldset></form></div>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, WEBPAGE_CONFIG_END_TEMPLATE, appDescr->version, g_persistent.nodeName);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  httpd_resp_send_chunk(req, NULL, 0);

  free(buf);

  return ESP_OK;
}

// static const httpd_uri_t cfgModule = { .uri     = "/cfgmodule",
//                                    .method  = HTTP_GET,
//                                    .handler = config_module_get_handler,
//                                    .user_ctx = NULL };

///////////////////////////////////////////////////////////////////////////////
// do_config_module_get_handler
//

static esp_err_t
do_config_module_get_handler(httpd_req_t *req)
{
  esp_err_t rv;
  char *buf;
  size_t buf_len;

  // Read URL query string length and allocate memory for length + 1,
  // extra byte for null termination
  buf_len = httpd_req_get_url_query_len(req) + 1;
  if (buf_len > 1) {
    buf = (char *) malloc(buf_len);
    if (httpd_req_get_url_query_str(req, buf, buf_len) == ESP_OK) {

      ESP_LOGD(TAG, "Found URL query => %s", buf);
      char *param = (char *) malloc(WEBPAGE_PARAM_SIZE);
      if (NULL == param) {
        return ESP_ERR_NO_MEM;
        free(param);
      }

      // name
      if (ESP_OK == (rv = httpd_query_key_value(buf, "node_name", param, WEBPAGE_PARAM_SIZE))) {
        char *pdecoded = urlDecode(param);
        if (NULL == pdecoded) {
          free(param);
          free(buf);
          return ESP_ERR_NO_MEM;
        }
        ESP_LOGD(TAG, "Found query parameter => name=%s", pdecoded);
        strncpy(g_persistent.nodeName, pdecoded, 31);
        free(pdecoded);

        // setAccessPointParameters();

        // Write changed value to persistent storage
        rv = nvs_set_str(g_nvsHandle, "nodeName", g_persistent.nodeName);
        if (rv != ESP_OK) {
          ESP_LOGE(TAG, "Failed to update node name [%s]", esp_err_to_name(rv));
        }
      }
      else {
        ESP_LOGE(TAG, "Error getting node name => rv=%d", rv);
      }

      // key
      if (ESP_OK == (rv = httpd_query_key_value(buf, "key", param, WEBPAGE_PARAM_SIZE))) {
        // uint8_t key_info[DEFAULT_KEY_LEN];
        ESP_LOGD(TAG, "Found query parameter => key");
        memset(g_persistent.pmk, 0, DEFAULT_KEY_LEN);
        rv = vscp_fwhlp_hex2bin(g_persistent.pmk, DEFAULT_KEY_LEN, param);
        if (rv == -1) {
          ESP_LOGE(TAG, "Failed to write key. rv=%d", rv);
        }

        if (rv < 16 || (rv > 16 && rv < 24) || (rv > 24 && rv < 32) || rv > 32) {
          ESP_LOGE(TAG, "Key length invalid. Must be 16, 24 or 32 bytes. rv=%d", rv);
          // Invalid key length
          ESP_LOGE(TAG, "Invalid key size. size=%d", rv);
        }
        else {
          g_persistent.pmkLen = 16; // rv; // Save the keylength (16/24/32 bytes)

          // Write changed value to persistent storage
          rv = nvs_set_blob(g_nvsHandle, "pmk", g_persistent.pmk, sizeof(g_persistent.pmk));
          if (rv != ESP_OK) {
            ESP_LOGE(TAG, "Failed to write node pmk to nvs. rv=%d", rv);
          }
        }
      }
      else {
        ESP_LOGE(TAG, "Error getting node_name => rv=%d", rv);
      }

      // Encryption level
      if (ESP_OK == (rv = httpd_query_key_value(buf, "encryptlvl", param, WEBPAGE_PARAM_SIZE))) {
        ESP_LOGD(TAG, "Found query parameter => encryptlvl=%s", param);
        g_persistent.encryptLvl = (uint8_t) atoi(param);
      }
      else {
        ESP_LOGE(TAG, "Error getting encryption level => rv=%d", rv);
      }
      // const char *encryptLvlStr;
      // switch (g_persistent.encryptLvl) {
      //   case 0:
      //     encryptLvlStr = "None";
      //     break;
      //   case 1:
      //     encryptLvlStr = "AES128";
      //     break;
      //     break;
      //   case 2:
      //     encryptLvlStr = "AES192";
      //     break;
      //   case 3:
      //     encryptLvlStr = "AES256";
      //     break;
      //   default:
      //     encryptLvlStr = "Unknown";
      //     break;
      // }
      // sprintf(buf, "<tr><td class=\"name\">Encryption Level:</td><td class=\"prop\">%s</td></tr>", encryptLvlStr);
      // httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

      // Write changed value to persistent storage
      rv = nvs_set_u8(g_nvsHandle, "encryptLvl", g_persistent.encryptLvl);
      if (rv != ESP_OK) {
        ESP_LOGE(TAG, "Failed to update encryption level [%s]", esp_err_to_name(rv));
      }

      // zone
      if (ESP_OK == (rv = httpd_query_key_value(buf, "zone", param, WEBPAGE_PARAM_SIZE))) {
        g_persistent.nodeZone = (uint8_t) vscp_fwhlp_readStringValue(param);

        // Write changed value to persistent storage
        rv = nvs_set_u8(g_nvsHandle, "nodeZone", g_persistent.nodeZone);
        if (rv != ESP_OK) {
          ESP_LOGE(TAG, "Failed to update node zone [%s]", esp_err_to_name(rv));
        }
      }
      else {
        ESP_LOGE(TAG, "Error getting node zone => rv=%d", rv);
      }

      // subzone
      if (ESP_OK == (rv = httpd_query_key_value(buf, "subzone", param, WEBPAGE_PARAM_SIZE))) {
        g_persistent.nodeSubzone = (uint8_t) vscp_fwhlp_readStringValue(param);

        // Write changed value to persistent storage
        rv = nvs_set_u8(g_nvsHandle, "nodeSubZone", g_persistent.nodeSubzone);
        if (rv != ESP_OK) {
          ESP_LOGE(TAG, "Failed to update node subzone [%s]", esp_err_to_name(rv));
        }
      }
      else {
        ESP_LOGE(TAG, "Error getting node subzone => rv=%d", rv);
      }

      rv = nvs_commit(g_nvsHandle);
      if (rv != ESP_OK) {
        ESP_LOGE(TAG, "Failed to commit updates to nvs\n");
      }

      rv = wcang_reconfigure_wifi_sta();
      if (rv != ESP_OK) {
        ESP_LOGW(TAG, "WiFi runtime reconfiguration failed: %s", esp_err_to_name(rv));
      }

      free(param);
    }

    free(buf);
  }
  const char *resp_str =
    "<html><head><meta charset='utf-8'><meta http-equiv=\"refresh\" content=\"1;url=cfgmodule\" "
    "/><style>" WEBPAGE_STYLE_CSS "</style></head><body><h2 class=\"name\">saving module data...</h2></body></html>";
  httpd_resp_send(req, resp_str, HTTPD_RESP_USE_STRLEN);

  return ESP_OK;
}

///////////////////////////////////////////////////////////////////////////////
// do_config_can_get_handler
//

static esp_err_t
do_config_can_get_handler(httpd_req_t *req)
{
  esp_err_t rv;
  char *buf;
  size_t buf_len;

  // Read URL query string length and allocate memory for length + 1,
  // extra byte for null termination
  buf_len = httpd_req_get_url_query_len(req) + 1;
  if (buf_len > 1) {
    buf = malloc(buf_len);
    if (httpd_req_get_url_query_str(req, buf, buf_len) == ESP_OK) {

      ESP_LOGD(TAG, "Found URL query => %s", buf);
      char *param = (char *) malloc(WEBPAGE_PARAM_SIZE);
      if (NULL == param) {
        free(buf);
        return ESP_ERR_NO_MEM;
      }

      // CAN Mode
      if (ESP_OK == (rv = httpd_query_key_value(buf, "mode", param, WEBPAGE_PARAM_SIZE))) {
        ESP_LOGD(TAG, "Found query parameter => mode=%s", param);
        g_persistent.canMode = (uint8_t) atoi(param);
        // Write changed value to persistent storage
        rv = nvs_set_u8(g_nvsHandle, "canMode", g_persistent.canMode);
        if (rv != ESP_OK) {
          ESP_LOGE(TAG, "Failed to update CAN mode [%s]", esp_err_to_name(rv));
        }
      }
      else {
        ESP_LOGE(TAG, "Error getting CAN mode => rv=%d", rv);
      }

      // CAN Speed
      if (ESP_OK == (rv = httpd_query_key_value(buf, "speed", param, WEBPAGE_PARAM_SIZE))) {
        ESP_LOGD(TAG, "Found query parameter => speed=%s", param);
        g_persistent.canSpeed = (uint8_t) atoi(param);
        // Write changed value to persistent storage
        rv = nvs_set_u8(g_nvsHandle, "canSpeed", g_persistent.canSpeed);
        if (rv != ESP_OK) {
          ESP_LOGE(TAG, "Failed to update CAN speed [%s]", esp_err_to_name(rv));
        }
      }
      else {
        ESP_LOGE(TAG, "Error getting CAN speed => rv=%d", rv);
      }

      // CAN Filter
      if (ESP_OK == (rv = httpd_query_key_value(buf, "filter", param, WEBPAGE_PARAM_SIZE))) {
        ESP_LOGD(TAG, "Found query parameter => filter=%s", param);
        uint32_t filter_val    = (uint32_t) strtoul(param, NULL, 16);
        g_persistent.canFilter = filter_val;
        // Write changed value to persistent storage
        rv = nvs_set_u32(g_nvsHandle, "filter", g_persistent.canFilter);
        if (rv != ESP_OK) {
          ESP_LOGE(TAG, "Failed to update CAN filter [%s]", esp_err_to_name(rv));
        }
      }
      else {
        ESP_LOGE(TAG, "Error getting CAN filter => rv=%d", rv);
      }

      rv = nvs_commit(g_nvsHandle);
      if (rv != ESP_OK) {
        ESP_LOGE(TAG, "Failed to commit updates to nvs\n");
      }

      free(param);
    }

    free(buf);
  }
  const char *resp_str =
    "<html><head><meta charset='utf-8'><meta http-equiv=\"refresh\" content=\"1;url=cfgcan\" "
    "/><style>" WEBPAGE_STYLE_CSS "</style></head><body><h2 class=\"name\">saving CAN/TWAI data...</h2></body></html>";
  httpd_resp_send(req, resp_str, HTTPD_RESP_USE_STRLEN);

  return ESP_OK;
}

///////////////////////////////////////////////////////////////////////////////
// print_auth_mode
//

static void
print_auth_mode(httpd_req_t *req, char *buf, int authmode)
{
  switch (authmode) {
    case WIFI_AUTH_OPEN:
      sprintf(buf, "<b>Authmode</b> WIFI_AUTH_OPEN<br>");
      break;
    case WIFI_AUTH_OWE:
      sprintf(buf, "<b>Authmode</b> WIFI_AUTH_OWE<br>");
      break;
    case WIFI_AUTH_WEP:
      sprintf(buf, "<b>Authmode</b> WIFI_AUTH_WEP<br>");
      break;
    case WIFI_AUTH_WPA_PSK:
      sprintf(buf, "<b>Authmode</b> WIFI_AUTH_WPA_PSK<br>");
      break;
    case WIFI_AUTH_WPA2_PSK:
      sprintf(buf, "<b>Authmode</b> WIFI_AUTH_WPA2_PSK<br>");
      break;
    case WIFI_AUTH_WPA_WPA2_PSK:
      sprintf(buf, "<b>Authmode</b> WIFI_AUTH_WPA_WPA2_PSK<br>");
      break;
    case WIFI_AUTH_WPA2_ENTERPRISE:
      sprintf(buf, "<b>Authmode</b> WIFI_AUTH_WPA2_ENTERPRISE<br>");
      break;
    case WIFI_AUTH_WPA3_PSK:
      sprintf(buf, "<b>Authmode</b> WIFI_AUTH_WPA3_PSK<br>");
      break;
    case WIFI_AUTH_WPA2_WPA3_PSK:
      sprintf(buf, "<b>Authmode</b> WIFI_AUTH_WPA2_WPA3_PSK<br>");
      break;
    default:
      sprintf(buf, "<b>Authmode</b> WIFI_AUTH_UNKNOWN<br>");
      break;
  }

  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
}

///////////////////////////////////////////////////////////////////////////////
// print_cipher_type
//

static void
print_cipher_type(httpd_req_t *req, char *buf, int pairwise_cipher, int group_cipher)
{
  switch (pairwise_cipher) {
    case WIFI_CIPHER_TYPE_NONE:
      sprintf(buf, "<b>Pairwise Cipher</b> WIFI_CIPHER_TYPE_NONE<br>");
      break;
    case WIFI_CIPHER_TYPE_WEP40:
      sprintf(buf, "<b>Pairwise Cipher</b> WIFI_CIPHER_TYPE_WEP40<br>");
      break;
    case WIFI_CIPHER_TYPE_WEP104:
      sprintf(buf, "<b>Pairwise Cipher</b> WIFI_CIPHER_TYPE_WEP104<br>");
      break;
    case WIFI_CIPHER_TYPE_TKIP:
      sprintf(buf, "<b>Pairwise Cipher</b> WIFI_CIPHER_TYPE_TKIP<br>");
      break;
    case WIFI_CIPHER_TYPE_CCMP:
      sprintf(buf, "<b>Pairwise Cipher</b> WIFI_CIPHER_TYPE_CCMP<br>");
      break;
    case WIFI_CIPHER_TYPE_TKIP_CCMP:
      sprintf(buf, "<b>Pairwise Cipher</b> WIFI_CIPHER_TYPE_TKIP_CCMP<br>");
      break;
    default:
      sprintf(buf, "<b>Pairwise Cipher</b> WIFI_CIPHER_TYPE_UNKNOWN<br>");
      break;
  }

  switch (group_cipher) {
    case WIFI_CIPHER_TYPE_NONE:
      sprintf(buf, "<b>Group Cipher</b> WIFI_CIPHER_TYPE_NONE<br>");
      break;
    case WIFI_CIPHER_TYPE_WEP40:
      sprintf(buf, "<b>Group Cipher</b> WIFI_CIPHER_TYPE_WEP40<br>");
      break;
    case WIFI_CIPHER_TYPE_WEP104:
      sprintf(buf, "<b>Group Cipher</b> WIFI_CIPHER_TYPE_WEP104<br>");
      break;
    case WIFI_CIPHER_TYPE_TKIP:
      sprintf(buf, "<b>Group Cipher</b> WIFI_CIPHER_TYPE_TKIP<br>");
      break;
    case WIFI_CIPHER_TYPE_CCMP:
      sprintf(buf, "<b>Group Cipher</b> WIFI_CIPHER_TYPE_CCMP<br>");
      break;
    case WIFI_CIPHER_TYPE_TKIP_CCMP:
      sprintf(buf, "<b>Group Cipher</b> WIFI_CIPHER_TYPE_TKIP_CCMP<br>");
      break;
    default:
      sprintf(buf, "<b>Group Cipher</b> WIFI_CIPHER_TYPE_UNKNOWN<br>");
      break;
  }
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
}

///////////////////////////////////////////////////////////////////////////////
// config_wifi_get_handler
//

static esp_err_t
config_wifi_get_handler(httpd_req_t *req)
{
  esp_err_t rv = ESP_OK;
  char *buf;
  char *req_buf;
  size_t req_buf_len;

  buf = (char *) calloc(CHUNK_BUFSIZE, 1);
  if (NULL == buf) {
    return ESP_ERR_NO_MEM;
  }

  // Get application info data
  const esp_app_desc_t *appDescr = esp_app_get_description();

  // Get header value string length and allocate memory for length + 1,
  // extra byte for null termination
  req_buf_len = httpd_req_get_hdr_value_len(req, "Host") + 1;
  if (req_buf_len > 1) {
    req_buf = (char *) malloc(req_buf_len);
    // Copy null terminated value string into buffer
    if (httpd_req_get_hdr_value_str(req, "Host", req_buf, req_buf_len) == ESP_OK) {
      ESP_LOGD(TAG, "Found header => Host: %s", req_buf);
    }
    free(req_buf);
  }

  sprintf(buf, WEBPAGE_START_TEMPLATE, g_persistent.nodeName, "Wifi Configuration");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "<div><form id=but3 class=\"button\" action='/docfgwifi' method='get'><fieldset>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  // Display current WiFi configuration
  sprintf(buf, "<fieldset><legend>Current WiFi Configuration</legend>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf,
          "Primary SSID:<input type=\"text\" name=\"primary_ssid\" value=\"%s\" maxlength=\"32\" size=\"25\">",
          g_persistent.wifiPrimarySsid);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf,
          "<br>Primary Password:<input type=\"password\" name=\"primary_password\" value=\"%s\" maxlength=\"64\" "
          "size=\"25\">",
          g_persistent.wifiPrimaryPassword);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(
    buf,
    "<br><br>Secondary SSID:<input type=\"text\" name=\"secondary_ssid\" value=\"%s\" maxlength=\"32\" size=\"25\">",
    g_persistent.wifiSecondarySsid);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf,
          "<br>Secondary Password:<input type=\"password\" name=\"secondary_password\" value=\"%s\" maxlength=\"64\" "
          "size=\"25\">",
          g_persistent.wifiSecondaryPassword);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf,
          "<br><br>IP Assignment:<select name=\"static_ip_enable\">"
          "<option value=\"0\" %s>DHCP</option>"
          "<option value=\"1\" %s>Static</option></select>",
          g_persistent.wifiStaticEnable ? "" : "selected",
          g_persistent.wifiStaticEnable ? "selected" : "");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf,
          "<br>Static IP:<input type=\"text\" name=\"static_ip\" value=\"%s\" maxlength=\"15\" size=\"25\">",
          g_persistent.wifiStaticIp);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf,
          "<br>Netmask:<input type=\"text\" name=\"static_netmask\" value=\"%s\" maxlength=\"15\" size=\"25\">",
          g_persistent.wifiStaticNetmask);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf,
          "<br>Gateway:<input type=\"text\" name=\"static_gateway\" value=\"%s\" maxlength=\"15\" size=\"25\">",
          g_persistent.wifiStaticGateway);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf,
          "<br>DNS:<input type=\"text\" name=\"static_dns\" value=\"%s\" maxlength=\"15\" size=\"25\">",
          g_persistent.wifiStaticDns);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "</fieldset><br>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "<fieldset><legend>Available WiFi Networks (Click SSID to copy to Primary/Secondary)</legend>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  uint16_t count = 5;
  wifi_ap_record_t ap_info[5];
  uint16_t ap_count = 0;
  memset(ap_info, 0, sizeof(ap_info));

  // Define scan configuration
  wifi_scan_config_t scan_config = {
    .ssid        = NULL,
    .bssid       = NULL,
    .channel     = 0, // Scan all channels
    .show_hidden = false,
    .scan_type   = WIFI_SCAN_TYPE_ACTIVE
    // .scan_time = {
    //     .active = {
    //         .min = 100,
    //         .max = 400
    //     }
    //}
  };

  ESP_LOGI(TAG, "WiFi scan start");

  // Start WiFi scan with configuration
  rv = esp_wifi_scan_start(&scan_config, true);
  // rv = esp_wifi_scan_start(NULL, true);
  if (rv != ESP_OK) {
    ESP_LOGE(TAG, "WiFi scan failed: %s", esp_err_to_name(rv));
    sprintf(buf, "WiFi scan failed: %s<br>", esp_err_to_name(rv));
    httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
    rv = ESP_FAIL; // Abort further processing on failure
    goto wifi_scan_done;
  }

  // Retrieve scan results
  rv = esp_wifi_scan_get_ap_records(&count, ap_info);
  if (rv != ESP_OK) {
    ESP_LOGE(TAG, "Failed to get AP records: %s", esp_err_to_name(rv));
    sprintf(buf, "Failed to get AP records: %s<br>", esp_err_to_name(rv));
    httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
    rv = ESP_FAIL; // Abort further processing on failure
    goto wifi_scan_done;
  }

  ESP_LOGI(TAG, "Number of access points found: %u", count);

  rv = esp_wifi_scan_get_ap_num(&ap_count);
  if (rv != ESP_OK) {
    ESP_LOGE(TAG, "Failed to get AP count: %s", esp_err_to_name(rv));
    sprintf(buf, "Failed to get AP count: %s<br>", esp_err_to_name(rv));
    httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
    rv = ESP_FAIL; // Abort further processing on failure
    goto wifi_scan_done;
  }

  ap_count = count;

  // Log and send total AP count
  // if (ap_count == 0) {
  //   ESP_LOGW(TAG, "No access points found");
  //   sprintf(buf, "<b>No access points found</b><br>");
  //   httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
  //   rv = ESP_FAIL; // Abort further processing on failure
  //   goto wifi_scan_done;
  // }

  sprintf(buf, "<b>Total APs scanned</b> = %u<br><br>", ap_count);
  ESP_LOGI(TAG, "Total APs scanned = %u", ap_count);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  // Send details of each AP
  for (int i = 0; (i < 5) && (i < ap_count); i++) {
    sprintf(buf, "<b>SSID</b> = %s<br>", ap_info[i].ssid);
    httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
    sprintf(buf, "<b>RSSI</b> = %d<br>", ap_info[i].rssi);
    httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
    print_auth_mode(req, buf, ap_info[i].authmode);
    if (ap_info[i].authmode != WIFI_AUTH_WEP) {
      print_cipher_type(req, buf, ap_info[i].pairwise_cipher, ap_info[i].group_cipher);
    }
    sprintf(buf, "Channel = %d<br><hr>", ap_info[i].primary);
    httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
  }

wifi_scan_done:

  sprintf(buf, "</fieldset><br>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "<button class=\"bgrn bgrn:hover\">Save Configuration</button>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "</fieldset></form></div>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "<br><div><form id=rescan class=\"button\" action='/cfgwifi' method='get'>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "<button class=\"button\">Rescan Networks</button></form></div>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, WEBPAGE_CONFIG_END_TEMPLATE, appDescr->version, g_persistent.nodeName);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  httpd_resp_send_chunk(req, NULL, 0);

  free(buf);

  return rv;
}

///////////////////////////////////////////////////////////////////////////////
// do_config_wifi_get_handler
//

static esp_err_t
do_config_wifi_get_handler(httpd_req_t *req)
{
  esp_err_t rv;
  char *buf;
  size_t buf_len;

  // Read URL query string length and allocate memory for length + 1,
  // extra byte for null termination
  buf_len = httpd_req_get_url_query_len(req) + 1;
  if (buf_len > 1) {
    buf = (char *) malloc(buf_len);
    if (httpd_req_get_url_query_str(req, buf, buf_len) == ESP_OK) {

      ESP_LOGD(TAG, "Found URL query => %s", buf);
      char *param = malloc(WEBPAGE_PARAM_SIZE);
      if (NULL == param) {
        return ESP_ERR_NO_MEM;
        free(param);
      }

      // Primary SSID
      if (ESP_OK == (rv = httpd_query_key_value(buf, "primary_ssid", param, WEBPAGE_PARAM_SIZE))) {
        char *pdecoded = urlDecode(param);
        if (NULL == pdecoded) {
          free(param);
          free(buf);
          return ESP_ERR_NO_MEM;
        }
        ESP_LOGD(TAG, "Found query parameter => primary_ssid=%s", pdecoded);
        strncpy(g_persistent.wifiPrimarySsid, pdecoded, sizeof(g_persistent.wifiPrimarySsid) - 1);
        g_persistent.wifiPrimarySsid[sizeof(g_persistent.wifiPrimarySsid) - 1] = '\0';
        free(pdecoded);
        // Write changed value to persistent storage
        rv = nvs_set_str(g_nvsHandle, "wifiPriSsid", g_persistent.wifiPrimarySsid);
        if (rv != ESP_OK) {
          ESP_LOGE(TAG, "Failed to update primary SSID [%s]", esp_err_to_name(rv));
        }
      }

      // Primary Password
      if (ESP_OK == (rv = httpd_query_key_value(buf, "primary_password", param, WEBPAGE_PARAM_SIZE))) {
        char *pdecoded = urlDecode(param);
        if (NULL == pdecoded) {
          free(param);
          free(buf);
          return ESP_ERR_NO_MEM;
        }
        ESP_LOGD(TAG, "Found query parameter => primary_password");
        strncpy(g_persistent.wifiPrimaryPassword, pdecoded, sizeof(g_persistent.wifiPrimaryPassword) - 1);
        g_persistent.wifiPrimaryPassword[sizeof(g_persistent.wifiPrimaryPassword) - 1] = '\0';
        free(pdecoded);
        // Write changed value to persistent storage
        rv = nvs_set_str(g_nvsHandle, "wifiPriPass", g_persistent.wifiPrimaryPassword);
        if (rv != ESP_OK) {
          ESP_LOGE(TAG, "Failed to update primary password [%s]", esp_err_to_name(rv));
        }
      }

      // Secondary SSID
      if (ESP_OK == (rv = httpd_query_key_value(buf, "secondary_ssid", param, WEBPAGE_PARAM_SIZE))) {
        char *pdecoded = urlDecode(param);
        if (NULL == pdecoded) {
          free(param);
          free(buf);
          return ESP_ERR_NO_MEM;
        }
        ESP_LOGD(TAG, "Found query parameter => secondary_ssid=%s", pdecoded);
        strncpy(g_persistent.wifiSecondarySsid, pdecoded, sizeof(g_persistent.wifiSecondarySsid) - 1);
        g_persistent.wifiSecondarySsid[sizeof(g_persistent.wifiSecondarySsid) - 1] = '\0';
        free(pdecoded);
        // Write changed value to persistent storage
        rv = nvs_set_str(g_nvsHandle, "wifiSecSsid", g_persistent.wifiSecondarySsid);
        if (rv != ESP_OK) {
          ESP_LOGE(TAG, "Failed to update secondary SSID [%s]", esp_err_to_name(rv));
        }
      }

      // Secondary Password
      if (ESP_OK == (rv = httpd_query_key_value(buf, "secondary_password", param, WEBPAGE_PARAM_SIZE))) {
        char *pdecoded = urlDecode(param);
        if (NULL == pdecoded) {
          free(param);
          free(buf);
          return ESP_ERR_NO_MEM;
        }
        ESP_LOGD(TAG, "Found query parameter => secondary_password");
        strncpy(g_persistent.wifiSecondaryPassword, pdecoded, sizeof(g_persistent.wifiSecondaryPassword) - 1);
        g_persistent.wifiSecondaryPassword[sizeof(g_persistent.wifiSecondaryPassword) - 1] = '\0';
        free(pdecoded);
        // Write changed value to persistent storage
        rv = nvs_set_str(g_nvsHandle, "wifiSecPass", g_persistent.wifiSecondaryPassword);
        if (rv != ESP_OK) {
          ESP_LOGE(TAG, "Failed to update secondary password [%s]", esp_err_to_name(rv));
        }
      }

      // IP assignment mode (0 = DHCP, 1 = static)
      if (ESP_OK == (rv = httpd_query_key_value(buf, "static_ip_enable", param, WEBPAGE_PARAM_SIZE))) {
        g_persistent.wifiStaticEnable = (0 == strcmp(param, "1")) ? 1 : 0;
        rv                            = nvs_set_u8(g_nvsHandle, "wifiStaIpEn", g_persistent.wifiStaticEnable);
        if (rv != ESP_OK) {
          ESP_LOGE(TAG, "Failed to update static IP enable [%s]", esp_err_to_name(rv));
        }
      }

      // Static IP address
      if (ESP_OK == (rv = httpd_query_key_value(buf, "static_ip", param, WEBPAGE_PARAM_SIZE))) {
        char *pdecoded = urlDecode(param);
        if (NULL == pdecoded) {
          free(param);
          free(buf);
          return ESP_ERR_NO_MEM;
        }
        strncpy(g_persistent.wifiStaticIp, pdecoded, sizeof(g_persistent.wifiStaticIp) - 1);
        g_persistent.wifiStaticIp[sizeof(g_persistent.wifiStaticIp) - 1] = '\0';
        free(pdecoded);
        rv = nvs_set_str(g_nvsHandle, "wifiStaIp", g_persistent.wifiStaticIp);
        if (rv != ESP_OK) {
          ESP_LOGE(TAG, "Failed to update static IP [%s]", esp_err_to_name(rv));
        }
      }

      // Static netmask
      if (ESP_OK == (rv = httpd_query_key_value(buf, "static_netmask", param, WEBPAGE_PARAM_SIZE))) {
        char *pdecoded = urlDecode(param);
        if (NULL == pdecoded) {
          free(param);
          free(buf);
          return ESP_ERR_NO_MEM;
        }
        strncpy(g_persistent.wifiStaticNetmask, pdecoded, sizeof(g_persistent.wifiStaticNetmask) - 1);
        g_persistent.wifiStaticNetmask[sizeof(g_persistent.wifiStaticNetmask) - 1] = '\0';
        free(pdecoded);
        rv = nvs_set_str(g_nvsHandle, "wifiStaMask", g_persistent.wifiStaticNetmask);
        if (rv != ESP_OK) {
          ESP_LOGE(TAG, "Failed to update static netmask [%s]", esp_err_to_name(rv));
        }
      }

      // Static gateway
      if (ESP_OK == (rv = httpd_query_key_value(buf, "static_gateway", param, WEBPAGE_PARAM_SIZE))) {
        char *pdecoded = urlDecode(param);
        if (NULL == pdecoded) {
          free(param);
          free(buf);
          return ESP_ERR_NO_MEM;
        }
        strncpy(g_persistent.wifiStaticGateway, pdecoded, sizeof(g_persistent.wifiStaticGateway) - 1);
        g_persistent.wifiStaticGateway[sizeof(g_persistent.wifiStaticGateway) - 1] = '\0';
        free(pdecoded);
        rv = nvs_set_str(g_nvsHandle, "wifiStaGw", g_persistent.wifiStaticGateway);
        if (rv != ESP_OK) {
          ESP_LOGE(TAG, "Failed to update static gateway [%s]", esp_err_to_name(rv));
        }
      }

      // Static DNS server
      if (ESP_OK == (rv = httpd_query_key_value(buf, "static_dns", param, WEBPAGE_PARAM_SIZE))) {
        char *pdecoded = urlDecode(param);
        if (NULL == pdecoded) {
          free(param);
          free(buf);
          return ESP_ERR_NO_MEM;
        }
        strncpy(g_persistent.wifiStaticDns, pdecoded, sizeof(g_persistent.wifiStaticDns) - 1);
        g_persistent.wifiStaticDns[sizeof(g_persistent.wifiStaticDns) - 1] = '\0';
        free(pdecoded);
        rv = nvs_set_str(g_nvsHandle, "wifiStaDns", g_persistent.wifiStaticDns);
        if (rv != ESP_OK) {
          ESP_LOGE(TAG, "Failed to update static DNS [%s]", esp_err_to_name(rv));
        }
      }

      rv = nvs_commit(g_nvsHandle);
      if (rv != ESP_OK) {
        ESP_LOGE(TAG, "Failed to commit updates to nvs\n");
      }

      free(param);
    }

    free(buf);
  }
  const char *resp_str =
    "<html><head><meta charset='utf-8'><meta http-equiv=\"refresh\" content=\"2;url=cfgwifi\" "
    "/><style>" WEBPAGE_STYLE_CSS "</style></head><body><h2 class=\"name\">Saving WiFi configuration...<br>"
    "Device will apply network settings and reconnect.</h2></body></html>";
  httpd_resp_send(req, resp_str, HTTPD_RESP_USE_STRLEN);

  return ESP_OK;
}

// ----------------------------------------------------------------------------

///////////////////////////////////////////////////////////////////////////////
// config_vscplink_get_handler
//

static esp_err_t
config_vscplink_get_handler(httpd_req_t *req)
{
  // esp_err_t rv;
  char *buf;
  // char *temp;

  char *req_buf;
  size_t req_buf_len;

  buf = (char *) calloc(CHUNK_BUFSIZE, 1);
  if (NULL == buf) {
    return ESP_ERR_NO_MEM;
  }

  // Get application info data
  const esp_app_desc_t *appDescr = esp_app_get_description();

  // Get header value string length and allocate memory for length + 1,
  // extra byte for null termination
  req_buf_len = httpd_req_get_hdr_value_len(req, "Name") + 1;
  if (req_buf_len > 1) {
    req_buf = (char *) malloc(req_buf_len);
    // Copy null terminated value string into buffer
    if (httpd_req_get_hdr_value_str(req, "Host", req_buf, req_buf_len) == ESP_OK) {
      ESP_LOGD(TAG, "Found header => Host: %s", req_buf);
    }
    free(req_buf);
  }

  sprintf(buf, WEBPAGE_START_TEMPLATE, g_persistent.nodeName, "VSCP Link Srv Configuration");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "<div><form id=but3 class=\"button\" action='/docfgvscplink' method='get'><fieldset>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  // Enable
  sprintf(buf, "<input type=\"checkbox\" name=\"enable\" value=\"true\" ");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
  sprintf(buf, "%s><label for=\"lr\"> Enable</label>", g_persistent.enableVscpLink ? "checked" : "");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "<br>Port:<input type=\"text\" name=\"port\" value=\"%d\" >", g_persistent.vscplinkPort);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "Username:<input type=\"text\" name=\"user\" value=\"%s\" >", g_persistent.vscplinkUser);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "Password:<input type=\"password\" name=\"password\" value=\"%s\" >", g_persistent.vscplinkPw);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "<button class=\"bgrn bgrn:hover\">Save</button></fieldset></form></div>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, WEBPAGE_CONFIG_END_TEMPLATE, appDescr->version, g_persistent.nodeName);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  httpd_resp_send_chunk(req, NULL, 0);

  free(buf);

  return ESP_OK;
}

///////////////////////////////////////////////////////////////////////////////
// do_config_vscplink_get_handler
//

static esp_err_t
do_config_vscplink_get_handler(httpd_req_t *req)
{
  esp_err_t rv;
  char *buf;
  size_t buf_len;

  // Read URL query string length and allocate memory for length + 1,
  // extra byte for null termination
  buf_len = httpd_req_get_url_query_len(req) + 1;
  if (buf_len > 1) {
    buf = (char *) malloc(buf_len);
    if (httpd_req_get_url_query_str(req, buf, buf_len) == ESP_OK) {

      ESP_LOGD(TAG, "Found URL query => %s", buf);
      char *param = malloc(WEBPAGE_PARAM_SIZE);
      if (NULL == param) {
        return ESP_ERR_NO_MEM;
        free(param);
      }

      // Enable
      if (ESP_OK == (rv = httpd_query_key_value(buf, "enable", param, WEBPAGE_PARAM_SIZE))) {
        ESP_LOGD(TAG, "Found query parameter => enable=%s", param);
        if (NULL != strstr(param, "true")) {
          g_persistent.enableVscpLink = true;
        }
      }
      else {
        g_persistent.enableVscpLink = false;
      }

      // Write changed value to persistent storage
      rv = nvs_set_u8(g_nvsHandle, "vscplinkEnable", g_persistent.enableVscpLink);
      if (rv != ESP_OK) {
        ESP_LOGE(TAG, "Failed to update vscp link srv enable [%s]", esp_err_to_name(rv));
      }

      // port
      if (ESP_OK == (rv = httpd_query_key_value(buf, "port", param, WEBPAGE_PARAM_SIZE))) {
        ESP_LOGD(TAG, "Found query parameter => port=%s", param);
        g_persistent.vscplinkPort = atoi(param);
        // Write changed value to persistent storage
        rv = nvs_set_u16(g_nvsHandle, "vscplinkPort", g_persistent.vscplinkPort);
        if (rv != ESP_OK) {
          ESP_LOGE(TAG, "Failed to update VSCP link srv port [%s]", esp_err_to_name(rv));
        }
      }
      else {
        ESP_LOGE(TAG, "Error getting VSCP link srv port => rv=%d", rv);
      }

      // username
      if (ESP_OK == (rv = httpd_query_key_value(buf, "user", param, WEBPAGE_PARAM_SIZE))) {
        char *pdecoded = urlDecode(param);
        if (NULL == pdecoded) {
          free(param);
          free(buf);
          return ESP_ERR_NO_MEM;
        }
        ESP_LOGD(TAG, "Found query parameter => user=%s", pdecoded);
        strncpy(g_persistent.vscplinkUser, pdecoded, sizeof(g_persistent.vscplinkUser) - 1);
        // Write changed value to persistent storage
        rv = nvs_set_str(g_nvsHandle, "vscplinkUser", g_persistent.vscplinkUser);
        if (rv != ESP_OK) {
          ESP_LOGE(TAG, "Failed to update VSCP link srv user [%s]", esp_err_to_name(rv));
        }
      }
      else {
        ESP_LOGE(TAG, "Error getting VSCP link srv username => rv=%d", rv);
      }

      // password
      if (ESP_OK == (rv = httpd_query_key_value(buf, "password", param, WEBPAGE_PARAM_SIZE))) {
        char *pdecoded = urlDecode(param);
        if (NULL == pdecoded) {
          free(param);
          free(buf);
          return ESP_ERR_NO_MEM;
        }
        ESP_LOGD(TAG, "Found query parameter => password=%s", pdecoded);
        strncpy(g_persistent.vscplinkPw, pdecoded, sizeof(g_persistent.vscplinkPw) - 1);
        // Write changed value to persistent storage
        rv = nvs_set_str(g_nvsHandle, "vscplinkPw", g_persistent.vscplinkPw);
        if (rv != ESP_OK) {
          ESP_LOGE(TAG, "Failed to update VSCP link srv password err=%02X [%s]", rv, esp_err_to_name(rv));
        }
      }
      else {
        ESP_LOGE(TAG, "Error getting VSCP link srv password => rv=%d", rv);
      }

      // key
      if (ESP_OK == (rv = httpd_query_key_value(buf, "key", param, WEBPAGE_PARAM_SIZE))) {
        ESP_LOGD(TAG, "Found query parameter => key=%s", param);
        memset(g_persistent.pmk, 0, 32);
        vscp_fwhlp_hex2bin(g_persistent.pmk, 32, param);

        // Write changed value to persistent storage
        rv = nvs_set_blob(g_nvsHandle, "vscp_key", g_persistent.pmk, sizeof(g_persistent.pmk));
        if (rv != ESP_OK) {
          ESP_LOGE(TAG, "Failed to write VSCP link key to nvs. rv=%d", rv);
        }
      }
      else {
        ESP_LOGE(TAG, "Error getting VSCP link key => rv=%d", rv);
      }

      rv = nvs_commit(g_nvsHandle);
      if (rv != ESP_OK) {
        ESP_LOGE(TAG, "Failed to commit updates to nvs\n");
      }

      free(param);
    }

    free(buf);
  }
  const char *resp_str =
    "<html><head><meta charset='utf-8'><meta http-equiv=\"refresh\" content=\"1;url=cfgvscplink\" "
    "/><style>" WEBPAGE_STYLE_CSS "</style></head><body><h2 class=\"name\">saving module data...</h2></body></html>";
  httpd_resp_send(req, resp_str, HTTPD_RESP_USE_STRLEN);

  return ESP_OK;
}

// ----------------------------------------------------------------------------

///////////////////////////////////////////////////////////////////////////////
// config_mqtt_get_handler
//

static esp_err_t
config_mqtt_get_handler(httpd_req_t *req)
{
  char *buf;

  char *req_buf;
  size_t req_buf_len;

  buf = (char *) calloc(CHUNK_BUFSIZE, 1);
  if (NULL == buf) {
    return ESP_ERR_NO_MEM;
  }

  // Get application info data
  const esp_app_desc_t *appDescr = esp_app_get_description();

  // Get header value string length and allocate memory for length + 1,
  // extra byte for null termination
  req_buf_len = httpd_req_get_hdr_value_len(req, "Host") + 1;
  if (req_buf_len > 1) {
    req_buf = (char *) malloc(req_buf_len);
    // Copy null terminated value string into buffer
    if (httpd_req_get_hdr_value_str(req, "Host", req_buf, req_buf_len) == ESP_OK) {
      ESP_LOGD(TAG, "Found header => Host: %s", req_buf);
    }
    free(req_buf);
  }

  sprintf(buf, WEBPAGE_START_TEMPLATE, g_persistent.nodeName, "MQTT Configuration");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "<div><form id=but3 class=\"button\" action='/docfgmqtt' method='get'><fieldset>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  // Enable
  sprintf(buf, "<input type=\"checkbox\" name=\"enable\" value=\"true\" ");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
  sprintf(buf, "%s><label for=\"lr\"> Enable</label>", g_persistent.enableMqtt ? "checked" : "");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf,
          "<br><br>Host: (without mqtt:// or other prefix)<input type=\"text\" name=\"url\" value=\"%s\" >",
          g_persistent.mqttUrl);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "Port:<input type=\"text\" name=\"port\" value=\"%d\" >", g_persistent.mqttPort);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "Client id:<input type=\"text\" name=\"client\" value=\"%s\" >", g_persistent.mqttClientId);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "Username:<input type=\"text\" name=\"user\" value=\"%s\" >", g_persistent.mqttUser);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "Password:<input type=\"password\" name=\"password\" value=\"%s\" >", g_persistent.mqttPw);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "Subscribe:<input type=\"text\" name=\"sub\" value=\"%s\" >", g_persistent.mqttSubTopic);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "Publish:<input type=\"text\" name=\"pub\" value=\"%s\" >", g_persistent.mqttPubTopic);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  // MQTT format
  sprintf(buf, "<br>MQTT format:<select name=\"format\">");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "<option value=\"0\" %s>JSON</option>", (g_persistent.mqttFormat == MQTT_FORMAT_JSON) ? "selected" : "");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "<option value=\"1\" %s>XML</option>", (g_persistent.mqttFormat == MQTT_FORMAT_XML) ? "selected" : "");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf,
          "<option value=\"2\" %s>String</option>",
          (g_persistent.mqttFormat == MQTT_FORMAT_STRING) ? "selected" : "");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf,
          "<option value=\"3\" %s>Binary</option>",
          (g_persistent.mqttFormat == MQTT_FORMAT_BINARY) ? "selected" : "");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "</select>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  // QoS selection
  sprintf(buf, "<br>QoS:<select name=\"qos\">");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
  sprintf(buf, "<option value=\"0\" %s>0 - At most once</option>", g_persistent.mqttQos == 0 ? "selected" : "");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
  sprintf(buf, "<option value=\"1\" %s>1 - At least once</option>", g_persistent.mqttQos == 1 ? "selected" : "");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
  sprintf(buf, "<option value=\"2\" %s>2 - Exactly once</option>", g_persistent.mqttQos == 2 ? "selected" : "");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
  sprintf(buf, "</select>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  // Retain flag
  sprintf(buf,
          " <input type=\"checkbox\" name=\"retain\" value=\"true\" %s><label> Retain</label>",
          g_persistent.mqttRetain ? "checked" : "");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "<br><br><fieldset><legend>TLS/SSL Configuration</legend>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  // Enable TLS
  sprintf(buf, "<input type=\"checkbox\" name=\"enable_tls\" value=\"true\" ");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
  sprintf(buf, "%s><label for=\"tls\"> Enable TLS/SSL</label>", g_persistent.enableMqttTls ? "checked" : "");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf,
          "<br><br>CA Certificate (PEM):<br><textarea name=\"ca_cert\" rows=\"6\" cols=\"60\">%s</textarea>",
          g_persistent.mqttCaCert);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf,
          "<br>Client Certificate (PEM):<br><textarea name=\"client_cert\" rows=\"6\" cols=\"60\">%s</textarea>",
          g_persistent.mqttClientCert);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf,
          "<br>Client Private Key (PEM):<br><textarea name=\"client_key\" rows=\"6\" cols=\"60\">%s</textarea>",
          g_persistent.mqttClientKey);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "</fieldset>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "<button class=\"bgrn bgrn:hover\">Save</button></fieldset></form></div>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, WEBPAGE_CONFIG_END_TEMPLATE, appDescr->version, g_persistent.nodeName);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  httpd_resp_send_chunk(req, NULL, 0);

  free(buf);

  return ESP_OK;
}

///////////////////////////////////////////////////////////////////////////////
// do_config_mqtt_get_handler
//

static esp_err_t
do_config_mqtt_get_handler(httpd_req_t *req)
{
  esp_err_t rv;
  char *buf;
  size_t buf_len;

  // Read URL query string length and allocate memory for length + 1,
  // extra byte for null termination
  buf_len = httpd_req_get_url_query_len(req) + 1;
  if (buf_len > 1) {
    buf = malloc(buf_len);
    if (httpd_req_get_url_query_str(req, buf, buf_len) == ESP_OK) {

      ESP_LOGD(TAG, "Found URL query => %s", buf);
      char *param = (char *) malloc(WEBPAGE_PARAM_SIZE);
      if (NULL == param) {
        return ESP_ERR_NO_MEM;
        free(param);
      }

      // Enable
      if (ESP_OK == (rv = httpd_query_key_value(buf, "enable", param, WEBPAGE_PARAM_SIZE))) {
        ESP_LOGD(TAG, "Found query parameter => enable=%s", param);
        if (NULL != strstr(param, "true")) {
          g_persistent.enableMqtt = true;
        }
      }
      else {
        g_persistent.enableMqtt = false;
      }

      // Write changed value to persistent storage
      nvs_set_u8(g_nvsHandle, "enableMqtt", g_persistent.enableMqtt);
      if (rv != ESP_OK) {
        ESP_LOGE(TAG, "Failed to update MQTT enable [%s]", esp_err_to_name(rv));
      }

      // url
      if (ESP_OK == (rv = httpd_query_key_value(buf, "url", param, WEBPAGE_PARAM_SIZE))) {
        char *pdecoded = urlDecode(param);
        if (NULL == pdecoded) {
          free(param);
          free(buf);
          return ESP_ERR_NO_MEM;
        }
        ESP_LOGD(TAG, "Found query parameter => url=%s", pdecoded);
        strncpy(g_persistent.mqttUrl, pdecoded, sizeof(g_persistent.mqttUrl) - 1);
        free(pdecoded);
        // Write changed value to persistent storage
        rv = nvs_set_str(g_nvsHandle, "mqttUrl", g_persistent.mqttUrl);
        if (rv != ESP_OK) {
          ESP_LOGE(TAG, "Failed to update MQTT url [%s]", esp_err_to_name(rv));
        }
      }
      else {
        ESP_LOGE(TAG, "Error getting MQTT URL => rv=%d", rv);
      }

      // port
      if (ESP_OK == (rv = httpd_query_key_value(buf, "port", param, WEBPAGE_PARAM_SIZE))) {
        ESP_LOGD(TAG, "Found query parameter => port=%s", param);
        g_persistent.mqttPort = atoi(param);
        // Write changed value to persistent storage
        rv = nvs_set_u16(g_nvsHandle, "mqttPort", g_persistent.mqttPort);
        if (rv != ESP_OK) {
          ESP_LOGE(TAG, "Failed to update MQTT port [%s]", esp_err_to_name(rv));
        }
      }
      else {
        ESP_LOGE(TAG, "Error getting MQTT port => rv=%d", rv);
      }

      // clientid
      if (ESP_OK == (rv = httpd_query_key_value(buf, "client", param, WEBPAGE_PARAM_SIZE))) {
        char *pdecoded = urlDecode(param);
        if (NULL == pdecoded) {
          free(param);
          free(buf);
          return ESP_ERR_NO_MEM;
        }
        ESP_LOGD(TAG, "Found query parameter => clientid=%s", pdecoded);
        strncpy(g_persistent.mqttClientId, pdecoded, sizeof(g_persistent.mqttClientId) - 1);
        // Write changed value to persistent storage
        rv = nvs_set_str(g_nvsHandle, "mqttClientId", g_persistent.mqttClientId);
        if (rv != ESP_OK) {
          ESP_LOGE(TAG, "Failed to update MQTT clientid [%s]", esp_err_to_name(rv));
        }
      }
      else {
        ESP_LOGE(TAG, "Error getting MQTT clientid => rv=%d", rv);
      }

      // user
      if (ESP_OK == (rv = httpd_query_key_value(buf, "user", param, WEBPAGE_PARAM_SIZE))) {
        char *pdecoded = urlDecode(param);
        if (NULL == pdecoded) {
          free(param);
          free(buf);
          return ESP_ERR_NO_MEM;
        }
        ESP_LOGD(TAG, "Found query parameter => user=%s", pdecoded);
        strncpy(g_persistent.mqttUser, pdecoded, sizeof(g_persistent.mqttUser) - 1);
        // Write changed value to persistent storage
        rv = nvs_set_str(g_nvsHandle, "mqttUser", g_persistent.mqttUser);
        if (rv != ESP_OK) {
          ESP_LOGE(TAG, "Failed to update MQTT user [%s]", esp_err_to_name(rv));
        }
      }
      else {
        ESP_LOGE(TAG, "Error getting MQTT user => rv=%d", rv);
      }

      // password
      if (ESP_OK == (rv = httpd_query_key_value(buf, "password", param, WEBPAGE_PARAM_SIZE))) {
        char *pdecoded = urlDecode(param);
        if (NULL == pdecoded) {
          free(param);
          free(buf);
          return ESP_ERR_NO_MEM;
        }
        ESP_LOGD(TAG, "Found query parameter => password=%s", pdecoded);
        strncpy(g_persistent.mqttPw, pdecoded, sizeof(g_persistent.mqttPw) - 1);
        // Write changed value to persistent storage
        rv = nvs_set_str(g_nvsHandle, "mqttPw", g_persistent.mqttPw);
        if (rv != ESP_OK) {
          ESP_LOGE(TAG, "Failed to update MQTT password [%s]", esp_err_to_name(rv));
        }
      }
      else {
        ESP_LOGE(TAG, "Error getting MQTT password => rv=%d", rv);
      }

      // Subscribe
      if (ESP_OK == (rv = httpd_query_key_value(buf, "sub", param, WEBPAGE_PARAM_SIZE))) {
        char *pdecoded = urlDecode(param);
        if (NULL == pdecoded) {
          free(param);
          free(buf);
          return ESP_ERR_NO_MEM;
        }
        ESP_LOGD(TAG, "Found query parameter => sub=%s", pdecoded);
        strncpy(g_persistent.mqttSubTopic, pdecoded, sizeof(g_persistent.mqttSubTopic) - 1);
        free(pdecoded);
        // Write changed value to persistent storage
        rv = nvs_set_str(g_nvsHandle, "mqttSubTopic", g_persistent.mqttSubTopic);
        if (rv != ESP_OK) {
          ESP_LOGE(TAG, "Failed to update MQTT sub [%s]", esp_err_to_name(rv));
        }
      }
      else {
        ESP_LOGE(TAG, "Error getting MQTT sub => rv=%d", rv);
      }

      // Publish
      if (ESP_OK == (rv = httpd_query_key_value(buf, "pub", param, WEBPAGE_PARAM_SIZE))) {
        char *pdecoded = urlDecode(param);
        if (NULL == pdecoded) {
          free(param);
          free(buf);
          return ESP_ERR_NO_MEM;
        }
        ESP_LOGD(TAG, "Found query parameter => pub=%s", pdecoded);
        strncpy(g_persistent.mqttPubTopic, pdecoded, sizeof(g_persistent.mqttPubTopic) - 1);
        free(pdecoded);
        // Write changed value to persistent storage
        rv = nvs_set_str(g_nvsHandle, "mqttPubTopic", g_persistent.mqttPubTopic);
        if (rv != ESP_OK) {
          ESP_LOGE(TAG, "Failed to update MQTT pub [%s]", esp_err_to_name(rv));
        }
      }
      else {
        ESP_LOGE(TAG, "Error getting MQTT pub => rv=%d", rv);
      }

      // QoS
      if (ESP_OK == (rv = httpd_query_key_value(buf, "qos", param, WEBPAGE_PARAM_SIZE))) {
        ESP_LOGD(TAG, "Found query parameter => qos=%s", param);
        g_persistent.mqttQos = atoi(param);
        // Clamp to valid range (0-2)
        if (g_persistent.mqttQos > 2) {
          g_persistent.mqttQos = 0;
        }
        // Write changed value to persistent storage
        rv = nvs_set_u8(g_nvsHandle, "mqttQos", g_persistent.mqttQos);
        if (rv != ESP_OK) {
          ESP_LOGE(TAG, "Failed to update MQTT QoS [%s]", esp_err_to_name(rv));
        }
      }
      else {
        ESP_LOGE(TAG, "Error getting MQTT QoS => rv=%d", rv);
      }

      // Retain
      if (ESP_OK == (rv = httpd_query_key_value(buf, "retain", param, WEBPAGE_PARAM_SIZE))) {
        ESP_LOGD(TAG, "Found query parameter => retain=%s", param);
        if (NULL != strstr(param, "true")) {
          g_persistent.mqttRetain = true;
        }
      }
      else {
        g_persistent.mqttRetain = false;
      }

      // MQTT format
      if (ESP_OK == (rv = httpd_query_key_value(buf, "format", param, WEBPAGE_PARAM_SIZE))) {
        ESP_LOGD(TAG, "Found query parameter => format=%s", param);
        g_persistent.mqttFormat = atoi(param);
        // Clamp to valid range (0-3)
        if (g_persistent.mqttFormat > 3) {
          g_persistent.mqttFormat = MQTT_FORMAT_JSON;
        }
        // Write changed value to persistent storage
        rv = nvs_set_u8(g_nvsHandle, "mqttFormat", g_persistent.mqttFormat);
        if (rv != ESP_OK) {
          ESP_LOGE(TAG, "Failed to update MQTT format [%s]", esp_err_to_name(rv));
        }
      }
      else {
        ESP_LOGE(TAG, "Error getting MQTT format => rv=%d", rv);
      }

      // Enable TLS
      if (ESP_OK == (rv = httpd_query_key_value(buf, "enable_tls", param, WEBPAGE_PARAM_SIZE))) {
        ESP_LOGD(TAG, "Found query parameter => enable_tls=%s", param);
        if (NULL != strstr(param, "true")) {
          g_persistent.enableMqttTls = true;
        }
      }
      else {
        g_persistent.enableMqttTls = false;
      }

      // Write changed value to persistent storage
      rv = nvs_set_u8(g_nvsHandle, "enableMqttTls", g_persistent.enableMqttTls);
      if (rv != ESP_OK) {
        ESP_LOGE(TAG, "Failed to update MQTT TLS enable [%s]", esp_err_to_name(rv));
      }

      // CA Certificate
      if (ESP_OK == (rv = httpd_query_key_value(buf, "ca_cert", param, WEBPAGE_PARAM_SIZE))) {
        char *pdecoded = urlDecode(param);
        if (NULL == pdecoded) {
          free(param);
          free(buf);
          return ESP_ERR_NO_MEM;
        }
        ESP_LOGD(TAG, "Found query parameter => ca_cert (length=%d)", strlen(pdecoded));
        strncpy(g_persistent.mqttCaCert, pdecoded, sizeof(g_persistent.mqttCaCert) - 1);
        free(pdecoded);
        // Write changed value to persistent storage
        rv = nvs_set_str(g_nvsHandle, "mqttCaCert", g_persistent.mqttCaCert);
        if (rv != ESP_OK) {
          ESP_LOGE(TAG, "Failed to update MQTT CA cert [%s]", esp_err_to_name(rv));
        }
      }
      else {
        ESP_LOGE(TAG, "Error getting MQTT CA cert => rv=%d", rv);
      }

      // Client Certificate
      if (ESP_OK == (rv = httpd_query_key_value(buf, "client_cert", param, WEBPAGE_PARAM_SIZE))) {
        char *pdecoded = urlDecode(param);
        if (NULL == pdecoded) {
          free(param);
          free(buf);
          return ESP_ERR_NO_MEM;
        }
        ESP_LOGD(TAG, "Found query parameter => client_cert (length=%d)", strlen(pdecoded));
        strncpy(g_persistent.mqttClientCert, pdecoded, sizeof(g_persistent.mqttClientCert) - 1);
        free(pdecoded);
        // Write changed value to persistent storage
        rv = nvs_set_str(g_nvsHandle, "mqttClientCert", g_persistent.mqttClientCert);
        if (rv != ESP_OK) {
          ESP_LOGE(TAG, "Failed to update MQTT client cert [%s]", esp_err_to_name(rv));
        }
      }
      else {
        ESP_LOGE(TAG, "Error getting MQTT client cert => rv=%d", rv);
      }

      // Client Private Key
      if (ESP_OK == (rv = httpd_query_key_value(buf, "client_key", param, WEBPAGE_PARAM_SIZE))) {
        char *pdecoded = urlDecode(param);
        if (NULL == pdecoded) {
          free(param);
          free(buf);
          return ESP_ERR_NO_MEM;
        }
        ESP_LOGD(TAG, "Found query parameter => client_key (length=%d)", strlen(pdecoded));
        strncpy(g_persistent.mqttClientKey, pdecoded, sizeof(g_persistent.mqttClientKey) - 1);
        free(pdecoded);
        // Write changed value to persistent storage
        rv = nvs_set_str(g_nvsHandle, "mqttClientKey", g_persistent.mqttClientKey);
        if (rv != ESP_OK) {
          ESP_LOGE(TAG, "Failed to update MQTT client key [%s]", esp_err_to_name(rv));
        }
      }
      else {
        ESP_LOGE(TAG, "Error getting MQTT client key => rv=%d", rv);
      }

      // Write changed value to persistent storage
      rv = nvs_set_u8(g_nvsHandle, "mqttRetain", g_persistent.mqttRetain);
      if (rv != ESP_OK) {
        ESP_LOGE(TAG, "Failed to update MQTT retain [%s]", esp_err_to_name(rv));
      }

      rv = nvs_commit(g_nvsHandle);
      if (rv != ESP_OK) {
        ESP_LOGE(TAG, "Failed to commit updates to nvs\n");
      }

      free(param);
    }

    free(buf);
  }
  const char *resp_str =
    "<html><head><meta charset='utf-8'><meta http-equiv=\"refresh\" content=\"1;url=cfgmqtt\" "
    "/><style>" WEBPAGE_STYLE_CSS "</style></head><body><h2 class=\"name\">saving module data...</h2></body></html>";
  httpd_resp_send(req, resp_str, HTTPD_RESP_USE_STRLEN);

  return ESP_OK;
}

// ----------------------------------------------------------------------------

///////////////////////////////////////////////////////////////////////////////
// config_multicast_get_handler
//

static esp_err_t
config_multicast_get_handler(httpd_req_t *req)
{
  // esp_err_t rv;
  char *buf;
  // char *temp;

  char *req_buf;
  size_t req_buf_len;

  buf = (char *) calloc(CHUNK_BUFSIZE, 1);
  if (NULL == buf) {
    return ESP_ERR_NO_MEM;
  }

  // Get application info data
  const esp_app_desc_t *appDescr = esp_app_get_description();

  // Get header value string length and allocate memory for length + 1,
  // extra byte for null termination
  req_buf_len = httpd_req_get_hdr_value_len(req, "Host") + 1;
  if (req_buf_len > 1) {
    req_buf = (char *) malloc(req_buf_len);
    // Copy null terminated value string into buffer
    if (httpd_req_get_hdr_value_str(req, "Host", req_buf, req_buf_len) == ESP_OK) {
      ESP_LOGD(TAG, "Found header => Host: %s", req_buf);
    }
    free(req_buf);
  }

  sprintf(buf, WEBPAGE_START_TEMPLATE, g_persistent.nodeName, "Multicast Configuration");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "<div><form id=but3 class=\"button\" action='/docfgmulticast' method='get'><fieldset>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  // Enable
  sprintf(buf, "<input type=\"checkbox\" name=\"enable\" value=\"true\" ");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
  sprintf(buf, "%s><label for=\"lr\"> Enable</label>", g_persistent.enableMulticast ? "checked" : "");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf,
          "<br><br>Multicast IP address (224.0.23.158):<input type=\"text\" name=\"url\" value=\"%s\" >",
          g_persistent.multicastUrl);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "Port (9598):<input type=\"text\" name=\"port\" value=\"%d\" >", g_persistent.multicastPort);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "TTL:<input type=\"text\" name=\"ttl\" value=\"%d\" >", g_persistent.multicastTtl);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  // bMcastEncrypt
  sprintf(buf, "<input type=\"checkbox\" name=\"bMcastEncrypt\" value=\"true\" ");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
  sprintf(buf, "%s><label for=\"lr\"> Enable Encryption</label>", g_persistent.bMcastEncrypt ? "checked" : "");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  // bMcastHbeat
  sprintf(buf, "<br><input type=\"checkbox\" name=\"bMcastHbeat\" value=\"true\" ");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
  sprintf(buf,
          "%s><label for=\"lr\"> Enable VSCP heartbeat on port 9598</label>",
          g_persistent.bHeartbeat ? "checked" : "");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "<button class=\"bgrn bgrn:hover\">Save</button></fieldset></form></div>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, WEBPAGE_CONFIG_END_TEMPLATE, appDescr->version, g_persistent.nodeName);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  httpd_resp_send_chunk(req, NULL, 0);

  free(buf);

  return ESP_OK;
}

///////////////////////////////////////////////////////////////////////////////
// do_config_multicast_get_handler
//

static esp_err_t
do_config_multicast_get_handler(httpd_req_t *req)
{
  esp_err_t rv;
  char *buf;
  size_t buf_len;

  // Read URL query string length and allocate memory for length + 1,
  // extra byte for null termination
  buf_len = httpd_req_get_url_query_len(req) + 1;
  if (buf_len > 1) {
    buf = malloc(buf_len);
    if (httpd_req_get_url_query_str(req, buf, buf_len) == ESP_OK) {

      ESP_LOGD(TAG, "Found URL query => %s", buf);
      char *param = (char *) malloc(WEBPAGE_PARAM_SIZE);
      if (NULL == param) {
        return ESP_ERR_NO_MEM;
        free(param);
      }

      // Enable
      if (ESP_OK == (rv = httpd_query_key_value(buf, "enable", param, WEBPAGE_PARAM_SIZE))) {
        ESP_LOGD(TAG, "Found query parameter => enable=%s", param);
        if (NULL != strstr(param, "true")) {
          g_persistent.enableMulticast = true;
        }
      }
      else {
        g_persistent.enableMulticast = false;
      }

      // Write changed value to persistent storage
      nvs_set_u8(g_nvsHandle, "enableMulticast", g_persistent.enableMulticast);
      if (rv != ESP_OK) {
        ESP_LOGE(TAG, "Failed to update multicast enable [%s]", esp_err_to_name(rv));
      }

      // url
      if (ESP_OK == (rv = httpd_query_key_value(buf, "url", param, WEBPAGE_PARAM_SIZE))) {
        char *pdecoded = urlDecode(param);
        if (NULL == pdecoded) {
          free(param);
          free(buf);
          return ESP_ERR_NO_MEM;
        }
        ESP_LOGD(TAG, "Found query parameter => url=%s", pdecoded);
        strncpy(g_persistent.multicastUrl, pdecoded, sizeof(g_persistent.multicastUrl) - 1);
        free(pdecoded);
        // Write changed value to persistent storage
        rv = nvs_set_str(g_nvsHandle, "multicastUrl", g_persistent.multicastUrl);
        if (rv != ESP_OK) {
          ESP_LOGE(TAG, "Failed to update multicast address [%s]", esp_err_to_name(rv));
        }
      }
      else {
        ESP_LOGE(TAG, "Error getting multicast URL => rv=%d", rv);
      }

      // port
      if (ESP_OK == (rv = httpd_query_key_value(buf, "port", param, WEBPAGE_PARAM_SIZE))) {
        ESP_LOGD(TAG, "Found query parameter => port=%s", param);
        g_persistent.multicastPort = atoi(param);
        // Write changed value to persistent storage
        rv = nvs_set_u16(g_nvsHandle, "multicastPort", g_persistent.multicastPort);
        if (rv != ESP_OK) {
          ESP_LOGE(TAG, "Failed to update multicast port [%s]", esp_err_to_name(rv));
        }
      }
      else {
        ESP_LOGE(TAG, "Error getting multicast port => rv=%d", rv);
      }

      // ttl
      if (ESP_OK == (rv = httpd_query_key_value(buf, "ttl", param, WEBPAGE_PARAM_SIZE))) {
        ESP_LOGD(TAG, "Found query parameter => ttl=%s", param);
        g_persistent.multicastTtl = atoi(param);
        // Write changed value to persistent storage
        rv = nvs_set_u8(g_nvsHandle, "multicastTtl", g_persistent.multicastTtl);
        if (rv != ESP_OK) {
          ESP_LOGE(TAG, "Failed to update multicast ttl [%s]", esp_err_to_name(rv));
        }
      }
      else {
        ESP_LOGE(TAG, "Error getting multicast ttl => rv=%d", rv);
      }

      // EnableEncryption
      if (ESP_OK == (rv = httpd_query_key_value(buf, "bMcastEncrypt", param, WEBPAGE_PARAM_SIZE))) {
        ESP_LOGD(TAG, "Found query parameter => bMcastEncrypt=%s", param);
        if (NULL != strstr(param, "true")) {
          g_persistent.bMcastEncrypt = true;
        }
      }
      else {
        g_persistent.bMcastEncrypt = false;
      }
      // Write changed value to persistent storage
      nvs_set_u8(g_nvsHandle, "bMcastEncrypt", g_persistent.bMcastEncrypt);
      if (rv != ESP_OK) {
        ESP_LOGE(TAG, "Failed to update multicast encryption enable [%s]", esp_err_to_name(rv));
      }

      // bMcastHbeat
      if (ESP_OK == (rv = httpd_query_key_value(buf, "bMcastHbeat", param, WEBPAGE_PARAM_SIZE))) {
        ESP_LOGD(TAG, "Found query parameter => bMcastHbeat=%s", param);
        if (NULL != strstr(param, "true")) {
          g_persistent.bHeartbeat = true;
        }
      }
      else {
        g_persistent.bHeartbeat = false;
      }
      // Write changed value to persistent storage
      nvs_set_u8(g_nvsHandle, "bMcastHbeat", g_persistent.bHeartbeat);
      if (rv != ESP_OK) {
        ESP_LOGE(TAG, "Failed to update multicast heartbeat enable [%s]", esp_err_to_name(rv));
      }

      rv = nvs_commit(g_nvsHandle);
      if (rv != ESP_OK) {
        ESP_LOGE(TAG, "Failed to commit updates to nvs\n");
      }

      free(param);
    }

    free(buf);
  }
  const char *resp_str =
    "<html><head><meta charset='utf-8'><meta http-equiv=\"refresh\" content=\"1;url=cfgmulticast\" "
    "/><style>" WEBPAGE_STYLE_CSS "</style></head><body><h2 class=\"name\">saving module data...</h2></body></html>";
  httpd_resp_send(req, resp_str, HTTPD_RESP_USE_STRLEN);

  return ESP_OK;
}

// ----------------------------------------------------------------------------

///////////////////////////////////////////////////////////////////////////////
// config_udp_get_handler
//

static esp_err_t
config_udp_get_handler(httpd_req_t *req)
{
  // esp_err_t rv;
  char *buf;
  // char *temp;

  char *req_buf;
  size_t req_buf_len;

  buf = (char *) calloc(CHUNK_BUFSIZE, 1);
  if (NULL == buf) {
    return ESP_ERR_NO_MEM;
  }

  // Get application info data
  const esp_app_desc_t *appDescr = esp_app_get_description();

  // Get header value string length and allocate memory for length + 1,
  // extra byte for null termination
  req_buf_len = httpd_req_get_hdr_value_len(req, "Host") + 1;
  if (req_buf_len > 1) {
    req_buf = (char *) malloc(req_buf_len);
    // Copy null terminated value string into buffer
    if (httpd_req_get_hdr_value_str(req, "Host", req_buf, req_buf_len) == ESP_OK) {
      ESP_LOGD(TAG, "Found header => Host: %s", req_buf);
    }
    free(req_buf);
  }

  sprintf(buf, WEBPAGE_START_TEMPLATE, g_persistent.nodeName, "UDP Configuration");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "<div><form id=but3 class=\"button\" action='/docfgudp' method='get'><fieldset>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  // EnableUdpRx
  sprintf(buf, "<input type=\"checkbox\" name=\"enablerx\" value=\"true\" ");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
  sprintf(buf, "%s><label for=\"lr\"> Enable RX</label>", g_persistent.enableUdpRx ? "checked" : "");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  // EnableUdpTx
  sprintf(buf, "<input type=\"checkbox\" name=\"enabletx\" value=\"true\" ");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
  sprintf(buf, "%s><label for=\"lr\"> Enable TX</label>", g_persistent.enableUdpTx ? "checked" : "");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(
    buf,
    "<br><br>Host <small> (IPv4, hostname or udp://host)</small>:<input type=\"text\" name=\"url\" value=\"%s\" >",
    g_persistent.udpUrl);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf,
          "Port <small> (default:33333)</small>:<input type=\"text\" name=\"port\" value=\"%d\" >",
          g_persistent.udpPort);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  // bUdpEncrypt
  sprintf(buf, "<input type=\"checkbox\" name=\"enableencryption\" value=\"true\" ");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
  sprintf(buf, "%s><label for=\"lr\"> Enable Encryption</label>", g_persistent.bUdpEncrypt ? "checked" : "");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "<button class=\"bgrn bgrn:hover\">Save</button></fieldset></form></div>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, WEBPAGE_CONFIG_END_TEMPLATE, appDescr->version, g_persistent.nodeName);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  httpd_resp_send_chunk(req, NULL, 0);

  free(buf);

  return ESP_OK;
}

///////////////////////////////////////////////////////////////////////////////
// do_config_udp_get_handler
//

static esp_err_t
do_config_udp_get_handler(httpd_req_t *req)
{
  esp_err_t rv;
  char *buf;
  size_t buf_len;

  // Read URL query string length and allocate memory for length + 1,
  // extra byte for null termination
  buf_len = httpd_req_get_url_query_len(req) + 1;
  if (buf_len > 1) {
    buf = malloc(buf_len);
    if (httpd_req_get_url_query_str(req, buf, buf_len) == ESP_OK) {

      ESP_LOGD(TAG, "Found URL query => %s", buf);
      char *param = (char *) malloc(WEBPAGE_PARAM_SIZE);
      if (NULL == param) {
        return ESP_ERR_NO_MEM;
        free(param);
      }

      // EnableRx
      if (ESP_OK == (rv = httpd_query_key_value(buf, "enablerx", param, WEBPAGE_PARAM_SIZE))) {
        ESP_LOGD(TAG, "Found query parameter => enablerx=%s", param);
        if (NULL != strstr(param, "true")) {
          g_persistent.enableUdpRx = true;
        }
      }
      else {
        g_persistent.enableUdpRx = false;
      }

      // Write changed value to persistent storage
      nvs_set_u8(g_nvsHandle, "enableUdpRx", g_persistent.enableUdpRx);
      if (rv != ESP_OK) {
        ESP_LOGE(TAG, "Failed to update UDP rx enable [%s]", esp_err_to_name(rv));
      }

      // EnableTx
      if (ESP_OK == (rv = httpd_query_key_value(buf, "enabletx", param, WEBPAGE_PARAM_SIZE))) {
        ESP_LOGD(TAG, "Found query parameter => enabletx=%s", param);
        if (NULL != strstr(param, "true")) {
          g_persistent.enableUdpTx = true;
        }
      }
      else {
        g_persistent.enableUdpTx = false;
      }

      // Write changed value to persistent storage
      nvs_set_u8(g_nvsHandle, "enableUdpTx", g_persistent.enableUdpTx);
      if (rv != ESP_OK) {
        ESP_LOGE(TAG, "Failed to update UDP tx enable [%s]", esp_err_to_name(rv));
      }

      // url
      if (ESP_OK == (rv = httpd_query_key_value(buf, "url", param, WEBPAGE_PARAM_SIZE))) {
        char *pdecoded = urlDecode(param);
        if (NULL == pdecoded) {
          free(param);
          free(buf);
          return ESP_ERR_NO_MEM;
        }
        ESP_LOGD(TAG, "Found query parameter => url=%s", pdecoded);
        strncpy(g_persistent.udpUrl, pdecoded, sizeof(g_persistent.udpUrl) - 1);
        free(pdecoded);
        // Write changed value to persistent storage
        rv = nvs_set_str(g_nvsHandle, "udpUrl", g_persistent.udpUrl);
        if (rv != ESP_OK) {
          ESP_LOGE(TAG, "Failed to update UDP url[%s]", esp_err_to_name(rv));
        }
      }
      else {
        ESP_LOGE(TAG, "Error getting MQTT URL => rv=%d", rv);
      }

      // port
      if (ESP_OK == (rv = httpd_query_key_value(buf, "port", param, WEBPAGE_PARAM_SIZE))) {
        ESP_LOGD(TAG, "Found query parameter => port=%s", param);
        g_persistent.udpPort = atoi(param);
        // Write changed value to persistent storage
        rv = nvs_set_u16(g_nvsHandle, "udpPort", g_persistent.udpPort);
        if (rv != ESP_OK) {
          ESP_LOGE(TAG, "Failed to update UDP port [%s]", esp_err_to_name(rv));
        }
      }
      else {
        ESP_LOGE(TAG, "Error getting MQTT port => rv=%d", rv);
      }

      // EnableEncryption
      if (ESP_OK == (rv = httpd_query_key_value(buf, "enableencryption", param, WEBPAGE_PARAM_SIZE))) {
        ESP_LOGD(TAG, "Found query parameter => enableencryption=%s", param);
        if (NULL != strstr(param, "true")) {
          g_persistent.bUdpEncrypt = true;
        }
      }
      else {
        g_persistent.bUdpEncrypt = false;
      }
      // Write changed value to persistent storage
      nvs_set_u8(g_nvsHandle, "bUdpEncrypt", g_persistent.bUdpEncrypt);
      if (rv != ESP_OK) {
        ESP_LOGE(TAG, "Failed to update UDP encryption enable [%s]", esp_err_to_name(rv));
      }

      rv = nvs_commit(g_nvsHandle);
      if (rv != ESP_OK) {
        ESP_LOGE(TAG, "Failed to commit updates to nvs\n");
      }

      free(param);
    }

    free(buf);
  }
  const char *resp_str =
    "<html><head><meta charset='utf-8'><meta http-equiv=\"refresh\" content=\"1;url=cfgudp\" "
    "/><style>" WEBPAGE_STYLE_CSS "</style></head><body><h2 class=\"name\">saving module data...</h2></body></html>";
  httpd_resp_send(req, resp_str, HTTPD_RESP_USE_STRLEN);

  return ESP_OK;
}

// ----------------------------------------------------------------------------

///////////////////////////////////////////////////////////////////////////////
// config_websockets_get_handler
//

static esp_err_t
config_websockets_get_handler(httpd_req_t *req)
{
  // esp_err_t rv;
  char *buf;
  // char *temp;

  char *req_buf;
  size_t req_buf_len;

  buf = (char *) calloc(CHUNK_BUFSIZE, 1);
  if (NULL == buf) {
    return ESP_ERR_NO_MEM;
  }

  // Get application info data
  const esp_app_desc_t *appDescr = esp_app_get_description();

  // Get header value string length and allocate memory for length + 1,
  // extra byte for null termination
  req_buf_len = httpd_req_get_hdr_value_len(req, "Host") + 1;
  if (req_buf_len > 1) {
    req_buf = (char *) malloc(req_buf_len);
    // Copy null terminated value string into buffer
    if (httpd_req_get_hdr_value_str(req, "Host", req_buf, req_buf_len) == ESP_OK) {
      ESP_LOGD(TAG, "Found header => Host: %s", req_buf);
    }
    free(req_buf);
  }

  sprintf(buf, WEBPAGE_START_TEMPLATE, g_persistent.nodeName, "Websockets Configuration");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "<div><form id=but3 class=\"button\" action='/docfgwebsockets' method='get'><fieldset>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  // Enable
  sprintf(buf, "<input type=\"checkbox\" name=\"enable\" value=\"true\" ");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
  sprintf(buf, "%s><label for=\"lr\"> Enable</label>", g_persistent.enableWebsock ? "checked" : "");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "<br>Port:<input type=\"text\" name=\"port\" value=\"%d\" >", g_persistent.websockPort);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "Username:<input type=\"text\" name=\"user\" value=\"%s\" >", g_persistent.websockUser);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "Password:<input type=\"password\" name=\"password\" value=\"%s\" >", g_persistent.websockPw);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "<button class=\"bgrn bgrn:hover\">Save</button></fieldset></form></div>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, WEBPAGE_CONFIG_END_TEMPLATE, appDescr->version, g_persistent.nodeName);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  httpd_resp_send_chunk(req, NULL, 0);

  free(buf);

  return ESP_OK;
}

///////////////////////////////////////////////////////////////////////////////
// do_config_websockets_get_handler
//

static esp_err_t
do_config_websockets_get_handler(httpd_req_t *req)
{
  esp_err_t rv;
  char *buf;
  size_t buf_len;

  // Read URL query string length and allocate memory for length + 1,
  // extra byte for null termination
  buf_len = httpd_req_get_url_query_len(req) + 1;
  if (buf_len > 1) {
    buf = malloc(buf_len);
    if (httpd_req_get_url_query_str(req, buf, buf_len) == ESP_OK) {

      ESP_LOGD(TAG, "Found URL query => %s", buf);
      char *param = (char *) malloc(WEBPAGE_PARAM_SIZE);
      if (NULL == param) {
        return ESP_ERR_NO_MEM;
        free(param);
      }

      // Enable
      if (ESP_OK == (rv = httpd_query_key_value(buf, "enable", param, WEBPAGE_PARAM_SIZE))) {
        ESP_LOGD(TAG, "Found query parameter => enable=%s", param);
        if (NULL != strstr(param, "true")) {
          g_persistent.enableWebsock = true;
        }
      }
      else {
        g_persistent.enableWebsock = false;
      }

      // Write changed value to persistent storage
      nvs_set_u8(g_nvsHandle, "enableWebsock", g_persistent.enableWebsock);
      if (rv != ESP_OK) {
        ESP_LOGE(TAG, "Failed to update Websockets enable [%s]", esp_err_to_name(rv));
      }

      // port
      if (ESP_OK == (rv = httpd_query_key_value(buf, "port", param, WEBPAGE_PARAM_SIZE))) {
        ESP_LOGD(TAG, "Found query parameter => port=%s", param);
        g_persistent.websockPort = atoi(param);
        // Write changed value to persistent storage
        rv = nvs_set_u16(g_nvsHandle, "websockPort", g_persistent.websockPort);
        if (rv != ESP_OK) {
          ESP_LOGE(TAG, "Failed to update Websockets port [%s]", esp_err_to_name(rv));
        }
      }
      else {
        ESP_LOGE(TAG, "Error getting Websockets port => rv=%d", rv);
      }

      // user
      if (ESP_OK == (rv = httpd_query_key_value(buf, "user", param, WEBPAGE_PARAM_SIZE))) {
        char *pdecoded = urlDecode(param);
        if (NULL == pdecoded) {
          free(param);
          free(buf);
          return ESP_ERR_NO_MEM;
        }
        ESP_LOGD(TAG, "Found query parameter => user=%s", pdecoded);
        strncpy(g_persistent.websockUser, pdecoded, sizeof(g_persistent.websockUser) - 1);
        // Write changed value to persistent storage
        rv = nvs_set_str(g_nvsHandle, "websockUser", g_persistent.websockUser);
        if (rv != ESP_OK) {
          ESP_LOGE(TAG, "Failed to update Websockets user[%s]", esp_err_to_name(rv));
        }
      }
      else {
        ESP_LOGE(TAG, "Error getting Websockets user => rv=%d", rv);
      }

      // password
      if (ESP_OK == (rv = httpd_query_key_value(buf, "password", param, WEBPAGE_PARAM_SIZE))) {
        char *pdecoded = urlDecode(param);
        if (NULL == pdecoded) {
          free(param);
          free(buf);
          return ESP_ERR_NO_MEM;
        }
        ESP_LOGD(TAG, "Found query parameter => password=%s", pdecoded);
        strncpy(g_persistent.websockPw, pdecoded, sizeof(g_persistent.websockPw) - 1);
        // Write changed value to persistent storage
        rv = nvs_set_str(g_nvsHandle, "websockPw", g_persistent.websockPw);
        if (rv != ESP_OK) {
          ESP_LOGE(TAG, "Failed to update Websockets password [%s]", esp_err_to_name(rv));
        }
      }
      else {
        ESP_LOGE(TAG, "Error getting Websockets password => rv=%d", rv);
      }

      rv = nvs_commit(g_nvsHandle);
      if (rv != ESP_OK) {
        ESP_LOGE(TAG, "Failed to commit updates to nvs\n");
      }

      free(param);
    }

    free(buf);
  }
  const char *resp_str =
    "<html><head><meta charset='utf-8'><meta http-equiv=\"refresh\" content=\"1;url=cfgwebsockets\" "
    "/><style>" WEBPAGE_STYLE_CSS "</style></head><body><h2 class=\"name\">saving module data...</h2></body></html>";
  httpd_resp_send(req, resp_str, HTTPD_RESP_USE_STRLEN);

  return ESP_OK;
}

// ----------------------------------------------------------------------------

///////////////////////////////////////////////////////////////////////////////
// config_web_get_handler
//

static esp_err_t
config_web_get_handler(httpd_req_t *req)
{
  // esp_err_t rv;
  char *buf;
  // char *temp;

  char *req_buf;
  size_t req_buf_len;

  buf = (char *) calloc(CHUNK_BUFSIZE, 1);
  if (NULL == buf) {
    return ESP_ERR_NO_MEM;
  }

  // Get application info data
  const esp_app_desc_t *appDescr = esp_app_get_description();

  // Get header value string length and allocate memory for length + 1,
  // extra byte for null termination
  req_buf_len = httpd_req_get_hdr_value_len(req, "Host") + 1;
  if (req_buf_len > 1) {
    req_buf = (char *) malloc(req_buf_len);
    // Copy null terminated value string into buffer
    if (httpd_req_get_hdr_value_str(req, "Host", req_buf, req_buf_len) == ESP_OK) {
      ESP_LOGD(TAG, "Found header => Host: %s", req_buf);
    }
    free(req_buf);
  }

  sprintf(buf, WEBPAGE_START_TEMPLATE, g_persistent.nodeName, "Module web interface");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "<div><form id=but3 class=\"button\" action='/docfgweb' method='get'><fieldset>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "Port:<input type=\"text\" name=\"port\" value=\"%d\" >", g_persistent.webPort);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "Username:<input type=\"text\" name=\"user\" value=\"%s\" >", g_persistent.webUser);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "Password:<input type=\"password\" name=\"password\" value=\"%s\" >", g_persistent.webPassword);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "<button class=\"bgrn bgrn:hover\">Save</button></fieldset></form></div>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, WEBPAGE_CONFIG_END_TEMPLATE, appDescr->version, g_persistent.nodeName);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  httpd_resp_send_chunk(req, NULL, 0);

  free(buf);

  return ESP_OK;
}

///////////////////////////////////////////////////////////////////////////////
// do_config_web_get_handler
//

static esp_err_t
do_config_web_get_handler(httpd_req_t *req)
{
  esp_err_t rv;
  char *buf;
  size_t buf_len;

  // Read URL query string length and allocate memory for length + 1,
  // extra byte for null termination
  buf_len = httpd_req_get_url_query_len(req) + 1;
  if (buf_len > 1) {
    buf = (char *) malloc(buf_len);
    if (httpd_req_get_url_query_str(req, buf, buf_len) == ESP_OK) {

      ESP_LOGD(TAG, "Found URL query => %s", buf);
      char *param = malloc(WEBPAGE_PARAM_SIZE);
      if (NULL == param) {
        return ESP_ERR_NO_MEM;
        free(param);
      }

      // port
      if (ESP_OK == (rv = httpd_query_key_value(buf, "port", param, WEBPAGE_PARAM_SIZE))) {
        ESP_LOGD(TAG, "Found query parameter => port=%s", param);
        g_persistent.webPort = atoi(param);
        // Write changed value to persistent storage
        rv = nvs_set_u16(g_nvsHandle, "webPort", g_persistent.webPort);
        if (rv != ESP_OK) {
          ESP_LOGE(TAG, "Failed to update Web interface port");
        }
      }
      else {
        ESP_LOGE(TAG, "Error getting Web interface port => rv=%d", rv);
      }

      // user
      if (ESP_OK == (rv = httpd_query_key_value(buf, "user", param, WEBPAGE_PARAM_SIZE))) {
        char *pdecoded = urlDecode(param);
        if (NULL == pdecoded) {
          free(param);
          free(buf);
          return ESP_ERR_NO_MEM;
        }
        ESP_LOGD(TAG, "Found query parameter => user=%s", pdecoded);
        strncpy(g_persistent.webUser, pdecoded, sizeof(g_persistent.webUser) - 1);
        // Write changed value to persistent storage
        rv = nvs_set_str(g_nvsHandle, "webUser", g_persistent.webUser);
        if (rv != ESP_OK) {
          ESP_LOGE(TAG, "Failed to update Web interface user");
        }
      }
      else {
        ESP_LOGE(TAG, "Error getting Web interface user => rv=%d", rv);
      }

      // password
      if (ESP_OK == (rv = httpd_query_key_value(buf, "password", param, WEBPAGE_PARAM_SIZE))) {
        char *pdecoded = urlDecode(param);
        if (NULL == pdecoded) {
          free(param);
          free(buf);
          return ESP_ERR_NO_MEM;
        }
        ESP_LOGD(TAG, "Found query parameter => password=%s", pdecoded);
        strncpy(g_persistent.webPassword, pdecoded, sizeof(g_persistent.webPassword) - 1);
        // Write changed value to persistent storage
        rv = nvs_set_str(g_nvsHandle, "webPassword", g_persistent.webPassword);
        if (rv != ESP_OK) {
          ESP_LOGE(TAG, "Failed to update Web interface password");
        }
      }
      else {
        ESP_LOGE(TAG, "Error getting Web interface password => rv=%d", rv);
      }

      rv = nvs_commit(g_nvsHandle);
      if (rv != ESP_OK) {
        ESP_LOGE(TAG, "Failed to commit updates to nvs\n");
      }

      free(param);
    }

    free(buf);
  }
  const char *resp_str =
    "<html><head><meta charset='utf-8'><meta http-equiv=\"refresh\" content=\"1;url=cfgweb\" "
    "/><style>" WEBPAGE_STYLE_CSS "</style></head><body><h2 class=\"name\">saving module data...</h2></body></html>";
  httpd_resp_send(req, resp_str, HTTPD_RESP_USE_STRLEN);

  return ESP_OK;
}

// ----------------------------------------------------------------------------

///////////////////////////////////////////////////////////////////////////////
// config_log_get_handler
//

static esp_err_t
config_log_get_handler(httpd_req_t *req)
{
  // esp_err_t rv;
  char *buf;
  // char *temp;

  char *req_buf;
  size_t req_buf_len;

  buf = (char *) calloc(CHUNK_BUFSIZE, 1);
  if (NULL == buf) {
    return ESP_ERR_NO_MEM;
  }

  // Get application info data
  const esp_app_desc_t *appDescr = esp_app_get_description();

  // Get header value string length and allocate memory for length + 1,
  // extra byte for null termination
  req_buf_len = httpd_req_get_hdr_value_len(req, "Host") + 1;
  if (req_buf_len > 1) {
    req_buf = (char *) malloc(req_buf_len);
    // Copy null terminated value string into buffer
    if (httpd_req_get_hdr_value_str(req, "Host", req_buf, req_buf_len) == ESP_OK) {
      ESP_LOGD(TAG, "Found header => Host: %s", req_buf);
    }
    free(req_buf);
  }

  sprintf(buf, WEBPAGE_START_TEMPLATE, g_persistent.nodeName, "Logging Configuration");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "<div><form id=but3 class=\"button\" action='/docfglog' method='get'><fieldset>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "<input type=\"checkbox\" id=\"stdout\"name=\"stdout\" value=\"true\" ");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
  sprintf(buf, "%s><label for=\"stdout\"> Log to stdout</label>", g_persistent.logwrite2Stdout ? "checked" : "");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "<br /><br />Log to:<select  name=\"type\" ");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
  sprintf(buf, "<option value=\"0\" %s>none</option>", (LOG_TYPE_NONE == g_persistent.logType) ? "selected" : "");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
  sprintf(buf, "<option value=\"1\" %s>stdout</option>", (LOG_TYPE_STD == g_persistent.logType) ? "selected" : "");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
  sprintf(buf, "<option value=\"2\" %s>UDP</option>", (LOG_TYPE_UDP == g_persistent.logType) ? "selected" : "");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
  sprintf(buf, "<option value=\"3\" %s>TCP</option>", (LOG_TYPE_TCP == g_persistent.logType) ? "selected" : "");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
  sprintf(buf, "<option value=\"4\" %s>HTTP</option>", (LOG_TYPE_HTTP == g_persistent.logType) ? "selected" : "");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
  sprintf(buf, "<option value=\"5\" %s>MQTT</option>", (LOG_TYPE_MQTT == g_persistent.logType) ? "selected" : "");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
  sprintf(buf, "<option value=\"6\" %s>VSCP</option>", (LOG_TYPE_VSCP == g_persistent.logType) ? "selected" : "");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
  sprintf(buf, "></select>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "Log level:<select name=\"level\" ");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
  sprintf(buf, "<option value=\"1\" %s>error</option>", (ESP_LOG_ERROR == g_persistent.logLevel) ? "selected" : "");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
  sprintf(buf, "<option value=\"2\" %s>warning</option>", (ESP_LOG_WARN == g_persistent.logLevel) ? "selected" : "");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
  sprintf(buf, "<option value=\"3\" %s>info</option>", (ESP_LOG_INFO == g_persistent.logLevel) ? "selected" : "");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
  sprintf(buf, "<option value=\"4\" %s>  debug</option>", (ESP_LOG_DEBUG == g_persistent.logLevel) ? "selected" : "");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
  sprintf(buf, "<option value=\"5\" %s>verbose</option>", (ESP_LOG_VERBOSE == g_persistent.logLevel) ? "selected" : "");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
  sprintf(buf, "></select>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "Max retries:<input type=\"text\" name=\"retries\" value=\"%d\" >", g_persistent.logRetries);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "Destination (IP Addr):<input type=\"text\" name=\"url\" value=\"%s\" >", g_persistent.logUrl);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "Port:<input type=\"text\" name=\"port\" value=\"%d\" >", g_persistent.logPort);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "MQTT log Topic:<input type=\"text\" name=\"topic\" value=\"%s\" >", g_persistent.logMqttTopic);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "<button class=\"bgrn bgrn:hover\">Save</button></fieldset></form></div>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, WEBPAGE_CONFIG_END_TEMPLATE, appDescr->version, g_persistent.nodeName);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  httpd_resp_send_chunk(req, NULL, 0);

  free(buf);

  return ESP_OK;
}

///////////////////////////////////////////////////////////////////////////////
// do_config_log_get_handler
//

static esp_err_t
do_config_log_get_handler(httpd_req_t *req)
{
  esp_err_t rv;
  char *buf;
  size_t buf_len;

  // Read URL query string length and allocate memory for length + 1,
  // extra byte for null termination
  buf_len = httpd_req_get_url_query_len(req) + 1;
  if (buf_len > 1) {
    buf = (char *) malloc(buf_len);
    if (httpd_req_get_url_query_str(req, buf, buf_len) == ESP_OK) {

      ESP_LOGD(TAG, "Found URL query => %s", buf);
      char *param = (char *) malloc(WEBPAGE_PARAM_SIZE);
      if (NULL == param) {
        return ESP_ERR_NO_MEM;
        free(param);
      }

      // stdout
      if (ESP_OK == (rv = httpd_query_key_value(buf, "stdout", param, WEBPAGE_PARAM_SIZE))) {

        ESP_LOGD(TAG, "Found query parameter => stdout=%s", param);

        if (NULL != strstr(param, "true")) {
          g_persistent.logwrite2Stdout = 1;
        }
        else {
          g_persistent.logwrite2Stdout = 0;
        }
      }
      else {
        g_persistent.logwrite2Stdout = 0;
      }

      rv = nvs_set_u8(g_nvsHandle, "logwrite2Stdout", g_persistent.logwrite2Stdout);
      if (rv != ESP_OK) {
        ESP_LOGE(TAG, "Failed to update log-stdout");
      }

      // type
      if (ESP_OK == (rv = httpd_query_key_value(buf, "type", param, WEBPAGE_PARAM_SIZE))) {
        ESP_LOGD(TAG, "Found query parameter => type=%s", param);
        g_persistent.logType = atoi(param);

        rv = nvs_set_u8(g_nvsHandle, "log_type", g_persistent.logType);
        if (rv != ESP_OK) {
          ESP_LOGE(TAG, "Failed to update log type");
        }
      }
      else {
        ESP_LOGE(TAG, "Error getting log type => rv=%d", rv);
      }

      // level
      if (ESP_OK == (rv = httpd_query_key_value(buf, "level", param, WEBPAGE_PARAM_SIZE))) {
        ESP_LOGD(TAG, "Found query parameter => level=%s", param);
        g_persistent.logLevel = atoi(param);

        rv = nvs_set_u8(g_nvsHandle, "log_level", g_persistent.logLevel);
        if (rv != ESP_OK) {
          ESP_LOGE(TAG, "Failed to update log level");
        }
      }
      else {
        ESP_LOGE(TAG, "Error getting log level => rv=%d", rv);
      }

      // retries
      if (ESP_OK == (rv = httpd_query_key_value(buf, "retries", param, WEBPAGE_PARAM_SIZE))) {
        ESP_LOGD(TAG, "Found query parameter => retries=%s", param);
        g_persistent.logRetries = atoi(param);

        rv = nvs_set_u8(g_nvsHandle, "log_retries", g_persistent.logRetries);
        if (rv != ESP_OK) {
          ESP_LOGE(TAG, "Failed to update log retries");
        }
      }
      else {
        ESP_LOGE(TAG, "Error getting log retries => rv=%d", rv);
      }

      // port
      if (ESP_OK == (rv = httpd_query_key_value(buf, "port", param, WEBPAGE_PARAM_SIZE))) {
        ESP_LOGD(TAG, "Found query parameter => port=%s", param);
        g_persistent.logPort = atoi(param);

        rv = nvs_set_u8(g_nvsHandle, "log_port", g_persistent.logPort);
        if (rv != ESP_OK) {
          ESP_LOGE(TAG, "Failed to update log port [%s]", esp_err_to_name(rv));
        }
      }
      else {
        ESP_LOGE(TAG, "Error getting log port => rv=%d", rv);
      }

      // url
      if (ESP_OK == (rv = httpd_query_key_value(buf, "url", param, WEBPAGE_PARAM_SIZE))) {
        ESP_LOGD(TAG, "Found query parameter => url=%s", param);
        strncpy(g_persistent.logUrl, param, sizeof(g_persistent.logUrl));

        rv = nvs_set_str(g_nvsHandle, "log_url", g_persistent.logUrl);
        if (rv != ESP_OK) {
          ESP_LOGE(TAG, "Failed to save log URL");
        }
      }
      else {
        ESP_LOGE(TAG, "Error getting log port => rv=%d", rv);
      }

      // MQTT topic
      if (ESP_OK == (rv = httpd_query_key_value(buf, "topic", param, WEBPAGE_PARAM_SIZE))) {
        char *pdecoded = urlDecode(param);
        if (NULL == pdecoded) {
          free(param);
          free(buf);
          return ESP_ERR_NO_MEM;
        }
        ESP_LOGD(TAG, "Found query parameter => topic=%s", pdecoded);
        strncpy(g_persistent.logMqttTopic, pdecoded, sizeof(g_persistent.logMqttTopic));
        free(pdecoded);

        rv = nvs_set_str(g_nvsHandle, "logMqttTopic", g_persistent.logMqttTopic);
        if (rv != ESP_OK) {
          ESP_LOGE(TAG, "Failed to save logMqtt topic");
        }
      }
      else {
        ESP_LOGE(TAG, "Error getting log topic => rv=%d", rv);
      }

      free(param);
    }

    free(buf);
  }
  const char *resp_str =
    "<html><head><meta charset='utf-8'><meta http-equiv=\"refresh\" content=\"1;url=cfglog\" "
    "/><style>" WEBPAGE_STYLE_CSS "</style></head><body><h2 class=\"name\">saving module data...</h2></body></html>";
  httpd_resp_send(req, resp_str, HTTPD_RESP_USE_STRLEN);

  return ESP_OK;
}

//---------------------------------------------------------------------------

///////////////////////////////////////////////////////////////////////////////
// config_factory_defaults_get_handler
//

static esp_err_t
config_factory_defaults_get_handler(httpd_req_t *req)
{
  // esp_err_t rv;
  char *buf;
  // char *temp;

  char *req_buf;
  size_t req_buf_len;

  buf = (char *) calloc(CHUNK_BUFSIZE, 1);
  if (NULL == buf) {
    return ESP_ERR_NO_MEM;
  }

  // Get application info data
  const esp_app_desc_t *appDescr = esp_app_get_description();

  // Get header value string length and allocate memory for length + 1,
  // extra byte for null termination
  req_buf_len = httpd_req_get_hdr_value_len(req, "Name") + 1;
  if (req_buf_len > 1) {
    req_buf = (char *) malloc(req_buf_len);
    // Copy null terminated value string into buffer
    if (httpd_req_get_hdr_value_str(req, "Host", req_buf, req_buf_len) == ESP_OK) {
      ESP_LOGD(TAG, "Found header => Host: %s", req_buf);
    }
    free(req_buf);
  }

  sprintf(buf, WEBPAGE_START_TEMPLATE, g_persistent.nodeName, "Factory Defaults");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "<div><form id=but3 class=\"button\" action='/docfgfactorydefaults' method='get'><fieldset>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  // Enable
  sprintf(buf, "<input type=\"checkbox\" name=\"yesimsure\" value=\"true\" ");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
  sprintf(buf, "%s><label for=\"lr\"> Yes I am sure</label>", "");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, "<button class=\"bred bred:hover\">Restore factory defaults</button></fieldset></form></div>");
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  sprintf(buf, WEBPAGE_CONFIG_END_TEMPLATE, appDescr->version, g_persistent.nodeName);
  httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

  httpd_resp_send_chunk(req, NULL, 0);

  free(buf);

  return ESP_OK;
}

///////////////////////////////////////////////////////////////////////////////
// do_config_factory_defaults_get_handler
//

static esp_err_t
do_config_factory_defaults_get_handler(httpd_req_t *req)
{
  esp_err_t rv;
  char *buf;
  size_t buf_len;

  ESP_LOGE(TAG, "HANDLER => do_config_factory_defaults_get_handler");
  // Read URL query string length and allocate memory for length + 1,
  // extra byte for null termination
  buf_len = httpd_req_get_url_query_len(req) + 1;
  if (buf_len > 1) {
    buf = (char *) malloc(buf_len);
    if (httpd_req_get_url_query_str(req, buf, buf_len) == ESP_OK) {

      ESP_LOGW(TAG, "Found URL query => %s", buf);
      char *param = malloc(WEBPAGE_PARAM_SIZE);
      if (NULL == param) {
        free(param);
        free(buf);
        return ESP_ERR_NO_MEM;
      }

      // Yes-I'm-Sure
      if (ESP_OK == (rv = httpd_query_key_value(buf, "yesimsure", param, WEBPAGE_PARAM_SIZE))) {
        ESP_LOGW(TAG, "Found query parameter => yesimsure=%s", param);
        if (NULL != strstr(param, "true")) {
          ESP_LOGW(TAG, "Restoring factory defaults...");
          nvs_erase_all(g_nvsHandle);
          nvs_commit(g_nvsHandle);
          const char *resp_str =
            "<html><head><meta charset='utf-8'><meta http-equiv=\"refresh\" content=\"1;url=reset\" "
            "/><style>" WEBPAGE_STYLE_CSS
            "</style></head><body><h2 class=\"name\">Restoring factory defaults...</h2></body></html>";
          httpd_resp_send(req, resp_str, HTTPD_RESP_USE_STRLEN);
        }
      }

      free(param);
    }
    free(buf);
  }

  ESP_LOGW(TAG, "NOT restoring factory defaults...");
  const char *resp_str = "<html><head><meta charset='utf-8'><meta http-equiv=\"refresh\" content=\"1;url=config\" "
                         "/><style>" WEBPAGE_STYLE_CSS
                         "</style></head><body><h2 class=\"name\">No factory default. Returning...</h2></body></html>";
  httpd_resp_send(req, resp_str, HTTPD_RESP_USE_STRLEN);

  return ESP_OK;
}

///////////////////////////////////////////////////////////////////////////////
// echo_post_handler
//
// An HTTP POST handler
//

static esp_err_t
echo_post_handler(httpd_req_t *req)
{
  char buf[100];
  int ret, remaining = req->content_len;

  while (remaining > 0) {
    // Read the data for the request
    if ((ret = httpd_req_recv(req, buf, MIN(remaining, sizeof(buf)))) <= 0) {
      if (ret == HTTPD_SOCK_ERR_TIMEOUT) {
        // Retry receiving if timeout occurred
        continue;
      }
      return ESP_FAIL;
    }

    // Send back the same data
    httpd_resp_send_chunk(req, buf, ret);
    remaining -= ret;

    // Log data received
    ESP_LOGD(TAG, "=========== RECEIVED DATA ==========");
    ESP_LOGD(TAG, "%.*s", ret, buf);
    ESP_LOGD(TAG, "====================================");
  }

  // End response
  httpd_resp_send_chunk(req, NULL, 0);
  return ESP_OK;
}

static const httpd_uri_t echo = { .uri = "/echo", .method = HTTP_POST, .handler = echo_post_handler, .user_ctx = NULL };

///////////////////////////////////////////////////////////////////////////////
// http_404_error_handler
//
// This handler allows the custom error handling functionality to be
// tested from client side. For that, when a PUT request 0 is sent to
// URI /ctrl, the /hello and /echo URIs are unregistered and following
// custom error handler http_404_error_handler() is registered.
// Afterwards, when /hello or /echo is requested, this custom error
// handler is invoked which, after sending an error message to client,
// either closes the underlying socket (when requested URI is /echo)
// or keeps it open (when requested URI is /hello). This allows the
// client to infer if the custom error handler is functioning as expected
// by observing the socket state.
//

esp_err_t
http_404_error_handler(httpd_req_t *req, httpd_err_code_t err)
{
  if (strcmp("/hello", req->uri) == 0) {
    httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "/hello URI is not available");
    // Return ESP_OK to keep underlying socket open
    return ESP_OK;
  }
  else if (strcmp("/echo", req->uri) == 0) {
    httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "/echo URI is not available");
    // Return ESP_FAIL to close underlying socket
    return ESP_FAIL;
  }
  // For any other URI send 404 and close socket
  httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "Some 404 error message");
  return ESP_FAIL;
}

///////////////////////////////////////////////////////////////////////////////
// ctrl_put_handler
//
// An HTTP PUT handler. This demonstrates realtime
// registration and deregistration of URI handlers
//

static esp_err_t
ctrl_put_handler(httpd_req_t *req)
{
  char buf;
  int ret;

  if ((ret = httpd_req_recv(req, &buf, 1)) <= 0) {
    if (ret == HTTPD_SOCK_ERR_TIMEOUT) {
      httpd_resp_send_408(req);
    }
    return ESP_FAIL;
  }

  if (buf == '0') {
    // URI handlers can be unregistered using the uri string
    ESP_LOGD(TAG, "Unregistering /hello and /echo URIs");
    httpd_unregister_uri(req->handle, "/hello");
    httpd_unregister_uri(req->handle, "/echo");
    // Register the custom error handler
    httpd_register_err_handler(req->handle, HTTPD_404_NOT_FOUND, http_404_error_handler);
  }
  else {
    ESP_LOGD(TAG, "Registering /hello and /echo URIs");
    httpd_register_uri_handler(req->handle, &hello);
    httpd_register_uri_handler(req->handle, &echo);
    // Unregister custom error handler
    httpd_register_err_handler(req->handle, HTTPD_404_NOT_FOUND, NULL);
  }

  // Respond with empty body
  httpd_resp_send(req, NULL, 0);
  return ESP_OK;
}

// static const httpd_uri_t ctrl = { .uri = "/ctrl", .method = HTTP_PUT, .handler = ctrl_put_handler, .user_ctx =
// NULL
// };

///////////////////////////////////////////////////////////////////////////////
// set_content_type_from_file
//
// Set HTTP response content type according to file extension
//

static esp_err_t
set_content_type_from_file(httpd_req_t *req, const char *filename)
{
  if (IS_FILE_EXT(filename, ".gz")) {
    return httpd_resp_set_type(req, "application/gzip");
  }
  else if (IS_FILE_EXT(filename, ".html")) {
    return httpd_resp_set_type(req, "text/html");
  }
  else if (IS_FILE_EXT(filename, ".css")) {
    return httpd_resp_set_type(req, "text/css");
  }
  else if (IS_FILE_EXT(filename, ".jpeg")) {
    return httpd_resp_set_type(req, "image/jpeg");
  }
  else if (IS_FILE_EXT(filename, ".png")) {
    return httpd_resp_set_type(req, "image/png");
  }
  else if (IS_FILE_EXT(filename, ".ico")) {
    return httpd_resp_set_type(req, "image/x-icon");
  }
  else if (IS_FILE_EXT(filename, ".js")) {
    return httpd_resp_set_type(req, "text/javascript");
  }
  // For any other type always set as plain text
  return httpd_resp_set_type(req, "text/plain");
}

///////////////////////////////////////////////////////////////////////////////
// default_get_handler
//
// Handler to download a file kept on the server
//

static esp_err_t
default_get_handler(httpd_req_t *req)
{
  char filepath[FILE_PATH_MAX];
  FILE *fd = NULL;
  struct stat file_stat;
  char *buf      = NULL;
  size_t buf_len = 0;

  ESP_LOGD(TAG, "uri : [%s]", req->uri);

  //---------------------------------------------------------------------------

  ESP_LOGD(TAG, "default_get_handler");

  buf_len = httpd_req_get_hdr_value_len(req, "Authorization") + 1;
  if (buf_len > 1) {
    buf = calloc(buf_len, 1);
    if (!buf) {
      ESP_LOGE(TAG, "No enough memory for basic authorization");
      return ESP_ERR_NO_MEM;
    }

    if (httpd_req_get_hdr_value_str(req, "Authorization", buf, buf_len) == ESP_OK) {
      ESP_LOGD(TAG, "Found header => Authorization: %s", buf);
    }
    else {
      ESP_LOGE(TAG, "No auth value received");
    }

    char *auth_credentials = http_auth_basic(DEFAULT_VSCP_LINK_USER, DEFAULT_VSCP_LINK_PASSWORD);
    if (!auth_credentials) {
      ESP_LOGE(TAG, "No enough memory for basic authorization credentials");
      free(buf);
      return ESP_ERR_NO_MEM;
    }

    if (strncmp(auth_credentials, buf, buf_len)) {
      ESP_LOGE(TAG, "Not authenticated");
      httpd_resp_set_status(req, HTTPD_401);
      httpd_resp_set_type(req, "application/json");
      httpd_resp_set_hdr(req, "Connection", "keep-alive");
      httpd_resp_set_hdr(req, "WWW-Authenticate", "Basic realm=\"Alpha\"");
      httpd_resp_send(req, NULL, 0);
    }
    else {
      ESP_LOGD(TAG, "------> Authenticated!");
      /*char *basic_auth_resp = NULL;
      httpd_resp_set_status(req, HTTPD_200);
      httpd_resp_set_type(req, "application/json");
      httpd_resp_set_hdr(req, "Connection", "keep-alive");
      asprintf(&basic_auth_resp, "{\"authenticated\": true,\"user\": \"%s\"}", basic_auth_info->username);
      if (!basic_auth_resp) {
        ESP_LOGE(TAG, "No enough memory for basic authorization response");
        free(auth_credentials);
        free(buf)
        return ESP_ERR_NO_MEM;
      }
      httpd_resp_send(req, basic_auth_resp, strlen(basic_auth_resp));
      free(basic_auth_resp); */
    }
    free(auth_credentials);
    free(buf);
  }
  else {
    ESP_LOGE(TAG, "No auth header received.");
    httpd_resp_set_status(req, HTTPD_401);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "keep-alive");
    httpd_resp_set_hdr(req, "WWW-Authenticate", "Basic realm=\"Alpha\"");
    httpd_resp_send(req, NULL, 0);
    return ESP_OK;
  }

  // -----------------------------------------------------------------------------

  if (0 == strncmp(req->uri, "/hello", 6)) {
    ESP_LOGV(TAG, "--------- HELLO ---------\n");
    return hello_get_handler(req);
  }

  if (0 == strncmp(req->uri, "/echo", 5)) {
    ESP_LOGV(TAG, "--------- ECHO ---------\n");
    return echo_post_handler(req);
  }

  if (0 == strncmp(req->uri, "/ctrl", 5)) {
    ESP_LOGV(TAG, "--------- CTRL ---------\n");
    return ctrl_put_handler(req);
  }

  if (0 == strncmp(req->uri, "/index.html", 11)) {
    ESP_LOGV(TAG, "--------- index ---------\n");
    return mainpg_get_handler(req);
  }

  if ((0 == strncmp(req->uri, "/", 1)) && (1 == strlen(req->uri))) {
    ESP_LOGV(TAG, "--------- index /---------\n");
    return mainpg_get_handler(req);
  }

  // ---------------------------------------------------------------

  if (0 == strncmp(req->uri, "/config", 7)) {
    ESP_LOGV(TAG, "--------- config ---------\n");
    return config_get_handler(req);
  }

  if (0 == strncmp(req->uri, "/cfgmodule", 10)) {
    ESP_LOGV(TAG, "--------- cfgmodule ---------\n");
    return config_module_get_handler(req);
  }

  if (0 == strncmp(req->uri, "/docfgmodule", 12)) {
    ESP_LOGV(TAG, "--------- docfgmodule ---------\n");
    return do_config_module_get_handler(req);
  }

  if (0 == strncmp(req->uri, "/cfgcan", 7)) {
    ESP_LOGV(TAG, "--------- cfgcan ---------\n");
    return config_can_get_handler(req);
  }

  if (0 == strncmp(req->uri, "/docfgcan", 9)) {
    ESP_LOGV(TAG, "--------- docfgcan ---------\n");
    return do_config_can_get_handler(req);
  }

  if (0 == strncmp(req->uri, "/cfgwifi", 8)) {
    ESP_LOGV(TAG, "--------- cfgwifi ---------\n");
    return config_wifi_get_handler(req);
  }

  if (0 == strncmp(req->uri, "/docfgwifi", 10)) {
    ESP_LOGV(TAG, "--------- docfgwifi ---------\n");
    return do_config_wifi_get_handler(req);
  }

  if (0 == strncmp(req->uri, "/cfgfactorydefaults", 8)) {
    ESP_LOGV(TAG, "--------- docfgfactorydefaults ---------\n");
    return config_factory_defaults_get_handler(req);
  }

  if (0 == strncmp(req->uri, "/docfgfactorydefaults", 10)) {
    ESP_LOGV(TAG, "--------- docfgfactorydefaults ---------\n");
    return do_config_factory_defaults_get_handler(req);
  }

  if (0 == strncmp(req->uri, "/cfgvscplink", 11)) {
    ESP_LOGV(TAG, "--------- cfgvscplink ---------\n");
    return config_vscplink_get_handler(req);
  }

  if (0 == strncmp(req->uri, "/docfgvscplink", 13)) {
    ESP_LOGV(TAG, "--------- docfgvscplink ---------\n");
    return do_config_vscplink_get_handler(req);
  }

  if (0 == strncmp(req->uri, "/cfgmqtt", 8)) {
    ESP_LOGV(TAG, "--------- cfgmqtt ---------\n");
    return config_mqtt_get_handler(req);
  }

  if (0 == strncmp(req->uri, "/docfgmqtt", 10)) {
    ESP_LOGV(TAG, "--------- docfgmqtt ---------\n");
    return do_config_mqtt_get_handler(req);
  }

  if (0 == strncmp(req->uri, "/cfgwebsockets", 14)) {
    ESP_LOGV(TAG, "--------- cfgwebsockets ---------\n");
    return config_websockets_get_handler(req);
  }

  if (0 == strncmp(req->uri, "/docfgwebsockets", 16)) {
    ESP_LOGV(TAG, "--------- docfgwebsockets ---------\n");
    return do_config_websockets_get_handler(req);
  }

  if (0 == strncmp(req->uri, "/cfgweb", 7)) {
    ESP_LOGV(TAG, "--------- cfgweb ---------\n");
    return config_web_get_handler(req);
  }

  if (0 == strncmp(req->uri, "/docfgweb", 9)) {
    ESP_LOGV(TAG, "--------- docfgweb ---------\n");
    return do_config_web_get_handler(req);
  }

  if (0 == strncmp(req->uri, "/cfglog", 7)) {
    ESP_LOGV(TAG, "--------- cfglog ---------\n");
    return config_log_get_handler(req);
  }

  if (0 == strncmp(req->uri, "/docfglog", 9)) {
    ESP_LOGV(TAG, "--------- docfglog ---------\n");
    return do_config_log_get_handler(req);
  }

  if (0 == strncmp(req->uri, "/cfgmulticast", 13)) {
    ESP_LOGV(TAG, "--------- cfgmulticast ---------\n");
    return config_multicast_get_handler(req);
  }

  if (0 == strncmp(req->uri, "/docfgmulticast", 15)) {
    ESP_LOGV(TAG, "--------- docfgmulticast ---------\n");
    return do_config_multicast_get_handler(req);
  }

  if (0 == strncmp(req->uri, "/cfgudp", 7)) {
    ESP_LOGV(TAG, "--------- cfgudp ---------\n");
    return config_udp_get_handler(req);
  }

  if (0 == strncmp(req->uri, "/docfgudp", 9)) {
    ESP_LOGV(TAG, "--------- docfgudp ---------\n");
    return do_config_udp_get_handler(req);
  }

  // ---------------------------------------------------------------

  if (0 == strncmp(req->uri, "/info", 5)) {
    ESP_LOGV(TAG, "--------- info ---------\n");
    return info_get_handler(req);
  }

  if (0 == strncmp(req->uri, "/reset", 6)) {
    ESP_LOGV(TAG, "--------- reset ---------\n");
    return reset_get_handler(req);
  }

  if (0 == strncmp(req->uri, "/upgrade", 8)) {
    ESP_LOGV(TAG, "--------- Upgrade main ---------\n");
    return upgrade_get_handler(req);
  }

  if (0 == strncmp(req->uri, "/upgrdsrv", 9)) {
    ESP_LOGV(TAG, "--------- Upgrade server ---------\n");
    return upgrdsrv_get_handler(req);
  }

  if (0 == strncmp(req->uri, "/upgrdlocal", 11)) {
    ESP_LOGV(TAG, "--------- Upgrade local ---------\n");
    return upgrdlocal_post_handler(req);
  }

  if (0 == strncmp(req->uri, "/upgrdSibling", 13)) {
    ESP_LOGV(TAG, "--------- Upgrade sibling(s) from server ---------\n");
    return upgrdsibling_get_handler(req);
  }

  if (0 == strncmp(req->uri, "/upgrdSiblingLocal", 18)) {
    ESP_LOGV(TAG, "--------- Upgrade sibling(s) local ---------\n");
    return upgrdSiblingslocal_post_handler(req);
  }

  return ESP_OK;

  // ------------------------------------------------------------------------------------------

  // If name has trailing '/', respond with directory contents
  if (0 == strcmp(req->uri, "/")) {
    ESP_LOGD(TAG, "Set default uri");
    strcpy((char *) req->uri, "/index.html");
  }

  const char *filename = get_path_from_uri(filepath, "/spiffs", req->uri, sizeof(filepath));
  if (!filename) {
    ESP_LOGE(TAG, "Filename is too long");
    // Respond with 500 Internal Server Error
    httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Filename too long");
    return ESP_FAIL;
  }

  if (stat(filepath, &file_stat) == -1) {
    // If file not present on SPIFFS check if URI
    // corresponds to one of the hardcoded paths
    if (strcmp(filename, "/index.html") == 0) {
      // return index_html_get_handler(req);
    }
    else if (strcmp(filename, "/favicon.ico") == 0) {
      // return favicon_get_handler(req);
    }
    ESP_LOGE(TAG, "Failed to stat file : %s", filepath);
    // Respond with 404 Not Found
    httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "File does not exist");
    return ESP_FAIL;
  }

  fd = fopen(filepath, "r");
  if (!fd) {
    ESP_LOGE(TAG, "Failed to read existing file : %s", filepath);
    // Respond with 500 Internal Server Error
    httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to read existing file");
    return ESP_FAIL;
  }

  ESP_LOGD(TAG, "Sending file : %s (%ld bytes)...", filename, file_stat.st_size);
  set_content_type_from_file(req, filename);

  // Retrieve the pointer to chunk buffer for temporary storage
  char *chunk = (char *) req->user_ctx;
  size_t chunksize;
  do {
    // Read file in chunks into the chund buffer
    memset(chunk, 0, sizeof(req->user_ctx));
    chunksize = fread(chunk, 1, CHUNK_BUFSIZE, fd);

    if (chunksize > 0) {
      // Send the buffer contents as HTTP response chunk
      if (httpd_resp_send_chunk(req, chunk, chunksize) != ESP_OK) {
        fclose(fd);
        ESP_LOGE(TAG, "File sending failed!");
        // Abort sending file
        httpd_resp_sendstr_chunk(req, NULL);
        // Respond with 500 Internal Server Error
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to send file");
        return ESP_FAIL;
      }
    }

    // Keep looping till the whole file is sent
  } while (chunksize != 0);

  // Close file after sending complete
  fclose(fd);
  ESP_LOGD(TAG, "File sending complete");

  /* Respond with an empty chunk to signal HTTP response completion */
#ifdef CONFIG_EXAMPLE_HTTPD_CONN_CLOSE_HEADER
  httpd_resp_set_hdr(req, "Connection", "close");
#endif
  httpd_resp_send_chunk(req, NULL, 0);
  return ESP_OK;
}

///////////////////////////////////////////////////////////////////////////////
// start_webserver
//

httpd_handle_t
start_webserver(void)
{
  httpd_handle_t srv        = NULL;
  httpd_config_t dfltconfig = HTTPD_DEFAULT_CONFIG();
  dfltconfig.server_port    = g_persistent.webPort;

  // 4096 is to low for OTA
  dfltconfig.stack_size = 1024 * 5;

  dfltconfig.lru_purge_enable = true;
  // Use the URI wildcard matching function in order to
  // allow the same handler to respond to multiple different
  // target URIs which match the wildcard scheme
  dfltconfig.uri_match_fn = httpd_uri_match_wildcard;

  dfltconfig.max_uri_handlers = 20;

  // Start the httpd server
  ESP_LOGD(TAG, "Starting server on port: '%d'", dfltconfig.server_port);
  if (httpd_start(&srv, &dfltconfig) == ESP_OK) {

    // Set URI handlers
    ESP_LOGD(TAG, "Registering URI handlers");

    // URI handler for getting uploaded files
    // httpd_uri_t file_spiffs = { .uri      = "/*", // Match all URIs of type /path/to/file
    //                             .method   = HTTP_GET,
    //                             .handler  = spiffs_get_handler,
    //                             .user_ctx = NULL };

    httpd_uri_t dflt = { .uri      = "/*", // Match all URIs of type /path/to/file
                         .method   = HTTP_GET,
                         .handler  = default_get_handler,
                         .user_ctx = NULL };

    // httpd_register_uri_handler(srv, &hello);
    // httpd_register_uri_handler(srv, &echo);
    // httpd_register_uri_handler(srv, &ctrl);
    // httpd_register_uri_handler(srv, &mainpg);
    httpd_register_uri_handler(srv, &dflt);

    httpd_register_uri_handler(srv, &upgrdlocal);
    httpd_register_uri_handler(srv, &upgrdsiblinglocal);

    // httpd_register_uri_handler(srv, &config);
    //  httpd_register_uri_handler(srv, &cfgModule);

    // httpd_register_uri_handler(srv, &info);
    // httpd_register_uri_handler(srv, &reset);

    // httpd_register_uri_handler(srv, &upgrade);
    // httpd_register_uri_handler(srv, &upgrade_local);

    // httpd_register_basic_auth(srv);
    // httpd_register_uri_handler(srv, &file_spiffs);

    return srv;
  }

  ESP_LOGD(TAG, "Error starting server!");
  return NULL;
}

///////////////////////////////////////////////////////////////////////////////
// stop_webserver
//

esp_err_t
stop_webserver(httpd_handle_t server)
{
  // Stop the httpd server
  return httpd_stop(server);
}

///////////////////////////////////////////////////////////////////////////////
// disconnect_handler
//

static void
disconnect_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data)
{
  httpd_handle_t *server = (httpd_handle_t *) arg;
  if (*server) {
    ESP_LOGD(TAG, "Stopping webserver");
    if (stop_webserver(*server) == ESP_OK) {
      *server = NULL;
    }
    else {
      ESP_LOGE(TAG, "Failed to stop http server");
    }
  }
}

///////////////////////////////////////////////////////////////////////////////
// connect_handler
//

static void
connect_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data)
{
  httpd_handle_t *server = (httpd_handle_t *) arg;
  if (*server == NULL) {
    ESP_LOGD(TAG, "Starting webserver");
    *server = start_webserver();
  }
}
