/*
  VSCP Multicast support

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

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"

#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "nvs_flash.h"

#include "lwip/sockets.h"
#include "lwip/err.h"
#include "lwip/sys.h"

// Enable functionality from  firmware helper
#define VSCP_FWHLP_CRYPTO_SUPPORT    // For encryption support
#define VSCP_FWHLP_UDP_FRAME_SUPPORT // For UDP frame support

#include "main.h"

#include <vscp.h>
#include <vscp-firmware-helper.h>

#include "vscp-multicast.h"

static const char *TAG = "vscp multicast";

// External from main
// extern nvs_handle_t g_nvsHandle;
extern node_persistent_config_t g_persistent;
extern vprintf_like_t g_stdLogFunc;



#define VSCP_MULTICAST_BUFFER_SIZE 1024

///////////////////////////////////////////////////////////////////////////////
// multicast_sendEvent
//
// socket - Socket to send event on
// pstrev - VSCP event on string form to send
// bEncrypt - true if the event should be encrypted with the set key
// nAlgorithm - Encryption algorithm to use (vscp.h)
//

int32_t
multicast_sendEvent(int sock, const char *pstrev, bool bEncrypt, uint8_t nAlgorithm)
{
  int32_t rv;
  uint16_t len                            = 0;
  uint8_t buf[VSCP_MULTICAST_BUFFER_SIZE] = { 0 };
  struct sockaddr_in multicast_addr;
  unsigned char multicast_ttl = 10;

  if ((sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
    ESP_LOGE(TAG, "socket() failed");
    exit(1);
  }

  if ((setsockopt(sock,
                  IPPROTO_IP,
                  IP_MULTICAST_TTL,
                  (void *) &g_persistent.multicastTtl,
                  sizeof(g_persistent.multicastTtl))) < 0) {
    ESP_LOGE(TAG, "setsockopt() failed");
    exit(1);
  }

  memset(&multicast_addr, 0, sizeof(multicast_addr));
  multicast_addr.sin_family      = AF_INET;
  multicast_addr.sin_addr.s_addr = inet_addr(g_persistent.multicastUrl);
  multicast_addr.sin_port        = htons(g_persistent.multicastPort);

  vscpEventEx ex;
  if (VSCP_ERROR_SUCCESS != (rv = vscp_fwhlp_parseStringToEventEx(&ex, pstrev))) {
    fprintf(stderr, "Error parsing event string\n");
    return VSCP_ERROR_SUCCESS;
  }

#ifdef _MULTICAST_DEBUG_
  printf("Parsed event:\n");
  printf("=============\n");
  printf("Class: %d\n", ex.vscp_class);
  printf("Type: %d\n", ex.vscp_type);
  printf("Priority: %d\n", ex.head & 0xE0);
  printf("GUID: ");
  for (int i = 0; i < 16; i++) {
    printf("%02x:", ex.GUID[i]);
  }
  printf("\n");
  printf("Data: ");
  for (int i = 0; i < ex.sizeData; i++) {
    printf("%02x:", ex.data[i]);
  }
  printf("\n");
  printf("----------------------------------------------------\n");
  printf("Timestamp: 0x%08lX\n", (long unsigned int) ex.timestamp);
  printf("Obid: 0x%08lX\n", (long unsigned int) ex.obid);
  printf("Head: %d\n", ex.head);
  printf("Year: %d\n", ex.year);
  printf("Month: %d\n", ex.month);
  printf("Day: %d\n", ex.day);
  printf("Hour: %d\n", ex.hour);
  printf("Minute: %d\n", ex.minute);
  printf("Second: %d\n", ex.second);
  printf("----------------------------------------------------\n");
#endif

  // Calculate needed buffer size
  len = vscp_fwhlp_getFrameSizeFromEventEx(&ex);
  if (VSCP_ERROR_SUCCESS != (rv = vscp_fwhlp_writeEventExToFrame(buf, sizeof(buf), 0, &ex))) {
    fprintf(stderr, "Error writing event to frame. rv=%u\n", (unsigned) rv);
    return VSCP_ERROR_SUCCESS;
  }

#ifdef _MULTICAST_DEBUG_
  printf("Frame size: %d\n", len);
  printf("Frame:\n");
  for (int i = 0; i < len; i++) {
    printf("%02x ", buf[i]);
  }
  printf("\n");
#endif

  // Encrypt frame as needed
  if (bEncrypt) {

    uint8_t newlen       = 0;
    uint8_t encbuf[1024] = { 0 };

    if (0 == (newlen = vscp_fwhlp_encryptFrame(encbuf, buf, len, g_persistent.pmk, NULL, nAlgorithm))) {
      fprintf(stderr, "Error encrypting frame. newlen = %d\n", newlen);
      return VSCP_ERROR_SUCCESS;
    }

    memcpy(buf, encbuf, newlen);
    buf[0] = (buf[0] & 0xF0) | (VSCP_HLO_ENCRYPTION_AES128 & 0x0F); // Set encryption type
    // Set the new length (may be padded to be modulo 16 + 1)
    len = newlen;

    if (1) {
      printf("Encrypted frame:\n");
      for (int i = 0; i < len; i++) {
        printf("%02x ", buf[i]);
      }
      printf("\nNew length: %d\n", len);
    }
  } // encrypted frame

  ssize_t nsent;
  if ((sendto(sock, buf, len, 0, (struct sockaddr *) &multicast_addr, sizeof(multicast_addr))) != len) {
    fprintf(stderr, "send event: Failed %d\n", errno);
    return VSCP_ERROR_ERROR;
  }
  // if ((nsent = sendto(sock, buf, len, s_multicast_ip, s_multicast_port)) < len) {
  //   fprintf(stderr, "send event: Failed %d\n", errno);
  //   return VSCP_ERROR_ERROR;
  // }

  return VSCP_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// handle_vscp_event
//

void
multicast_handle_vscp_event(uint8_t *buf, uint16_t len)
{
  int rv;
  bool bVerbose = false;

  if (bVerbose) {
    printf("Buf: ");
    for (int i = 0; i < len; i++) {
      printf("%02x:", buf[i]);
    }
    printf("\n");
  }

  // If encrypted frame decrypt it
  if (buf[0] & 0x0F) {

    if (bVerbose) {
      printf("Encrypted frame detected. Type: %d\n", buf[0] & 0x0F);
    }

    uint8_t encbuf[VSCP_MULTICAST_BUFFER_SIZE] = { 0 };
    if (VSCP_ERROR_SUCCESS != vscp_fwhlp_decryptFrame(encbuf,
                                                      buf,
                                                      len - 16,
                                                      g_persistent.pmk,
                                                      buf + len - 16,
                                                      VSCP_ENCRYPTION_FROM_TYPE_BYTE)) {
      fprintf(stderr, "Error decrypting frame.\n");
      return;
    }
    if (bVerbose) {
      printf("Decrypted frame:\n");
      printf("Length: %d\n", len);
      for (int i = 0; i < len; i++) {
        printf("%02x ", encbuf[i]);
      }
      printf("\n");
    }

    // Copy decrypted frame back to buffer
    memcpy(buf, encbuf, len);

  } // encrypted

  vscpEventEx ex;
  memset(&ex, 0, sizeof(ex));
  if (VSCP_ERROR_SUCCESS != (rv = vscp_fwhlp_getEventExFromFrame(&ex, buf, len))) {
    fprintf(stderr, "Error reading event from frame. rv=%d\n", rv);
    return;
  }

  if (bVerbose) {
    printf("Event:\n");
    printf("Head: %d\n", ex.head);
    printf("Class: %d\n", ex.vscp_class);
    printf("Type: %d\n", ex.vscp_type);
    printf("Size: %d\n", ex.sizeData);
    for (int i = 0; i < ex.sizeData; i++) {
      printf("%02x ", ex.data[i]);
    }
    printf("\n");
    printf("----------------------------------------------------\n");
    printf("Timestamp: 0x%08lX\n", (long unsigned int) ex.timestamp);
    printf("Obid: 0x%08lX\n", (long unsigned int) ex.obid);
    printf("Year: %d\n", ex.year);
    printf("Month: %d\n", ex.month);
    printf("Day: %d\n", ex.day);
    printf("Hour: %d\n", ex.hour);
    printf("Minute: %d\n", ex.minute);
    printf("Second: %d\n", ex.second);
    printf("----------------------------------------------------\n");
  }
}

///////////////////////////////////////////////////////////////////////////////
// multicast_receive
//

void
multicast_receive(void)
{
  int sock;
  int flag_on = 1;
  struct sockaddr_in multicast_addr;
  char buf[VSCP_MULTICAST_BUFFER_SIZE];
  uint16_t len;
  struct ip_mreq mc_req;
  struct sockaddr_in from_addr;
  unsigned long from_len;

  static char *multicast_ip = "224.0.23.158";
  short multicast_port      = 9598;

  if ((sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
    ESP_LOGE(TAG, "socket() failed");
    exit(1);
  }

  if ((setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &flag_on, sizeof(flag_on))) < 0) {
    ESP_LOGE(TAG, "setsockopt() failed");
    exit(1);
  }

  memset(&multicast_addr, 0, sizeof(multicast_addr));
  multicast_addr.sin_family      = AF_INET;
  multicast_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  multicast_addr.sin_port        = htons(multicast_port);

  if ((bind(sock, (struct sockaddr *) &multicast_addr, sizeof(multicast_addr))) < 0) {
    ESP_LOGE(TAG, "bind() failed");
    exit(1);
  }

  mc_req.imr_multiaddr.s_addr = inet_addr(multicast_ip);
  mc_req.imr_interface.s_addr = htonl(INADDR_ANY);

  if ((setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (void *) &mc_req, sizeof(mc_req))) < 0) {
    ESP_LOGE(TAG, "setsockopt() failed");
    exit(1);
  }

  while (1) {
    memset(buf, 0, sizeof(buf));
    from_len = sizeof(from_addr);
    memset(&from_addr, 0, from_len);

    ESP_LOGI(TAG, "Wait for message");

    if ((len = recvfrom(sock, buf, VSCP_MULTICAST_BUFFER_SIZE, 0, (struct sockaddr *) &from_addr, &from_len)) < 0) {
      ESP_LOGE(TAG, "recvfrom() failed");
      break;
    }

    ESP_LOGI(TAG, "Message received");
    ESP_LOGI(TAG, "Received %d bytes from %s: ", len, inet_ntoa(from_addr.sin_addr));
    // ESP_LOGI(TAG, "%s", buf);
    ESP_LOG_BUFFER_HEX_LEVEL(TAG, buf, len, ESP_LOG_INFO);
  } // while

  /* send a DROP MEMBERSHIP message via setsockopt */
  if ((setsockopt(sock, IPPROTO_IP, IP_DROP_MEMBERSHIP, (void *) &mc_req, sizeof(mc_req))) < 0) {
    ESP_LOGE(TAG, "setsockopt() failed");
    exit(1);
  }
  close(sock);
}

///////////////////////////////////////////////////////////////////////////////
// multicast_send_dummy
//

void
multicast_send_dummy(void)
{
  int sock;
  char *message_to_send = "Hello";
  unsigned int send_len;
  unsigned char multicast_ttl = 10;
  struct sockaddr_in multicast_addr;

  if ((sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
    ESP_LOGE(TAG, "socket() failed");
    exit(1);
  }

  if ((setsockopt(sock, IPPROTO_IP, IP_MULTICAST_TTL, (void *) &multicast_ttl, sizeof(multicast_ttl))) < 0) {
    ESP_LOGE(TAG, "setsockopt() failed");
    exit(1);
  }

  memset(&multicast_addr, 0, sizeof(multicast_addr));
  multicast_addr.sin_family      = AF_INET;
  multicast_addr.sin_addr.s_addr = inet_addr(g_persistent.multicastUrl);
  multicast_addr.sin_port        = htons(g_persistent.multicastPort);

  send_len = strlen(message_to_send);
  if ((sendto(sock, message_to_send, send_len, 0, (struct sockaddr *) &multicast_addr, sizeof(multicast_addr))) !=
      send_len) {
    ESP_LOGE(TAG, "Error in number of bytes");
    exit(1);
  }
  ESP_LOGI(TAG, "Send done");
  close(sock);
}