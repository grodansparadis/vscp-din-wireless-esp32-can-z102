/*
  File: tcpsrv.c

  VSCP Wireless CAN4VSCP Gateway (VSCP-WCANG)

  This file is part of the VSCP (https://www.vscp.org)

  The MIT License (MIT)
  Copyright © 2022 Ake Hedman, the VSCP project <info@vscp.org>

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

  Config
  ------
  Enable (yes)
  ip-address for server
  port (9598)
  Valid client ip's (all)
  Username (admin)
  Password (secret)
*/

#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "nvs_flash.h"
#include <string.h>
#include <sys/param.h>

#include "lwip/err.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"
#include <lwip/netdb.h>

#include <vscp.h>

#include "tcpsrv.h"

#define KEEPALIVE_IDLE                                                                                                 \
  5 // Keep-alive idle time. In idle time without receiving any data from peer, will send keep-alive probe packet
#define KEEPALIVE_INTERVAL 5 // Keep-alive probe packet interval time.
#define KEEPALIVE_COUNT    3 // Keep-alive probe packet retry count.

static const char *TAG = "tcpsrv";

#define MSG_MAX_CLIENTS "Max number of clients reached. Disconnecting-\r\n"

static uint8_t cntClients = 0;  // Holds current number of clients

/**
  Received event are written to this fifo 
  from all channels and events is consumed by the 
  VSCP protocol handler.
*/
vscp_fifo_t fifoEventsIn;

struct _ctx ctx[MAX_TCP_CONNECTIONS]; // Socket context

///////////////////////////////////////////////////////////////////////////////
// setContextDefaults
// 

static void
setContextDefaults(struct _ctx* pctx)
{
  pctx->bValidated        = 0;
  pctx->privLevel         = 0;
  pctx->bRcvLoop          = 0;
  pctx->size              = 0;
  //pctx->last_rcvloop_time = time_us_32(); TODO
  vscp_fifo_clear(&pctx->fifoEventsOut);
  memset(pctx->buf, 0, ETHERNET_BUF_MAX_SIZE);
  memset(pctx->user, 0, VSCP_LINK_MAX_USER_NAME_LENGTH);  
  // Filter: All events received
  memset(&pctx->filter, 0, sizeof(vscpEventFilter));
  memset(&pctx->statistics, 0, sizeof(VSCPStatistics));
  memset(&pctx->status, 0, sizeof(VSCPStatus));
}

///////////////////////////////////////////////////////////////////////////////
// do_retransmit
//

static void
do_retransmit(const int sock)
{
  int len;
  char rx_buffer[128];

  do {
    len = recv(sock, rx_buffer, sizeof(rx_buffer) - 1, 0);
    if (len < 0) {
      ESP_LOGE(TAG, "Error occurred during receiving: errno %d", errno);
    }
    else if (len == 0) {
      ESP_LOGW(TAG, "Connection closed");
    }
    else {
      rx_buffer[len] = 0; // Null-terminate whatever is received and treat it like a string
      ESP_LOGI(TAG, "Received %d bytes: %s", len, rx_buffer);

      // send() can return less bytes than supplied length.
      // Walk-around for robust implementation.
      int to_write = len;
      while (to_write > 0) {
        int written = send(sock, rx_buffer + (len - to_write), to_write, 0);
        if (written < 0) {
          ESP_LOGE(TAG, "Error occurred during sending: errno %d", errno);
        }
        to_write -= written;
      }
    }
  } while (len > 0);
}

///////////////////////////////////////////////////////////////////////////////
// client_task
//

static void
client_task(void *pvParameters)
{
  int rv;
  size_t len;
  char rxbuf[128];

  //int sock = (int)*((int *)pvParameters);
  ctx_t *pctx = (ctx_t*)pvParameters;
  cntClients++;

  ESP_LOGI(TAG, "Client worker");

  do {
    len = (rv = recv(pctx->sock, rxbuf, sizeof(rxbuf) - 1, 0));
    if (rv < 0) {
      ESP_LOGE(TAG, "Error occurred during receiving: errno %d", errno);
    }
    else if (len == 0) {
      ESP_LOGW(TAG, "Connection closed");
    }
    else {
      // Check that the buffer can hold the new data
      if (pctx->size + len > sizeof(pctx->buf)) {
        len = sizeof(pctx->buf) - pctx->size;
      }
      strncat(pctx->buf, rxbuf, len);

      rxbuf[len] = 0; // Null-terminate whatever is received and treat it like a string
      ESP_LOGI(TAG, "Received %d bytes: %s", len, rxbuf);

      // Parse VSCP command
      vscp_link_parser(pctx, rxbuf, &len);

      // Get event from input fifo
      vscpEvent *pev = NULL;
      vscp_fifo_read(&fifoEventsIn, &pev);

      // pev is NULL if no event is available here
      // The worker is still called.
      // if pev != NULL the worker is responsible for 
      // freeing the event

      // Do protocol work here
      vscp2_do_work(pev);

      // Handle rcvloop etc
      vscp_link_idle_worker(pctx);
    }
  } while (len > 0);

  shutdown(pctx->sock, 0);
  close(pctx->sock);  

  cntClients--;
  vTaskDelete(NULL);
}

///////////////////////////////////////////////////////////////////////////////
// tcpsrv_task
//

void
tcpsrv_task(void *pvParameters)
{
  char addr_str[128];
  int addr_family  = (int) pvParameters;
  int ip_protocol  = 0;
  int keepAlive    = 1;
  int keepIdle     = KEEPALIVE_IDLE;
  int keepInterval = KEEPALIVE_INTERVAL;
  int keepCount    = KEEPALIVE_COUNT;
  struct sockaddr_storage dest_addr;

  for (int i = 0; i < MAX_TCP_CONNECTIONS; i++) {
    ctx[i].sock          = 0;
    vscp_fifo_init(&ctx[i].fifoEventsOut, TRANSMIT_FIFO_SIZE);
    setContextDefaults(&ctx[i]);
  }

  // Initialize the input fifo
  vscp_fifo_init(&fifoEventsIn, RECEIVE_FIFO_SIZE);  

  if (addr_family == AF_INET) {
    struct sockaddr_in *dest_addr_ip4 = (struct sockaddr_in *) &dest_addr;
    dest_addr_ip4->sin_addr.s_addr    = htonl(INADDR_ANY);
    dest_addr_ip4->sin_family         = AF_INET;
    dest_addr_ip4->sin_port           = htons(VSCP_DEFAULT_TCP_PORT);
    ip_protocol                       = IPPROTO_IP;
  }
  else if (addr_family == AF_INET6) {
    struct sockaddr_in6 *dest_addr_ip6 = (struct sockaddr_in6 *) &dest_addr;
    bzero(&dest_addr_ip6->sin6_addr.un, sizeof(dest_addr_ip6->sin6_addr.un));
    dest_addr_ip6->sin6_family = AF_INET6;
    dest_addr_ip6->sin6_port   = htons(VSCP_DEFAULT_TCP_PORT);
    ip_protocol                = IPPROTO_IPV6;
  }

  int listen_sock = socket(addr_family, SOCK_STREAM, ip_protocol);
  if (listen_sock < 0) {
    ESP_LOGE(TAG, "Unable to create socket: errno %d", errno);
    vTaskDelete(NULL);
    return;
  }
  int opt = 1;
  setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#if defined(CONFIG_EXAMPLE_IPV4) && defined(CONFIG_EXAMPLE_IPV6)
  // Note that by default IPV6 binds to both protocols, it must be disabled
  // if both protocols used at the same time (used in CI)
  setsockopt(listen_sock, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt));
#endif

  ESP_LOGI(TAG, "Socket created");

  int err = bind(listen_sock, (struct sockaddr *) &dest_addr, sizeof(dest_addr));
  if (err != 0) {
    ESP_LOGE(TAG, "Socket unable to bind: errno %d", errno);
    ESP_LOGE(TAG, "IPPROTO: %d", addr_family);
    goto CLEAN_UP;
  }
  ESP_LOGI(TAG, "Socket bound, port %d", VSCP_DEFAULT_UDP_PORT);

  err = listen(listen_sock, 1);
  if (err != 0) {
    ESP_LOGE(TAG, "Error occurred during listen: errno %d", errno);
    goto CLEAN_UP;
  }

  int sock;
  while (1) {

    ESP_LOGI(TAG, "Socket listening");

    struct sockaddr_storage source_addr; // Large enough for both IPv4 or IPv6
    socklen_t addr_len = sizeof(source_addr);
    sock           = accept(listen_sock, (struct sockaddr *) &source_addr, &addr_len);
    if (sock < 0) {
      ESP_LOGE(TAG, "Unable to accept connection: errno %d", errno);
      break;
    }

    // Set tcp keepalive option
    setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &keepAlive, sizeof(int));
    setsockopt(sock, IPPROTO_TCP, TCP_KEEPIDLE, &keepIdle, sizeof(int));
    setsockopt(sock, IPPROTO_TCP, TCP_KEEPINTVL, &keepInterval, sizeof(int));
    setsockopt(sock, IPPROTO_TCP, TCP_KEEPCNT, &keepCount, sizeof(int));
    // Convert ip address to string
    if (source_addr.ss_family == PF_INET) {
      inet_ntoa_r(((struct sockaddr_in *) &source_addr)->sin_addr, addr_str, sizeof(addr_str) - 1);
    }
    else if (source_addr.ss_family == PF_INET6) {
      inet6_ntoa_r(((struct sockaddr_in6 *) &source_addr)->sin6_addr, addr_str, sizeof(addr_str) - 1);
    }

    ESP_LOGI(TAG, "Socket accepted ip address: %s", addr_str);
    
    if (cntClients > MAX_TCP_CONNECTIONS) {
      send(sock, MSG_MAX_CLIENTS, sizeof(MSG_MAX_CLIENTS), 0);
      shutdown(sock, 0);
      close(sock); 
      continue;
    }

    xTaskCreate(client_task, "client", 4096, (void*)&sock, 5, NULL);
  }

CLEAN_UP:
  close(listen_sock);
  vTaskDelete(NULL);
}