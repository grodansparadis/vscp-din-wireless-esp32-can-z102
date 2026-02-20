/*
  File: udpsrv.c

  VSCP Wireless CAN4VSCP Gateway (VSCP-WCANG)

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

  UDP send: echo "Hello from PC" | nc -w1 -u 192.168.1.112 33333
  UDP receive: echo "Hello from PC" | nc -w1 -u 192.168.1.112 33333

  UDP client: nc -u 192.168.1.112 33333
  UDP server: nc -u -l 192.168.1.112 -p 33333

  Config
  ------
  Enable
  ip-address for server
  port
  Encryption
  Encryption key
  Valid client ip's
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

#include "udpsrv.h"

static const char *TAG = "udpsrv";

////////////////////////////////////////////////////////////////////////////
// udpsrv_task
//
// This task listens for incoming UDP packets on the configured port. When a
// packet is received, it parse the data and if a valid VSCP frame send it
// on the CAN interface. The task runs indefinitely and handles errors gracefully, 
// logging any issues with socket creation, binding, or receiving data.

void
udpsrv_task(void *pvParameters)
{
  char rx_buffer[128];
  char addr_str[128];
  int addr_family = (int) pvParameters;
  int ip_protocol = 0;
  struct sockaddr_in6 dest_addr;

  while (1) {

    if (addr_family == AF_INET) {
      struct sockaddr_in *dest_addr_ip4 = (struct sockaddr_in *) &dest_addr;
      dest_addr_ip4->sin_addr.s_addr    = htonl(INADDR_ANY);
      dest_addr_ip4->sin_family         = AF_INET;
      dest_addr_ip4->sin_port           = htons(VSCP_DEFAULT_UDP_PORT);
      ip_protocol                       = IPPROTO_IP;
    }
    else if (addr_family == AF_INET6) {
      bzero(&dest_addr.sin6_addr.un, sizeof(dest_addr.sin6_addr.un));
      dest_addr.sin6_family = AF_INET6;
      dest_addr.sin6_port   = htons(VSCP_DEFAULT_UDP_PORT);
      ip_protocol           = IPPROTO_IPV6;
    }

    int sock = socket(addr_family, SOCK_DGRAM, ip_protocol);
    if (sock < 0) {
      ESP_LOGE(TAG, "Unable to create socket: errno %d", errno);
      break;
    }
    ESP_LOGI(TAG, "Socket created");

#if defined(CONFIG_LWIP_NETBUF_RECVINFO) && !defined(CONFIG_EXAMPLE_IPV6)
    int enable = 1;
    lwip_setsockopt(sock, IPPROTO_IP, IP_PKTINFO, &enable, sizeof(enable));
#endif

#if defined(CONFIG_EXAMPLE_IPV4) && defined(CONFIG_EXAMPLE_IPV6)
    if (addr_family == AF_INET6) {
      // Note that by default IPV6 binds to both protocols, it is must be disabled
      // if both protocols used at the same time (used in CI)
      int opt = 1;
      setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
      setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt));
    }
#endif
    // Set timeout
    struct timeval timeout;
    timeout.tv_sec  = 10;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout);

    int err = bind(sock, (struct sockaddr *) &dest_addr, sizeof(dest_addr));
    if (err < 0) {
      ESP_LOGE(TAG, "Socket unable to bind: errno %d", errno);
    }
    ESP_LOGI(TAG, "Socket bound, port %d", VSCP_DEFAULT_UDP_PORT);

    struct sockaddr_storage source_addr; // Large enough for both IPv4 or IPv6
    socklen_t socklen = sizeof(source_addr);

#if defined(CONFIG_LWIP_NETBUF_RECVINFO) && !defined(CONFIG_EXAMPLE_IPV6)
    struct iovec iov;
    struct msghdr msg;
    struct cmsghdr *cmsgtmp;
    u8_t cmsg_buf[CMSG_SPACE(sizeof(struct in_pktinfo))];

    iov.iov_base       = rx_buffer;
    iov.iov_len        = sizeof(rx_buffer);
    msg.msg_control    = cmsg_buf;
    msg.msg_controllen = sizeof(cmsg_buf);
    msg.msg_flags      = 0;
    msg.msg_iov        = &iov;
    msg.msg_iovlen     = 1;
    msg.msg_name       = (struct sockaddr *) &source_addr;
    msg.msg_namelen    = socklen;
#endif

    while (1) {
      ESP_LOGI(TAG, "Waiting for data");
#if defined(CONFIG_LWIP_NETBUF_RECVINFO) && !defined(CONFIG_EXAMPLE_IPV6)
      int len = recvmsg(sock, &msg, 0);
#else
      int len = recvfrom(sock, rx_buffer, sizeof(rx_buffer) - 1, 0, (struct sockaddr *) &source_addr, &socklen);
#endif
      // Error occurred during receiving
      if (len < 0) {
        if (errno == EWOULDBLOCK || errno == EAGAIN) {
          ESP_LOGI(TAG, "Receive timeout, no data received");
          continue;
        }
        else {
          ESP_LOGE(TAG, "recvfrom failed: errno %d", errno);
          
        }
        break;
      }
      // Data received
      else {
        // Get the sender's ip address as string
        if (source_addr.ss_family == PF_INET) {
          inet_ntoa_r(((struct sockaddr_in *) &source_addr)->sin_addr, addr_str, sizeof(addr_str) - 1);
#if defined(CONFIG_LWIP_NETBUF_RECVINFO) && !defined(CONFIG_EXAMPLE_IPV6)
          for (cmsgtmp = CMSG_FIRSTHDR(&msg); cmsgtmp != NULL; cmsgtmp = CMSG_NXTHDR(&msg, cmsgtmp)) {
            if (cmsgtmp->cmsg_level == IPPROTO_IP && cmsgtmp->cmsg_type == IP_PKTINFO) {
              struct in_pktinfo *pktinfo;
              pktinfo = (struct in_pktinfo *) CMSG_DATA(cmsgtmp);
              ESP_LOGI(TAG, "dest ip: %s\n", inet_ntoa(pktinfo->ipi_addr));
            }
          }
#endif
        }
        else if (source_addr.ss_family == PF_INET6) {
          inet6_ntoa_r(((struct sockaddr_in6 *) &source_addr)->sin6_addr, addr_str, sizeof(addr_str) - 1);
        }

        rx_buffer[len] = 0; // Null-terminate whatever we received and treat like a string...
        ESP_LOGI(TAG, "Received %d bytes from %s:", len, addr_str);
        ESP_LOGI(TAG, "%s", rx_buffer);

        int err = sendto(sock, rx_buffer, len, 0, (struct sockaddr *) &source_addr, sizeof(source_addr));
        if (err < 0) {
          ESP_LOGE(TAG, "Error occurred during sending: errno %d", errno);
          break;
        }
      }
    }

    if (sock != -1) {
      ESP_LOGE(TAG, "Shutting down socket and restarting...");
      shutdown(sock, 0);
      close(sock);
    }
  }
  vTaskDelete(NULL);
}

////////////////////////////////////////////////////////////////////////////////
// udp_start
// This function creates the UDP server task for both IPv4 and IPv6 (if enabled).
// The task will listen for incoming UDP packets and process them as defined in udpsrv_task.
//

void udp_start(void)
{
  xTaskCreate(udpsrv_task, "udpsrv", 4096, (void *) AF_INET, 5, NULL);
#ifdef CONFIG_EXAMPLE_IPV6
  xTaskCreate(udpsrv_task, "udpsrv", 4096, (void *) AF_INET6, 5, NULL);
#endif
}