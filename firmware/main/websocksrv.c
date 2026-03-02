/*
  File: websocksrv.h

  VSCP Wireless CAN4VSCP Gateway (VSCP-WCANG)

  This file is part of the VSCP (https://www.vscp.org)

  The MIT License (MIT)
  Copyright (C) 2025-2026 Ake Hedman, the VSCP project <info@vscp.org>

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

#include "websocksrv.h"

///////////////////////////////////////////////////////////////////////////////
// ws_async_send
//

static void
ws_async_send(void *arg)
{
  httpd_ws_frame_t ws_pkt;
  struct async_resp_arg *resp_arg = arg;
  httpd_handle_t hd               = resp_arg->hd;
  int fd                          = resp_arg->fd;

  char buf[4];
  memset(buf, 0, sizeof(buf));
  sprintf(buf, "%d", led_state);

  memset(&ws_pkt, 0, sizeof(httpd_ws_frame_t));
  ws_pkt.payload = (uint8_t *) buf;
  ws_pkt.len     = strlen(buf);
  ws_pkt.type    = HTTPD_WS_TYPE_TEXT;

  static size_t max_clients = CONFIG_LWIP_MAX_LISTENING_TCP;
  size_t fds                = max_clients;
  int client_fds[max_clients];

  esp_err_t ret = httpd_get_client_list(server, &fds, client_fds);

  if (ret != ESP_OK) {
    return;
  }

  for (int i = 0; i < fds; i++) {
    int client_info = httpd_ws_get_fd_info(server, client_fds[i]);
    if (client_info == HTTPD_WS_CLIENT_WEBSOCKET) {
      httpd_ws_send_frame_async(hd, client_fds[i], &ws_pkt);
    }
  }
  free(resp_arg);
}

///////////////////////////////////////////////////////////////////////////////
// trigger_async_send
//

static esp_err_t
trigger_async_send(httpd_handle_t handle, httpd_req_t *req)
{
  struct async_resp_arg *resp_arg = malloc(sizeof(struct async_resp_arg));
  resp_arg->hd                    = req->handle;
  resp_arg->fd                    = httpd_req_to_sockfd(req);
  return httpd_queue_work(handle, ws_async_send, resp_arg);
}

///////////////////////////////////////////////////////////////////////////////
// handle_ws1_command
//

int handle_ws1_command(char *pCommand, const char *p)
{
  // Make sure command is upper case for easier handling
  for (char *c = pCommand; *c; c++) {
    *c = toupper(*c);
  }

  if (strcmp(pCommand, "NOOP") == 0) {
    vscp_ws1_callback_noop();
  }
  else if (strcmp(pCommand, "VERSION") == 0) {
    vscp_ws1_callback_version();
  }
  else if (strcmp(pCommand, "COPYRIGHT") == 0) {
    vscp_ws1_callback_copyright();
  }
  else if (strcmp(pCommand, "AUTH") == 0) {
    vscp_ws1_callback_auth(p);
  }
  else if (strcmp(pCommand, "CHALLENGE") == 0) {
    vscp_ws1_callback_challenge(p);
  }
  else if (strcmp(pCommand, "OPEN") == 0) {
    vscp_ws1_callback_open();
  }
  else if (strcmp(pCommand, "CLOSE") == 0) {
    vscp_ws1_callback_close();
  }
  else if (strcmp(pCommand, "SETFILTER") == 0) {
    vscp_ws1_callback_setfilter(p);
  }
  else if (strcmp(pCommand, "SF") == 0) {
    vscp_ws1_callback_setfilter();
  }
  else if (strcmp(pCommand, "CLRQUEUE") == 0) {
    vscp_ws1_callback_clrqueue();
  }
  else if (strcmp(pCommand, "CLRQ") == 0) {
    ;
  }
  else {
    ESP_LOGW(TAG, "Unknown command: %s", pCommand);
    return VSCP_ERROR_INVALID_COMMAND;
  }

  return VSCP_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// handle_protocol_request_ws1
//
// Packets are
// Command:        'C' ; command ; optional data that may be separated by additional semicolons.
// Reply:          '+' ; 'command'
// Netative reply: '-' ; 'command' ; Error code ; Error in real text
// Event:          'E' ; head , vscp_class , vscp_type ,obid, datetime, timestamp, GUID, data
//

int
handle_protocol_request_ws1(const char *packet)
{
  uint8_t packet_type = WS1_PKT_TYPE_UNKNOWN;
  char *pCommand; // Pointer to command part of packet

  ESP_LOGI(TAG, "Handling protocol WS1");

  char *p = packet;

  // Command
  if (*p == 'C') {
    paket_type = WS1_PKT_TYPE_COMMAND;
    p++;
    if (';' != *p) {
      // Malformed packet, command part must be separated by ';'
      return VSCP_ERROR_INVALID_FRAME;
    }
    p++;
    if (!*p) {
      // No command part
      return VSCP_ERROR_INVALID_FRAME;
    }

    // Point at command part of packet
    pCommand = p;

    // Find next ';' or end of string to determine end of command part
    while (*p && *p != ';') {
      p++;
    }
    if (*p) {
      *p = 0; // Null-terminate command part  
      p++;
    }

    // p now point to optional data part of packet (if any) or end of string

    ESP_LOGI(TAG, "Received command: %s", pCommand);
    handle_ws1_command(pCommand, p);
    
  }
  // Received event 
  else if (*p == 'E') {
    packet_type = WS1_PKT_TYPE_EVENT;
    vscp_ws1_callback_event();
  }
  // Positive respone
  else if (*p == '+') {
    packet_type = WS1_PKT_TYPE_POSITIVE_RESPONSE;
  }
  // Negative response
  else if (*p == '-') {
    packet_type = WS1_PKT_TYPE_NEGATIVE_RESPONSE;
  }
  // Unknown packet type
  else {
    // Unknown packet type
    return VSCP_ERROR_INVALID_FRAME;
  }

  return VSCP_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// handle_ws_req
//

static esp_err_t
handle_ws1_req(httpd_req_t *req)
{
  if (req->method == HTTP_GET) {
    ESP_LOGI(TAG, "Handshake done, the new connection was opened");
    return ESP_OK;
  }

  httpd_ws_frame_t ws_pkt;
  uint8_t *buf = NULL;
  memset(&ws_pkt, 0, sizeof(httpd_ws_frame_t));
  ws_pkt.type   = HTTPD_WS_TYPE_TEXT;
  esp_err_t ret = httpd_ws_recv_frame(req, &ws_pkt, 0);
  if (ret != ESP_OK) {
    ESP_LOGE(TAG, "httpd_ws_recv_frame failed to get frame len with %d", ret);
    return ret;
  }

  if (ws_pkt.len) {
    buf = calloc(1, ws_pkt.len + 1);
    if (buf == NULL) {
      ESP_LOGE(TAG, "Failed to calloc memory for buf");
      return ESP_ERR_NO_MEM;
    }
    ws_pkt.payload = buf;
    ret            = httpd_ws_recv_frame(req, &ws_pkt, ws_pkt.len);
    if (ret != ESP_OK) {
      ESP_LOGE(TAG, "httpd_ws_recv_frame failed with %d", ret);
      free(buf);
      return ret;
    }
    ESP_LOGI(TAG, "Got packet with message: %s", ws_pkt.payload);
  }

  ESP_LOGI(TAG, "frame len is %d", ws_pkt.len);

  if (ws_pkt.type == HTTPD_WS_TYPE_TEXT && strcmp((char *) ws_pkt.payload, "toggle") == 0) {
    free(buf);
    return trigger_async_send(req->handle, req);
  }
  return ESP_OK;
}

///////////////////////////////////////////////////////////////////////////////
// handle_ws2_req
//

static esp_err_t
handle_ws2_req(httpd_req_t *req)
{
  if (req->method == HTTP_GET) {
    ESP_LOGI(TAG, "Handshake done, the new connection was opened");
    return ESP_OK;
  }

  httpd_ws_frame_t ws_pkt;
  uint8_t *buf = NULL;
  memset(&ws_pkt, 0, sizeof(httpd_ws_frame_t));
  ws_pkt.type   = HTTPD_WS_TYPE_TEXT;
  esp_err_t ret = httpd_ws_recv_frame(req, &ws_pkt, 0);
  if (ret != ESP_OK) {
    ESP_LOGE(TAG, "httpd_ws_recv_frame failed to get frame len with %d", ret);
    return ret;
  }

  if (ws_pkt.len) {
    buf = calloc(1, ws_pkt.len + 1);
    if (buf == NULL) {
      ESP_LOGE(TAG, "Failed to calloc memory for buf");
      return ESP_ERR_NO_MEM;
    }
    ws_pkt.payload = buf;
    ret            = httpd_ws_recv_frame(req, &ws_pkt, ws_pkt.len);
    if (ret != ESP_OK) {
      ESP_LOGE(TAG, "httpd_ws_recv_frame failed with %d", ret);
      free(buf);
      return ret;
    }
    ESP_LOGI(TAG, "Got packet with message: %s", ws_pkt.payload);
  }

  ESP_LOGI(TAG, "frame len is %d", ws_pkt.len);

  if (ws_pkt.type == HTTPD_WS_TYPE_TEXT && strcmp((char *) ws_pkt.payload, "toggle") == 0) {
    free(buf);
    return trigger_async_send(req->handle, req);
  }
  return ESP_OK;
}

///////////////////////////////////////////////////////////////////////////////
// setup_websocket_server
//

httpd_handle_t
setup_websocket_server(void)
{
  httpd_config_t config = HTTPD_DEFAULT_CONFIG();

  httpd_uri_t ws1 = { .uri          = "/ws1",
                      .method       = HTTP_GET,
                      .handler      = handle_ws1_req,
                      .user_ctx     = NULL,
                      .is_websocket = true };

  httpd_uri_t ws2 = { .uri          = "/ws2",
                      .method       = HTTP_GET,
                      .handler      = handle_ws_req,
                      .user_ctx     = NULL,
                      .is_websocket = true };

  if (httpd_start(&server, &config) == ESP_OK) {
    httpd_register_uri_handler(server, &ws1);
    httpd_register_uri_handler(server, &ws2);
  }

  return server;
}
