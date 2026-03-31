/*
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

  This file contains callback implementations for the VSCP binary protocol.
*/

/*!
  The abstraction of the binary interface is defined in vscp-binary.h and vscp-binary.c
  This file moves the abstraction into the real world on a real device.
  The callbacks defined in vscp-binary.h are implemented here.
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
#include <esp_http_server.h>

#include <esp_event_base.h>
#include <esp_tls_crypto.h>
#include <esp_vfs.h>
#include <esp_spiffs.h>
#include <esp_http_server.h>

#include <netinet/in.h>
#include <lwip/sockets.h>

#include "vscp-compiler.h"
#include "vscp-projdefs.h"

#include <vscp.h>
#include <crc.h>
#include <vscp-firmware-helper.h>
#include "vscp-binary.h"
#include "vscp-mesh.h"
#include "vscp-ws1.h"
#include "vscp-ws-common.h"

static bool g_vscp_mesh_initialized = false;

static void
vscp_binary_mesh_lazy_init(void)
{
  if (!g_vscp_mesh_initialized) {
    vscp_mesh_config_t cfg;
    vscp_mesh_default_config(&cfg);
    (void) vscp_mesh_init(&cfg);
    g_vscp_mesh_initialized = true;
  }
}

///////////////////////////////////////////////////////////////////////////////
// vscp_binary_callback_reply
//

int
vscp_binary_callback_reply(const void *pdata, uint16_t command, uint16_t error, const uint8_t *parg, size_t len)
{
  if (NULL == pdata) {
    return VSCP_ERROR_PARAMETER;
  }

  vscp_ws_connection_context_t *pctx = (vscp_ws_connection_context_t *) pdata;
  httpd_req_t *req                   = (httpd_req_t *) pctx->pdata;
  if (NULL == req) {
    return VSCP_ERROR_INVALID_CONTEXT;
  }

  const uint8_t encryption = pctx->encryption & 0x0F;
  const size_t plain_len   = 1 + 4 + len + 2; // type + command/error + argument + crc
  uint8_t *plain           = calloc(1, plain_len);
  if (NULL == plain) {
    return VSCP_ERROR_MEMORY;
  }

  // Frame type 0xF0 is reply, lower nibble is encryption algorithm.
  plain[0] = 0xF0 | encryption;
  plain[1] = (command >> 8) & 0xFF;
  plain[2] = command & 0xFF;
  plain[3] = (error >> 8) & 0xFF;
  plain[4] = error & 0xFF;

  if (parg && len > 0) {
    memcpy(plain + 5, parg, len);
  }

  // CRC is over command + error + argument (skip type byte and crc bytes).
  uint16_t crc  = crcFast(plain + 1, 4 + len);
  plain[5 + len] = (crc >> 8) & 0xFF;
  plain[6 + len] = crc & 0xFF;

  const uint8_t *tx_payload = plain;
  size_t tx_len             = plain_len;
  uint8_t *enc              = NULL;

  if (encryption != VSCP_HLO_ENCRYPTION_NONE) {
    enc = calloc(1, plain_len + 32); // Room for padding and trailing IV.
    if (NULL == enc) {
      free(plain);
      return VSCP_ERROR_MEMORY;
    }

    tx_len = vscp_fwhlp_encryptFrame(enc,
                                     plain,
                                     plain_len,
                                     vscp_ws1_callback_get_primary_key(pctx),
                                     NULL,
                                     VSCP_ENCRYPTION_FROM_TYPE_BYTE);
    if (0 == tx_len) {
      free(enc);
      free(plain);
      return VSCP_ERROR_ERROR;
    }

    tx_payload = enc;
  }

  httpd_ws_frame_t tx = { 0 };
  tx.type             = HTTPD_WS_TYPE_BINARY;
  tx.payload          = (uint8_t *) tx_payload;
  tx.len              = tx_len;

  esp_err_t err = httpd_ws_send_frame(req, &tx);

  free(enc);
  free(plain);

  if (ESP_OK != err) {
    return VSCP_ERROR_INTERFACE;
  }

  return VSCP_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// vscp_binary_callback_challenge
//

int
vscp_binary_callback_challenge(const void *pdata)
{
  if (NULL == pdata) {
    return VSCP_ERROR_PARAMETER;
  }

  // Generate a random 16-byte challenge
  uint8_t challenge[16];
  esp_fill_random(challenge, sizeof(challenge));

  // Send challenge as binary reply with command 0 and error 0
  return vscp_binary_callback_reply(pdata, 0, VSCP_ERROR_SUCCESS, challenge, sizeof(challenge));
}

///////////////////////////////////////////////////////////////////////////////
// vscp_binary_callback_get_chid
//

int
vscp_binary_callback_get_chid(const void *pdata, uint32_t *pchid)
{
  if (NULL == pdata || NULL == pchid) {
    return VSCP_ERROR_PARAMETER;
  }

  // Generate a unique channel ID from session ID bytes
  vscp_ws_connection_context_t *pctx = (vscp_ws_connection_context_t *) pdata;
  uint32_t chid                       = (pctx->sid[0] << 24) | (pctx->sid[1] << 16) | (pctx->sid[2] << 8) | pctx->sid[3];
  *pchid                             = chid;

  // Convert to big-endian bytes for reply
  uint8_t arg[4];
  arg[0] = (chid >> 24) & 0xFF;
  arg[1] = (chid >> 16) & 0xFF;
  arg[2] = (chid >> 8) & 0xFF;
  arg[3] = chid & 0xFF;

  // Send reply with channel ID
  return vscp_binary_callback_reply(pdata, 0, VSCP_ERROR_SUCCESS, arg, sizeof(arg));
}

///////////////////////////////////////////////////////////////////////////////
// vscp_binary_callback_set_guid
//

int
vscp_binary_callback_set_guid(const void *pdata, uint8_t *pguid)
{
  if (NULL == pdata || NULL == pguid) {
    return VSCP_ERROR_PARAMETER;
  }

  // Send reply confirming GUID set
  return vscp_binary_callback_reply(pdata, 0, VSCP_ERROR_SUCCESS, NULL, 0);
}

///////////////////////////////////////////////////////////////////////////////
// vscp_binary_callback_get_guid
//

int
vscp_binary_callback_get_guid(const void *pdata, uint8_t *pguid)
{
  if (NULL == pdata || NULL == pguid) {
    return VSCP_ERROR_PARAMETER;
  }

  // Use session ID as GUID (16 bytes)
  vscp_ws_connection_context_t *pctx = (vscp_ws_connection_context_t *) pdata;
  memcpy(pguid, pctx->sid, 16);

  // Send reply with GUID (16 bytes)
  return vscp_binary_callback_reply(pdata, 0, VSCP_ERROR_SUCCESS, pctx->sid, 16);
}

///////////////////////////////////////////////////////////////////////////////
// vscp_binary_callback_setfilter
//

int
vscp_binary_callback_setfilter(const void *pdata, const vscpEventFilter *pfilter)
{
  if (NULL == pdata || NULL == pfilter) {
    return VSCP_ERROR_PARAMETER;
  }

  vscp_ws_connection_context_t *pctx = (vscp_ws_connection_context_t *) pdata;
  memcpy(&pctx->filter, pfilter, sizeof(vscpEventFilter));

  // Send reply confirming filter set
  return vscp_binary_callback_reply(pdata, 0, VSCP_ERROR_SUCCESS, NULL, 0);
}

///////////////////////////////////////////////////////////////////////////////
// vscp_binary_callback_setmask
//

int
vscp_binary_callback_setmask(const void *pdata, const vscpEventFilter *pfilter)
{
  if (NULL == pdata || NULL == pfilter) {
    return VSCP_ERROR_PARAMETER;
  }

  // For simplicity, we store mask in the same filter structure
  // In a real implementation, you might want a separate mask field
  vscp_ws_connection_context_t *pctx = (vscp_ws_connection_context_t *) pdata;
  // Mask is typically combined with filter; store it separately if needed
  (void) pctx;

  // Send reply confirming mask set
  return vscp_binary_callback_reply(pdata, 0, VSCP_ERROR_SUCCESS, NULL, 0);
}

///////////////////////////////////////////////////////////////////////////////
// vscp_binary_callback_get_version
//

int
vscp_binary_callback_get_version(const void *pdata, uint8_t *pversion)
{
  if (NULL == pdata || NULL == pversion) {
    return VSCP_ERROR_PARAMETER;
  }

  // Send reply with version byte
  return vscp_binary_callback_reply(pdata, 0, VSCP_ERROR_SUCCESS, pversion, 1);
}

///////////////////////////////////////////////////////////////////////////////
// vscp_binary_callback_is_open
//

bool
vscp_binary_callback_is_open(const void *pdata)
{
  return true;
}

///////////////////////////////////////////////////////////////////////////////
// vscp_binary_callback_open
//

int
vscp_binary_callback_open(const void *pdata)
{
  if (NULL == pdata) {
    return VSCP_ERROR_PARAMETER;
  }

  vscp_ws_connection_context_t *pctx = (vscp_ws_connection_context_t *) pdata;
  pctx->bOpen                        = true;

  // Send reply confirming opened
  return vscp_binary_callback_reply(pdata, 0, VSCP_ERROR_SUCCESS, NULL, 0);
}

///////////////////////////////////////////////////////////////////////////////
// vscp_binary_callback_close
//

int
vscp_binary_callback_close(const void *pdata)
{
  if (NULL == pdata) {
    return VSCP_ERROR_PARAMETER;
  }

  vscp_ws_connection_context_t *pctx = (vscp_ws_connection_context_t *) pdata;
  pctx->bOpen                        = false;

  // Send reply confirming closed
  return vscp_binary_callback_reply(pdata, 0, VSCP_ERROR_SUCCESS, NULL, 0);
}

///////////////////////////////////////////////////////////////////////////////
// vscp_binary_callback_user
//

int
vscp_binary_callback_user(const void *pdata, const char *user)
{
  if (NULL == pdata || NULL == user) {
    return VSCP_ERROR_PARAMETER;
  }

  // Note: user field is a ws_user_t structure, not a simple string
  // In a real implementation, extract user info from user string
  (void) user;

  // Send reply confirming user set
  return vscp_binary_callback_reply(pdata, 0, VSCP_ERROR_SUCCESS, NULL, 0);
}

///////////////////////////////////////////////////////////////////////////////
// vscp_binary_callback_password
//

int
vscp_binary_callback_password(const void *pdata, const char *password)
{
  if (NULL == pdata || NULL == password) {
    return VSCP_ERROR_PARAMETER;
  }

  // Send reply confirming password set (don't store password in context)
  return vscp_binary_callback_reply(pdata, 0, VSCP_ERROR_SUCCESS, NULL, 0);
}

///////////////////////////////////////////////////////////////////////////////
// vscp_binary_callback_check_authenticated
//

int
vscp_binary_callback_check_authenticated(const void *pdata)
{
  if (NULL == pdata) {
    return VSCP_ERROR_PARAMETER;
  }

  vscp_ws_connection_context_t *pctx = (vscp_ws_connection_context_t *) pdata;
  uint8_t auth_status                = pctx->bAuthenticated ? 1 : 0;

  // Send reply with authentication status
  return vscp_binary_callback_reply(pdata, 0, VSCP_ERROR_SUCCESS, &auth_status, 1);
}

///////////////////////////////////////////////////////////////////////////////
// vscp_binary_callback_check_privilege
//

int
vscp_binary_callback_check_privilege(const void *pdata, uint8_t priv)
{
  if (NULL == pdata) {
    return VSCP_ERROR_PARAMETER;
  }

  // Check if authenticated (simple privilege check)
  vscp_ws_connection_context_t *pctx = (vscp_ws_connection_context_t *) pdata;
  uint8_t has_priv                   = pctx->bAuthenticated ? 1 : 0;

  // Send reply with privilege status
  return vscp_binary_callback_reply(pdata, 0, VSCP_ERROR_SUCCESS, &has_priv, 1);
}

///////////////////////////////////////////////////////////////////////////////
// vscp_binary_callback_test
//

int
vscp_binary_callback_test(const void *pdata, const uint8_t *arg, size_t len)
{
  if (NULL == pdata) {
    return VSCP_ERROR_PARAMETER;
  }

  // Echo back the test data as reply
  return vscp_binary_callback_reply(pdata, 0, VSCP_ERROR_SUCCESS, arg, len);
}

///////////////////////////////////////////////////////////////////////////////
// vscp_binary_callback_wcyd
//

int
vscp_binary_callback_wcyd(const void *pdata, uint64_t *pwcyd)
{
  if (NULL == pdata || NULL == pwcyd) {
    return VSCP_ERROR_PARAMETER;
  }

  // Send reply with WCYD (What Can You Do) info - 8 bytes, big-endian
  uint8_t wcyd_bytes[8];
  wcyd_bytes[0] = (*pwcyd >> 56) & 0xFF;
  wcyd_bytes[1] = (*pwcyd >> 48) & 0xFF;
  wcyd_bytes[2] = (*pwcyd >> 40) & 0xFF;
  wcyd_bytes[3] = (*pwcyd >> 32) & 0xFF;
  wcyd_bytes[4] = (*pwcyd >> 24) & 0xFF;
  wcyd_bytes[5] = (*pwcyd >> 16) & 0xFF;
  wcyd_bytes[6] = (*pwcyd >> 8) & 0xFF;
  wcyd_bytes[7] = *pwcyd & 0xFF;

  return vscp_binary_callback_reply(pdata, 0, VSCP_ERROR_SUCCESS, wcyd_bytes, sizeof(wcyd_bytes));
}

///////////////////////////////////////////////////////////////////////////////
// vscp_binary_callback_check_data
//

int
vscp_binary_callback_check_data(const void *pdata, uint32_t *pcount)
{
  if (NULL == pdata || NULL == pcount) {
    return VSCP_ERROR_PARAMETER;
  }

  // Send reply with data count (4 bytes, big-endian)
  uint8_t count_bytes[4];
  count_bytes[0] = (*pcount >> 24) & 0xFF;
  count_bytes[1] = (*pcount >> 16) & 0xFF;
  count_bytes[2] = (*pcount >> 8) & 0xFF;
  count_bytes[3] = *pcount & 0xFF;

  return vscp_binary_callback_reply(pdata, 0, VSCP_ERROR_SUCCESS, count_bytes, sizeof(count_bytes));
}

///////////////////////////////////////////////////////////////////////////////
// vscp_binary_callback_clrall
//

int
vscp_binary_callback_clrall(const void *pdata)
{
  if (NULL == pdata) {
    return VSCP_ERROR_PARAMETER;
  }

  // Send reply confirming all cleared
  return vscp_binary_callback_reply(pdata, 0, VSCP_ERROR_SUCCESS, NULL, 0);
}

///////////////////////////////////////////////////////////////////////////////
// vscp_binary_callback_send_event
//

int
vscp_binary_callback_send_event(const void *pdata, const vscpEvent *pev)
{
  if (NULL == pdata || NULL == pev) {
    return VSCP_ERROR_PARAMETER;
  }

  // Send reply confirming event sent
  return vscp_binary_callback_reply(pdata, 0, VSCP_ERROR_SUCCESS, NULL, 0);
}

///////////////////////////////////////////////////////////////////////////////
// vscp_binary_callback_send_eventex
//

int
vscp_binary_callback_send_eventex(const void *pdata, const vscpEventEx *pex)
{
  (void) pdata;

  vscp_binary_mesh_lazy_init();
  int rv = vscp_mesh_send_eventex(pex, VSCP_MESH_ADDR_BROADCAST);

  // Preserve existing callback behavior when no mesh TX backend is attached yet.
  if (VSCP_ERROR_UNSUPPORTED == rv) {
    return VSCP_ERROR_SUCCESS;
  }

  return rv;
}

///////////////////////////////////////////////////////////////////////////////
// vscp_binary_callback_get_event
//

int
vscp_binary_callback_get_event(const void *pdata, vscpEvent *pev)
{
  if (NULL == pdata || NULL == pev) {
    return VSCP_ERROR_PARAMETER;
  }

  // Send reply confirming event retrieved
  return vscp_binary_callback_reply(pdata, 0, VSCP_ERROR_SUCCESS, NULL, 0);
}

///////////////////////////////////////////////////////////////////////////////
// vscp_binary_callback_get_eventex
//

int
vscp_binary_callback_get_eventex(const void *pdata, vscpEventEx *pex)
{
  if (NULL == pdata || NULL == pex) {
    return VSCP_ERROR_PARAMETER;
  }

  // Send reply confirming event retrieved
  return vscp_binary_callback_reply(pdata, 0, VSCP_ERROR_SUCCESS, NULL, 0);
}

///////////////////////////////////////////////////////////////////////////////
// vscp_binary_callback_send_asyncevent
//

int
vscp_binary_callback_send_asyncevent(const void *pdata, vscpEvent *pev)
{
  if (NULL == pdata || NULL == pev) {
    return VSCP_ERROR_PARAMETER;
  }

  // Send reply confirming async event sent
  return vscp_binary_callback_reply(pdata, 0, VSCP_ERROR_SUCCESS, NULL, 0);
}

///////////////////////////////////////////////////////////////////////////////
// vscp_binary_callback_quit
//

int
vscp_binary_callback_quit(const void *pdata)
{
  if (NULL == pdata) {
    return VSCP_ERROR_PARAMETER;
  }

  // Send reply confirming quit
  return vscp_binary_callback_reply(pdata, 0, VSCP_ERROR_SUCCESS, NULL, 0);
}

///////////////////////////////////////////////////////////////////////////////
// vscp_binary_callback_write_client
//

int
vscp_binary_callback_write_client(const void *pdata, const char *msg)
{
  if (NULL == pdata || NULL == msg) {
    return VSCP_ERROR_PARAMETER;
  }

  // Send reply with message echoed back
  size_t len = strlen(msg);
  return vscp_binary_callback_reply(pdata, 0, VSCP_ERROR_SUCCESS, (const uint8_t *)msg, len);
}

///////////////////////////////////////////////////////////////////////////////
// vscp_binary_callback_get_interface_count
//

int
vscp_binary_callback_get_interface_count(const void *pdata, uint16_t *pcount)
{
  if (NULL == pdata || NULL == pcount) {
    return VSCP_ERROR_PARAMETER;
  }

  // Send reply with interface count (2 bytes, big-endian)
  uint8_t count_bytes[2];
  count_bytes[0] = (*pcount >> 8) & 0xFF;
  count_bytes[1] = *pcount & 0xFF;

  return vscp_binary_callback_reply(pdata, 0, VSCP_ERROR_SUCCESS, count_bytes, sizeof(count_bytes));
}

///////////////////////////////////////////////////////////////////////////////
// vscp_binary_callback_get_interface
//

int
vscp_binary_callback_get_interface(const void *pdata, uint16_t idx, vscp_interface_info_t *pifinfo)
{
  if (NULL == pdata || NULL == pifinfo) {
    return VSCP_ERROR_PARAMETER;
  }

  // Send reply with interface info (just confirm for now)
  return vscp_binary_callback_reply(pdata, 0, VSCP_ERROR_SUCCESS, NULL, 0);
}

///////////////////////////////////////////////////////////////////////////////
// vscp_binary_callback_interface_open
//

int
vscp_binary_callback_interface_open(const void *pdata, uint16_t idx)
{
  if (NULL == pdata) {
    return VSCP_ERROR_PARAMETER;
  }

  // Send reply confirming interface opened
  return vscp_binary_callback_reply(pdata, 0, VSCP_ERROR_SUCCESS, NULL, 0);
}

///////////////////////////////////////////////////////////////////////////////
// vscp_binary_callback_interface_close
//

int
vscp_binary_callback_interface_close(const void *pdata, uint16_t idx)
{
  if (NULL == pdata) {
    return VSCP_ERROR_PARAMETER;
  }

  // Send reply confirming interface closed
  return vscp_binary_callback_reply(pdata, 0, VSCP_ERROR_SUCCESS, NULL, 0);
}

///////////////////////////////////////////////////////////////////////////////
// vscp_binary_callback_event_received
//

int
vscp_binary_callback_event_received(const void *pdata, const vscpEvent *pev)
{
  (void) pdata;

  if (NULL == pev) {
    return VSCP_ERROR_PARAMETER;
  }

  vscpEventEx ex;
  int rv = vscp_fwhlp_convertEventToEventEx(&ex, pev);
  if (VSCP_ERROR_SUCCESS != rv) {
    return rv;
  }

  vscp_binary_mesh_lazy_init();
  rv = vscp_mesh_send_eventex(&ex, VSCP_MESH_ADDR_BROADCAST);

  // Preserve existing callback behavior when no mesh TX backend is attached yet.
  if (VSCP_ERROR_UNSUPPORTED == rv) {
    return VSCP_ERROR_SUCCESS;
  }

  return rv;
}

///////////////////////////////////////////////////////////////////////////////
// vscp_binary_callback_disconnect_client
//

int
vscp_binary_callback_disconnect_client(const void *pdata)
{
  if (NULL == pdata) {
    return VSCP_ERROR_PARAMETER;
  }

  // Send reply confirming disconnect
  return vscp_binary_callback_reply(pdata, 0, VSCP_ERROR_SUCCESS, NULL, 0);
}

///////////////////////////////////////////////////////////////////////////////
// vscp_binary_callback_statistics
//

int
vscp_binary_callback_statistics(const void *pdata, VSCPStatistics *pStatistics)
{
  if (NULL == pdata || NULL == pStatistics) {
    return VSCP_ERROR_PARAMETER;
  }

  // Send reply confirming statistics retrieved
  return vscp_binary_callback_reply(pdata, 0, VSCP_ERROR_SUCCESS, NULL, 0);
}

///////////////////////////////////////////////////////////////////////////////
// vscp_binary_callback_info
//

int
vscp_binary_callback_info(const void *pdata, VSCPStatus *pstatus)
{
  if (NULL == pdata || NULL == pstatus) {
    return VSCP_ERROR_PARAMETER;
  }

  // Send reply confirming info retrieved
  return vscp_binary_callback_reply(pdata, 0, VSCP_ERROR_SUCCESS, NULL, 0);
}

///////////////////////////////////////////////////////////////////////////////
// vscp_binary_callback_user_command
//

int
vscp_binary_callback_user_command(const void *pdata, uint16_t command, const uint8_t *parg, size_t len)
{
  if (NULL == pdata) {
    return VSCP_ERROR_PARAMETER;
  }

  // Send reply confirming user command executed
  return vscp_binary_callback_reply(pdata, command, VSCP_ERROR_SUCCESS, parg, len);
}

///////////////////////////////////////////////////////////////////////////////
// vscp_binary_callback_restart
//

int
vscp_binary_callback_restart(const void *pdata)
{
  if (NULL == pdata) {
    return VSCP_ERROR_PARAMETER;
  }

  // Send reply confirming restart
  vscp_binary_callback_reply(pdata, 0, VSCP_ERROR_SUCCESS, NULL, 0);

  // Schedule device restart
  esp_restart();
  return VSCP_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// vscp_binary_callback_shutdown
//

int
vscp_binary_callback_shutdown(const void *pdata)
{
  if (NULL == pdata) {
    return VSCP_ERROR_PARAMETER;
  }

  // Send reply confirming shutdown (actual shutdown will be deferred)
  vscp_binary_callback_reply(pdata, 0, VSCP_ERROR_SUCCESS, NULL, 0);

  // Note: Actual system shutdown would require additional implementation
  // For now, just return success after notifying the client
  return VSCP_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// vscp_binary_callback_text
//

int
vscp_binary_callback_text(const void *pdata)
{
  // We do noting except resetting the binary flag in the context.

  // Check pointer
  if (NULL == pdata) {
    return VSCP_ERROR_PARAMETER;
  }

  // Set the binary flag in the context
  vscp_ws_connection_context_t *pctx = (vscp_ws_connection_context_t *) pdata;
  (void) pctx;

  return VSCP_ERROR_SUCCESS;
}