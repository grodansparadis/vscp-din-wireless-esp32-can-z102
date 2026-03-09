/* ******************************************************************************
 * VSCP (Very Simple Control Protocol)
 * http://www.vscp.org
 *
 * The MIT License (MIT)
 *
 * Copyright (c) 2000-2026 Ake Hedman,
 * The VSCP Project <info@grodansparadis.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 *  This file is part of VSCP - Very Simple Control Protocol
 *  http://www.vscp.org
 *
 * ******************************************************************************
 */

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>

#include <esp_log.h>

#include "vscp-compiler.h"
#include "vscp-projdefs.h"

#include "vscp.h"

#include "vscp-ws1.h"

#define TAG __func__

#define VSCP_WS1_SID_SIZE           16
#define VSCP_WS1_MAX_CRYPTO_BIN_LEN 128

///////////////////////////////////////////////////////////////////////////////
// vscp_ws1_is_hex_string
//

static bool
vscp_ws1_is_hex_string(const char *str)
{
  if (NULL == str) {
    return false;
  }

  for (const char *p = str; *p; ++p) {
    if (!isxdigit((unsigned char) *p)) {
      return false;
    }
  }

  return true;
}

///////////////////////////////////////////////////////////////////////////////
// vscp_ws1_init
//

int
vscp_ws1_init(vscp_ws1_connection_context_t *pctx, void *pdata)
{
  int rv;
  char buf[VSCP_WS1_MAX_PACKET_SIZE] = { 0 };

  // Initialize the connection context
  memset(pctx, 0, sizeof(vscp_ws1_connection_context_t));
  pctx->pdata          = pdata; // Save the user data (request pointer)
  pctx->bAuthenticated = false;
  pctx->bOpen          = false;
  pctx->pdata          = pdata;

  // Clear the global VSCP filter
  memset(&pctx->filter, 0, sizeof(pctx->filter));

  
  // Generate a random SID for the session
  if (VSCP_ERROR_SUCCESS != (rv = vscp_ws1_callback_generate_sid(pctx->sid, sizeof(pctx->sid), pctx))) {
    ESP_LOGE(TAG, "Failed to generate SID with error %d", rv);
    return rv;
  }

  // Send initial sid
  ESP_LOGI(TAG, "Sending generated SID");
  sprintf(buf,
          "+;AUTH0;%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X",
          pctx->sid[0],
          pctx->sid[1],
          pctx->sid[2],
          pctx->sid[3],
          pctx->sid[4],
          pctx->sid[5],
          pctx->sid[6],
          pctx->sid[7],
          pctx->sid[8],
          pctx->sid[9],
          pctx->sid[10],
          pctx->sid[11],
          pctx->sid[12],
          pctx->sid[13],
          pctx->sid[14],
          pctx->sid[15]);
  if (VSCP_ERROR_SUCCESS != (rv = vscp_ws1_callback_reply(buf, pctx))) {
    ESP_LOGE(TAG, "Failed to send initial SID reply rv=%d", rv);
    return rv;
  }

  if (VSCP_ERROR_SUCCESS != (rv = vscp_ws1_callback_init(pctx))) {
    ESP_LOGE(TAG, "Failed to perform WS1 callback init");
    return rv;
  }

  return VSCP_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// vscp_ws1_clearup
//

int
vscp_ws1_clearup(vscp_ws1_connection_context_t *pctx)
{
  int rv;
  if (VSCP_ERROR_SUCCESS != (rv = vscp_ws1_callback_cleanup(pctx))) {
    ESP_LOGE(TAG, "Failed to perform WS1 callback cleanup");
    return rv;
  }

  return VSCP_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// vscp_ws1_generate_sid
//

int
vscp_ws1_generate_sid(uint8_t *sid, size_t size, vscp_ws1_connection_context_t *pctx)
{
  // Generate a random SID (session ID) for authentication and encryption
  // In a real implementation, this should be done using a secure random generator
  for (size_t i = 0; i < size; i++) {
    sid[i] = rand() % 256;
  }
  return VSCP_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// vscp_ws1_handle_protocol_request
//
// Packets are
// Command:        'C' ; command ; optional data that may be separated by additional semicolons.
// Reply:          '+' ; 'command'
// Negative reply: '-' ; 'command' ; Error code ; Error in real text
// Event:          'E' ; head , vscp_class , vscp_type ,obid, datetime, timestamp, GUID, data
//

int
vscp_ws1_handle_protocol_request(const char *pframe, uint16_t len, vscp_ws1_connection_context_t *pctx)
{
  uint8_t frame_type = VSCP_WS1_PKT_TYPE_UNKNOWN;
  char frame_buf[VSCP_WS1_MAX_PACKET_SIZE];
  char *pCommand; // Pointer to command part of packet

  ESP_LOGI(TAG, "Handling protocol WS1");

  if (NULL == pframe || 0 == len || len >= sizeof(frame_buf)) {
    return VSCP_ERROR_INVALID_FRAME;
  }

  memcpy(frame_buf, pframe, len);
  frame_buf[len] = '\0';
  char *p = frame_buf;

  // Command
  if (*p == 'C') {
    frame_type = VSCP_WS1_PKT_TYPE_COMMAND;
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

    ESP_LOGI(TAG, "Received command: %s arg: %s", pCommand, p ? p : "(none)");
    vscp_ws1_handle_command(pCommand, p, pctx);
  }
  // Received event
  else if (*p == 'E') {
    frame_type       = VSCP_WS1_PKT_TYPE_EVENT;
    vscpEvent *pEvent = NULL;
    // Parse event data from packet (p should be in the format "E;head;
    vscp_ws1_callback_event(pEvent, pctx);
  }
  // Positive respone
  else if (*p == '+') {
    frame_type = VSCP_WS1_PKT_TYPE_POSITIVE_RESPONSE;
  }
  // Negative response
  else if (*p == '-') {
    frame_type = VSCP_WS1_PKT_TYPE_NEGATIVE_RESPONSE;
  }
  // Unknown packet type
  else {
    // Unknown packet type
    return VSCP_ERROR_INVALID_FRAME;
  }



  return VSCP_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// vscp_ws1_handle_command
//

int
vscp_ws1_handle_command(const char *pCommand, const char *parg, vscp_ws1_connection_context_t *pctx)
{
  int rv;
  char buf[100] = { 0 };
  char command_buf[VSCP_WS1_MAX_PACKET_SIZE];

  size_t command_len = strnlen(pCommand, sizeof(command_buf));
  if ((0 == command_len) || (command_len >= sizeof(command_buf))) {
    return VSCP_ERROR_INVALID_SYNTAX;
  }

  memcpy(command_buf, pCommand, command_len + 1);

  // Make sure command is upper case for easier handling
  for (char *c = command_buf; *c; c++) {
    *c = (char) toupper((unsigned char) *c);
  }

  if (strcmp(command_buf, "NOOP") == 0) {
    vscp_ws1_callback_reply("+;NOOP", pctx); // Send positive reply
  }
  else if (strcmp(command_buf, "VERSION") == 0) {
    sprintf(buf,
            "+;VERSION;%d.%d.%d.%d",
            VSCP_WS1_PROTOCOL_VERSION,
            VSCP_WS1_PROTOCOL_MINOR_VERSION,
            VSCP_WS1_PROTOCOL_RELEASE_VERSION,
            VSCP_WS1_PROTOCOL_BUILD_VERSION);
    vscp_ws1_callback_reply(buf, pctx); // Send positive reply with version information
  }
  else if (strcmp(command_buf, "COPYRIGHT") == 0) {
    vscp_ws1_callback_copyright(pctx); // Send copyright information
  }
  // Authentication command with session ID and encrypted credentials
  // Expected format for parg: "sid;crypto" where both values are hex strings
  else if (strcmp(command_buf, "AUTH") == 0) {
    char argbuf[VSCP_WS1_MAX_PACKET_SIZE];
    char *sid_hex;
    char *crypto_hex;
    uint8_t sid[16]                  = { 0 };
    uint8_t crypto[VSCP_WS1_MAX_CRYPTO_BIN_LEN] = { 0 };
    size_t sid_hex_len;
    size_t crypto_hex_len;
    size_t crypto_bin_len;

    if ((NULL == parg) || ('\0' == *parg)) {
      ESP_LOGE(TAG, "AUTH missing arguments");
      return VSCP_ERROR_INVALID_SYNTAX;
    }

    if (strnlen(parg, sizeof(argbuf)) >= sizeof(argbuf)) {
      ESP_LOGE(TAG, "AUTH arguments too long");
      return VSCP_ERROR_INVALID_SYNTAX;
    }

    strcpy(argbuf, parg);

    sid_hex    = argbuf;
    crypto_hex = strchr(argbuf, ';');
    if (NULL == crypto_hex) {
      ESP_LOGE(TAG, "AUTH invalid format, expected sid;crypto");
      return VSCP_ERROR_INVALID_SYNTAX;
    }

    *crypto_hex = '\0';
    ++crypto_hex;

    if (('\0' == *sid_hex) || ('\0' == *crypto_hex) || (NULL != strchr(crypto_hex, ';'))) {
      ESP_LOGE(TAG, "AUTH invalid format, expected exactly two arguments");
      return VSCP_ERROR_INVALID_SYNTAX;
    }

    sid_hex_len    = strlen(sid_hex);
    crypto_hex_len = strlen(crypto_hex);

    if ((2 * VSCP_WS1_SID_SIZE != sid_hex_len) || ((sid_hex_len & 1U) != 0U) || !vscp_ws1_is_hex_string(sid_hex)) {
      ESP_LOGE(TAG, "AUTH invalid SID hex");
      return VSCP_ERROR_INVALID_SYNTAX;
    }

    if ((0 == crypto_hex_len) || ((crypto_hex_len & 1U) != 0U) ||
        (crypto_hex_len > (2U * VSCP_WS1_MAX_CRYPTO_BIN_LEN)) || !vscp_ws1_is_hex_string(crypto_hex)) {
      ESP_LOGE(TAG, "AUTH invalid crypto hex");
      return VSCP_ERROR_INVALID_SYNTAX;
    }

    if (16 != (rv = vscp_fwhlp_hex2bin(sid, sizeof(sid), sid_hex))) {
      ESP_LOGE(TAG, "Failed to convert AUTH SID from hex. len returned: %d", rv);
      return VSCP_ERROR_INVALID_FORMAT;
    }

    if (16 != (crypto_bin_len = vscp_fwhlp_hex2bin(crypto+1, sizeof(crypto), crypto_hex))) {
      ESP_LOGE(TAG, "Failed to convert AUTH crypto from hex %d", crypto_bin_len);
      return VSCP_ERROR_INVALID_FORMAT;
    }

    // Attempt to validate user with provided credentials  and session ID
    vscp_ws1_callback_validate_user(crypto, crypto_bin_len+1, sid, pctx); 
    if (VSCP_ERROR_SUCCESS != rv) {
      return rv;
    }
  }
  else if (strcmp(command_buf, "CHALLENGE") == 0) {
    sprintf(buf,
            "+;AUTH0;%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X",
            pctx->sid[0],
            pctx->sid[1],
            pctx->sid[2],
            pctx->sid[3],
            pctx->sid[4],
            pctx->sid[5],
            pctx->sid[6],
            pctx->sid[7],
            pctx->sid[8],
            pctx->sid[9],
            pctx->sid[10],
            pctx->sid[11],
            pctx->sid[12],
            pctx->sid[13],
            pctx->sid[14],
            pctx->sid[15]);
    if (VSCP_ERROR_SUCCESS != (rv = vscp_ws1_callback_reply(buf, pctx))) {
      ESP_LOGE(TAG, "Failed to send CHALLENGE reply rv=%d", rv);
      return rv;
    }
  }
  else if (strcmp(command_buf, "OPEN") == 0) {
    vscp_ws1_callback_open(pctx);
  }
  else if (strcmp(command_buf, "CLOSE") == 0) {
    vscp_ws1_callback_close(pctx);
  }
  else if ((strcmp(command_buf, "SETFILTER") == 0) || (strcmp(command_buf, "SF") == 0)) {
    vscpEventFilter filter;
    memset(&filter, 0, sizeof(filter));

    if ((NULL == parg) || ('\0' == *parg)) {
      ESP_LOGE(TAG, "SETFILTER missing filter argument");
      return VSCP_ERROR_INVALID_SYNTAX;
    }

    if (VSCP_ERROR_SUCCESS != (rv = vscp_fwhlp_parseFilter(&filter, parg))) {
      ESP_LOGE(TAG, "SETFILTER invalid filter string");
      return VSCP_ERROR_INVALID_SYNTAX;
    }

    if (VSCP_ERROR_SUCCESS != (rv = vscp_ws1_callback_setfilter(&filter, pctx))) {
      return rv;
    }
  }
  else if ((strcmp(command_buf, "CLRQUEUE") == 0) || (strcmp(command_buf, "CLRQ") == 0)) {
    vscp_ws1_callback_clrqueue(pctx);
  }
  else {
    // ESP_LOGW(TAG, "Unknown command: %s", pCommand);
    return VSCP_ERROR_INVALID_SYNTAX;
  }

  return VSCP_ERROR_SUCCESS;
}
