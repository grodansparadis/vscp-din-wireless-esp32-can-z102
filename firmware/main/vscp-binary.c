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

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>

#include "vscp-binary.h"

///////////////////////////////////////////////////////////////////////////////
// vscp_handle_binary_command
//

int
vscp_handle_binary_command(uint16_t command, const char *parg, size_t len, const void *pctx)
{
  int rv;
  char buf[512] = { 0 };

  if (VSCP_BINARY_COMMAND_CODE_NOOP == command) {
    // No operation, just reply with success
    return vscp_binary_callback_reply(pctx, command, VSCP_ERROR_SUCCESS, NULL, 0);
  }
  else if (VSCP_BINARY_COMMAND_CODE_QUIT == command) {
    // Quit command, close connection
    return vscp_binary_callback_quit(pctx);
  }
  else if (VSCP_BINARY_COMMAND_CODE_USER == command) {
    return vscp_binary_callback_user(pctx, parg);
  }
  else if (VSCP_BINARY_COMMAND_CODE_PASS == command) {
    return vscp_binary_callback_password(pctx, parg);
  }
  else if (VSCP_BINARY_COMMAND_CODE_CHALLENGE == command) {
    return vscp_binary_callback_challenge(pctx);
  }
  else if (VSCP_BINARY_COMMAND_CODE_SEND == command) {
    vscpEventEx ex;
    // Parse event data from parg and fill ex structure
    if (VSCP_ERROR_SUCCESS != (rv = vscp_fwhlp_getEventExFromFrame(&ex, parg, len))) {
      ESP_LOGE(TAG, "Failed to parse event data from argument with error %d", rv);
      return vscp_binary_callback_reply(pctx, command, rv, NULL, 0);
    }
    return vscp_binary_callback_send(pctx, &ex);
  }
  else if (VSCP_BINARY_COMMAND_CODE_RETR == command) {
    // Check argument length
    if (len < 2) {
      ESP_LOGE(TAG, "RETR command argument too short");
      return vscp_binary_callback_reply(pctx, command, VSCP_ERROR_INVALID_ARGUMENT, NULL, 0);
    }
    uint16_t count = (parg[0] << 8) | parg[1];
    return vscp_binary_callback_retr(pctx, count);
  }
  else if (VSCP_BINARY_COMMAND_CODE_OPEN == command) {
    return vscp_binary_callback_open(pctx);
  }
  else if (VSCP_BINARY_COMMAND_CODE_CLOSE == command) {
    return vscp_binary_callback_close(pctx);
  }
  else if (VSCP_BINARY_COMMAND_CODE_CHKDATA == command) {
    uint32_t count;
    if (VSCP_ERROR_SUCCESS != (rv = vscp_binary_callback_check_data(pctx, &count))) {
      return vscp_binary_callback_reply(pctx, command, rv, NULL, 0);
    }
    else {
      uint8_t buf[4];
      buf[0] = (count >> 24) & 0xFF;
      buf[1] = (count >> 16) & 0xFF;
      buf[2] = (count >> 8) & 0xFF;
      buf[3] = count & 0xFF;

      // Send reply with count of events ready to be received
      return vscp_binary_callback_reply(pctx, command, VSCP_ERROR_SUCCESS, (char *) buf, sizeof(buf));
    }
  }
  else if (VSCP_BINARY_COMMAND_CODE_CLEAR == command) {
    return vscp_binary_callback_clrall(pctx);
  }
  else if (VSCP_BINARY_COMMAND_CODE_STAT == command) {
    structVSCPStatistics statistics;
    if (VSCP_ERROR_SUCCESS != (rv = vscp_binary_callback_stat(pctx, &stat))) {
      return vscp_binary_callback_reply(pctx, command, rv, NULL, 0);
    }
    else {
      uint8_t buf[28];
      // Fill buf with statistical information from statistics structure
      buf[0] = (statistics.x >> 24) & 0xFF;
      buf[1] = (statistics.x >> 16) & 0xFF;
      buf[2] = (statistics.x >> 8) & 0xFF;
      buf[3] = statistics.x & 0xFF;

      buf[4] = (statistics.y >> 24) & 0xFF;
      buf[5] = (statistics.y >> 16) & 0xFF;
      buf[6] = (statistics.y >> 8) & 0xFF;
      buf[7] = statistics.y & 0xFF;

      buf[8]  = (statistics.z >> 24) & 0xFF;
      buf[9]  = (statistics.z >> 16) & 0xFF;
      buf[10] = (statistics.z >> 8) & 0xFF;
      buf[11] = statistics.z & 0xFF;

      buf[12] = (statistics.cntReceiveData >> 24) & 0xFF;
      buf[13] = (statistics.cntReceiveData >> 16) & 0xFF;
      buf[14] = (statistics.cntReceiveData >> 8) & 0xFF;
      buf[15] = statistics.cntReceiveData & 0xFF;

      buf[16] = (statistics.cntReceiveFrames >> 24) & 0xFF;
      buf[17] = (statistics.cntReceiveFrames >> 16) & 0xFF;
      buf[18] = (statistics.cntReceiveFrames >> 8) & 0xFF;
      buf[19] = statistics.cntReceiveFrames & 0xFF;

      buf[20] = (statistics.cntTransmitData >> 24) & 0xFF;
      buf[21] = (statistics.cntTransmitData >> 16) & 0xFF;
      buf[22] = (statistics.cntTransmitData >> 8) & 0xFF;
      buf[23] = statistics.cntTransmitData & 0xFF;

      buf[24] = (statistics.cntTransmitFrames >> 24) & 0xFF;
      buf[25] = (statistics.cntTransmitFrames >> 16) & 0xFF;
      buf[26] = (statistics.cntTransmitFrames >> 8) & 0xFF;
      buf[27] = statistics.cntTransmitFrames & 0xFF;

      // Send reply with statistical information
      return vscp_binary_callback_reply(pctx, command, VSCP_ERROR_SUCCESS, buf, sizeof(buf));
    }
  }
  else if (VSCP_BINARY_COMMAND_CODE_INFO == command) {
    structVSCPStatus status;
    if (VSCP_ERROR_SUCCESS != (rv = vscp_binary_callback_stat(pctx, &stat))) {
      return vscp_binary_callback_reply(pctx, command, rv, NULL, 0);
    }
    else {
      uint8_t buf[12];
      // Fill buf with statistical information from statistics structure
      buf[0] = (status.channel_status >> 24) & 0xFF;
      buf[1] = (status.channel_status >> 16) & 0xFF;
      buf[2] = (status.channel_status >> 8) & 0xFF;
      buf[3] = status.channel_status & 0xFF;

      buf[4] = (status.lasterrorcode >> 24) & 0xFF;
      buf[5] = (status.lasterrorcode >> 16) & 0xFF;
      buf[6] = (status.lasterrorcode >> 8) & 0xFF;
      buf[7] = status.lasterrorcode & 0xFF;

      buf[8]  = (status.lasterrorsubcode >> 24) & 0xFF;
      buf[9]  = (status.lasterrorsubcode >> 16) & 0xFF;
      buf[10] = (status.lasterrorsubcode >> 8) & 0xFF;
      buf[11] = status.lasterrorsubcode & 0xFF;

      // Send reply with statistical information
      return vscp_binary_callback_reply(pctx, command, VSCP_ERROR_SUCCESS, buf, sizeof(buf));
    }
  }
  else if (VSCP_BINARY_COMMAND_CODE_GETCHID == command) {
    uint32_t chid;
    rv = vscp_binary_callback_get_channel_id(pctx, &chid);
    if (VSCP_ERROR_SUCCESS != rv) {
      return vscp_binary_callback_reply(pctx, command, rv, NULL, 0);
    }
    else {
      // Send reply with channel id
      uint8_t buf[4];
      buf[0] = (chid >> 24) & 0xFF;
      buf[1] = (chid >> 16) & 0xFF;
      buf[2] = (chid >> 8) & 0xFF;
      buf[3] = chid & 0xFF;
      return vscp_binary_callback_reply(pctx, command, rv, (char *) buf, sizeof(buf));
    }
  }
  else if (VSCP_BINARY_COMMAND_CODE_SETGUID == command) {
    uint8_t guid[16];
    if (VSCP_ERROR_SUCCESS != (rv = vscp_binary_callback_set_guid(pctx, guid))) {
      return rv;
    }
    // Send reply with GUID
    return vscp_handle_binary_reply(command, VSCP_ERROR_SUCCESS, NULL, 0, pctx);
  }
  else if (VSCP_BINARY_COMMAND_CODE_GETGUID == command) {
    uint8_t guid[16];
    if (VSCP_ERROR_SUCCESS != (rv = vscp_binary_callback_get_guid(pctx, guid))) {
      return vscp_binary_callback_reply(pctx, command, rv, NULL, 0);
    }
    // Send reply with GUID
    return vscp_handle_binary_reply(command, VSCP_ERROR_SUCCESS, guid, 16, pctx);
  }
  else if (VSCP_BINARY_COMMAND_CODE_VERSION == command) {
    uint8_t version[6];
    if (VSCP_ERROR_SUCCESS != (rv = vscp_binary_callback_get_version(pctx, version))) {
      return vscp_binary_callback_reply(pctx, command, rv, NULL, 0);
    }
    // Send reply with version
    return vscp_handle_binary_reply(command, VSCP_ERROR_SUCCESS, (char *) version, sizeof(version), pctx);
  }
  else if (VSCP_BINARY_COMMAND_CODE_SETFILTER == command) {
    vscpEventFilter filter;

    /*
      len can be 21 or 42 as it is possible to send filter AND mask in the same command
    */
    if (len < 21) {
      ESP_LOGE(TAG, "SETFILTER command argument too short len=%d", len);
      return vscp_binary_callback_reply(pctx, command, VSCP_ERROR_INVALID_ARGUMENT, NULL, 0);
    }

    // read filter part of argument
    filter.priority = parg[0];
    filter.class    = (parg[1] << 8) | parg[2];
    filter.type     = (parg[3] << 8) | parg[4];
    memcpy(filter.guid, parg + 5, 16);

    if (VSCP_ERROR_SUCCESS != (rv = vscp_ws1_callback_setfilter(&filter, pctx))) {
      ESP_LOGE(TAG, "Failed to set event filter with error %d", rv);
      return vscp_binary_callback_reply(pctx, command, rv, NULL, 0);
    }

    if (len >= 42) {
      // read mask part of argument if present (mask part is ignored by callback but can be used by client to keep track
      // of mask)
      filter.mask_priority = parg[21];
      filter.mask_class    = (parg[22] << 8) | parg[23];
      filter.mask_type     = (parg[24] << 8) | parg[25];
      memcpy(filter.mask_guid, parg + 26, 16);

      if (VSCP_ERROR_SUCCESS != (rv = vscp_ws1_callback_setmask(&filter, pctx))) {
        ESP_LOGE(TAG, "Failed to set event mask with error %d", rv);
        return vscp_binary_callback_reply(pctx, command, rv, NULL, 0);
      }
    }

    return vscp_binary_callback_reply(pctx, command, VSCP_ERROR_SUCCESS, NULL, 0);
  }
  else if (VSCP_BINARY_COMMAND_CODE_SETMASK == command) {
    vscpEventFilter filter;
    if (len < 21) {
      ESP_LOGE(TAG, "SETMASK command argument too short len=%d", len);
      return vscp_binary_callback_reply(pctx, command, VSCP_ERROR_INVALID_ARGUMENT, NULL, 0);
    }

    // read mask part of argument
    filter.mask_priority = parg[0];
    filter.mask_class    = (parg[1] << 8) | parg[2];
    filter.mask_type     = (parg[3] << 8) | parg[4];
    memcpy(filter.mask_guid, parg + 5, 16);

    if (VSCP_ERROR_SUCCESS != (rv = vscp_binary_callback_setmask(&filter, pctx))) {
      ESP_LOGE(TAG, "Failed to set event mask with error %d", rv);
      return vscp_binary_callback_reply(pctx, command, rv, NULL, 0);
    }

    return vscp_binary_callback_reply(pctx, command, VSCP_ERROR_SUCCESS, NULL, 0);
  }
  else if (VSCP_BINARY_COMMAND_CODE_INTERFACE == command) {
    /*!
      Argument = 0 - Get interface count
      Argument = 1 - Get interface information interface. (index as second argument)
      Argument = 2 - Close interface (index as second argument)
      Argument = 3 - Open interface (index as second argument)
    */

    if (len == 1 && parg[0] == 0) {
      // Get interface count
      uint16_t count;
      if (VSCP_ERROR_SUCCESS != (rv = vscp_binary_callback_get_interface_count(pctx, &count))) {
        ESP_LOGE(TAG, "Failed to get interface count with error %d", rv);
        return vscp_binary_callback_reply(pctx, command, rv, NULL, 0);
      }
      // Send reply with count
      uint8_t buf[2];
      buf[0] = (count >> 8) & 0xFF;
      buf[1] = count & 0xFF;
      return vscp_binary_callback_reply(pctx, command, VSCP_ERROR_SUCCESS, (char *) buf, sizeof(buf));
    }
    else if (len >= 3 && parg[0] == 1) {
      // Get interface information
      vscp_interface_info interface_info;

      // Interface index
      uint16_t idx = (parg[1] << 8) | parg[2];

      if (VSCP_ERROR_SUCCESS != (rv = vscp_binary_callback_get_interface_info(pctx, idx, &interface_info))) {
        ESP_LOGE(TAG, "Failed to get information for interface %d with error %d", idx, rv);
        return vscp_binary_callback_reply(pctx, command, rv, NULL, 0);
      }

      uint8_t buf[2 + 2 + 16 + 64] = { 0 };
      buf[0]                       = (interface_info.index >> 8) & 0xFF;
      buf[1]                       = interface_info.index & 0xFF;
      buf[2]                       = (interface_info.index >> 8) & 0xFF;
      buf[3]                       = interface_info.index & 0xFF;
      memcpy(buf + 4, interface_info.guid, 16);
      strncpy((char *) buf + 20, interface_info.description,
              63); // Interface description
      return vscp_binary_callback_reply(pctx, command, VSCP_ERROR_SUCCESS, (char *) buf, sizeof(buf));
    }
    else if (len >= 3 && parg[0] == 2) {
      // Close interface

      // Interface index
      uint16_t idx = (parg[1] << 8) | parg[2];

      if (VSCP_ERROR_SUCCESS != (rv = vscp_binary_callback_close_interface(pctx, idx))) {
        ESP_LOGE(TAG, "Failed to close interface %d with error %d", idx, rv);
        return vscp_binary_callback_reply(pctx, command, rv, NULL, 0);
      }
      // Send reply confirming interface was closed
      return vscp_binary_callback_reply(pctx, command, VSCP_ERROR_SUCCESS, NULL, 0);
    }
    else if (len >= 3 && parg[0] == 3) {
      // Open interface

      // Interface index
      uint16_t idx = (parg[1] << 8) | parg[2];

      if (VSCP_ERROR_SUCCESS != (rv = vscp_binary_callback_open_interface(pctx, idx))) {
        ESP_LOGE(TAG, "Failed to open interface %d with error %d", idx, rv);
        return vscp_binary_callback_reply(pctx, command, rv, NULL, 0);
      }
      // Send reply confirming interface was opened    return vscp_binary_callback_reply(pctx, command,
      // VSCP_ERROR_SUCCESS, NULL, 0);
      return vscp_binary_callback_reply(pctx, command, VSCP_ERROR_SUCCESS, NULL, 0);
    }

    ESP_LOGE(TAG, "INTERFACE command argument invalid len=%d", len);
    return vscp_binary_callback_reply(pctx, command, VSCP_ERROR_INVALID_ARGUMENT, NULL, 0);
  }
  else if (VSCP_BINARY_COMMAND_CODE_TEST == command) {
    return vscp_binary_callback_test(pctx, parg, len);
  }
  else if (VSCP_BINARY_COMMAND_CODE_WCYD == command) {
    uint64_t capabilities = 0;  
    if (VSCP_ERROR_SUCCESS != vscp_binary_callback_what_can_you_do(pctx, &capabilities)) {
      ESP_LOGE(TAG, "Failed to get capabilities");
      return vscp_binary_callback_reply(pctx, command, VSCP_ERROR_UNKNOWN, NULL, 0);
    }
    // Send reply with capabilities
    uint8_t buf[8];
    for (int i = 0; i < 8; i++) {
      buf[i] = (capabilities >> (56 - i * 8)) & 0xFF;
    }
    return vscp_binary_callback_reply(pctx, command, VSCP_ERROR_SUCCESS, (char *)buf, sizeof(buf));
  }
  else if (VSCP_BINARY_COMMAND_CODE_SHUTDOWN == command) {
    return vscp_binary_callback_shutdown(pctx);
  }
  else if (VSCP_BINARY_COMMAND_CODE_RESTART == command) {
    return vscp_binary_callback_restart(pctx);
  }
  else if (command >= VSCP_BINARY_COMMAND_CODE_USER_START) {
    // User defined command, pass to callback
    return vscp_binary_callback_user_command(pctx, command, parg, len);
  }
  else {
    // Unknown command
    ESP_LOGE(TAG, "Unknown binary command code: %04X", command);
    return VSCP_ERROR_UNKNOWN_COMMAND;
  }

  return VSCP_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// vscp_handle_binary_event
//

int
vscp_handle_binary_event(vscpEvent *pEvent, const void *pctx)
{
  return VSCP_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// vscp_handle_binary_reply
//

int
vscp_handle_binary_reply(uint16_t command, uint16_t error, const char *preplyarg, const void *pctx)
{
  return VSCP_ERROR_SUCCESS;
}