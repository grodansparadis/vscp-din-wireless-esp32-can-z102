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
#include <vscp-firmware-helper.h>
#include "vscp-binary.h"




///////////////////////////////////////////////////////////////////////////////
// vscp_binary_callback_reply
//

int
vscp_binary_callback_reply(const void *pdata, uint16_t command, uint16_t error, const uint8_t *parg, size_t len)
{
  return VSCP_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// vscp_binary_callback_challenge
//

int
vscp_binary_callback_challenge(const void *pdata)
{
  return VSCP_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// vscp_binary_callback_get_chid
//

int
vscp_binary_callback_get_chid(const void *pdata, uint32_t *pchid)
{
  return VSCP_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// vscp_binary_callback_set_guid
//

int
vscp_binary_callback_set_guid(const void *pdata, uint8_t *pguid)
{
  return VSCP_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// vscp_binary_callback_get_guid
//

int
vscp_binary_callback_get_guid(const void *pdata, uint8_t *pguid)
{
  return VSCP_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// vscp_binary_callback_setfilter
//

int
vscp_binary_callback_setfilter(const void *pdata, const vscpEventFilter *pfilter)
{
  return VSCP_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// vscp_binary_callback_setmask
//

int
vscp_binary_callback_setmask(const void *pdata, const vscpEventFilter *pfilter)
{
  return VSCP_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// vscp_binary_callback_get_version
//

int
vscp_binary_callback_get_version(const void *pdata, uint8_t *pversion)
{
  return VSCP_ERROR_SUCCESS;
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
  return VSCP_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// vscp_binary_callback_close
//

int
vscp_binary_callback_close(const void *pdata)
{
  return VSCP_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// vscp_binary_callback_user
//

int
vscp_binary_callback_user(const void *pdata, const char *user)
{
  return VSCP_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// vscp_binary_callback_password
//

int
vscp_binary_callback_password(const void *pdata, const char *password)
{
  return VSCP_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// vscp_binary_callback_check_authenticated
//

int
vscp_binary_callback_check_authenticated(const void *pdata)
{
  return VSCP_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// vscp_binary_callback_check_authenticated
//

int
vscp_binary_callback_check_privilege(const void *pdata, uint8_t priv)
{
  return VSCP_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// vscp_binary_callback_test
//

int
vscp_binary_callback_test(const void *pdata, const uint8_t *arg, size_t len)
{
  return VSCP_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// vscp_binary_callback_wcyd
//

int
vscp_binary_callback_wcyd(const void *pdata, uint64_t *pwcyd)
{
  return VSCP_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// vscp_binary_callback_check_data
//

int
vscp_binary_callback_check_data(const void *pdata, uint32_t *pcount)
{
  return VSCP_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// vscp_binary_callback_clrall
//

int
vscp_binary_callback_clrall(const void *pdata)
{
  return VSCP_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// vscp_binary_callback_send_event
//

int
vscp_binary_callback_send_event(const void *pdata, const vscpEvent *pev)
{
  return VSCP_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// vscp_binary_callback_send_eventex
//

int
vscp_binary_callback_send_eventex(const void *pdata, const vscpEventEx *pex)
{
  return VSCP_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// vscp_binary_callback_get_event
//

int
vscp_binary_callback_get_event(const void *pdata, vscpEvent *pev)
{
  return VSCP_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// vscp_binary_callback_get_eventex
//

int
vscp_binary_callback_get_eventex(const void *pdata, vscpEventEx *pex)
{
  return VSCP_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// vscp_binary_callback_send_asyncevent
//

int
vscp_binary_callback_send_asyncevent(const void *pdata, vscpEvent *pev)
{
  return VSCP_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// vscp_binary_callback_quit
//

int
vscp_binary_callback_quit(const void *pdata)
{
  return VSCP_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// vscp_binary_callback_write_client
//

int
vscp_binary_callback_write_client(const void *pdata, const char *msg)
{
  return VSCP_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// vscp_binary_callback_get_interface_count
//

int
vscp_binary_callback_get_interface_count(const void *pdata, uint16_t *pcount)
{
  return VSCP_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// vscp_binary_callback_get_interface
//

int
vscp_binary_callback_get_interface(const void *pdata, uint16_t idx, vscp_interface_info_t *pifinfo)
{
  return VSCP_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// vscp_binary_callback_interface_open
//

int
vscp_binary_callback_interface_open(const void *pdata, uint16_t idx)
{
  return VSCP_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// vscp_binary_callback_interface_close
//

int
vscp_binary_callback_interface_close(const void *pdata, uint16_t idx)
{
  return VSCP_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// vscp_binary_callback_event_received
//

int
vscp_binary_callback_event_received(const void *pdata, const vscpEvent *pev)
{
  return VSCP_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// vscp_binary_callback_disconnect_client
//

int
vscp_binary_callback_disconnect_client(const void *pdata)
{
  return VSCP_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// vscp_binary_callback_disconnect_client
//

int
vscp_binary_callback_statistics(const void *pdata, VSCPStatistics *pStatistics)
{
  return VSCP_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// vscp_binary_callback_info
//

int
vscp_binary_callback_info(const void *pdata, VSCPStatus *pstatus)
{
  return VSCP_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// int vscp_binary_callback_user_command(const void *pdata, uint16_t command, const uint8_t *parg, size_t len)

//

int
vscp_binary_callback_user_command(const void *pdata, uint16_t command, const uint8_t *parg, size_t len)
{
  return VSCP_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// vscp_binary_callback_restart
//

int
vscp_binary_callback_restart(const void *pdata)
{
  return VSCP_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// vscp_binary_callback_shutdown
//

int
vscp_binary_callback_shutdown(const void *pdata)
{
  return VSCP_ERROR_SUCCESS;
}