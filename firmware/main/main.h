/*
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
*/

#ifndef __VSCP_WCANG_H__
#define __VSCP_WCANG_H__

#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <freertos/queue.h>

#include "vscp.h"
#include "can4vscp.h"

#define CONNECTED_LED_GPIO_NUM		0
#define ACTIVE_LED_GPIO_NUM			  1
#define GPIO_OUTPUT_PIN_SEL       ((1ULL<<CONNECTED_LED_GPIO_NUM) | (1ULL<<ACTIVE_LED_GPIO_NUM) )

#define DEV_BUFFER_LENGTH	        64

typedef enum
{	
  CH_LINK = 0,    // tcp/ip link protocol
  CH_CAN,         // CAN
  CH_WS,          // websocket I & II
  CH_UDP,         // UDP 
  CH_MULTI,       // Multicast
  CH_MQTT,        // MQTT
	CH_BLE,         // BLE
	CH_UART         // UART  
} dev_channel_t;

// All transports use this structure for state 

typedef struct {
  union {
    struct {
      uint32_t active: 1;     /**< Transport active if set to one */
      uint32_t open: 1;       /**< Transport open if set to one */
      uint32_t reserved: 30;  /**< Reserved bits */
    };
    uint32_t flags;             /**< Don't use */ 
  };
  QueueHandle_t msg_queue;      /**< Message queue for transport */
  uint32_t overruns;            /**< Queue overrun counter */

} transport_t;



/*!
  Default values stored in non volatile memory
  on start up.
*/

#define DEFAULT_GUID              ""      // Empty constructs from MAC, "-" all nills, "xx:yy:..." set GUID

// BLE
#define DEFAULT_BLE_ENABLE        true
#define DEFAULT_ADVERTISE_ENABLE  true

// Web server
#define DEFAULT_WEB_ENABLE        true
#define DEFAULT_WEB_PORT          80

// MQTT
#define DEAFULT_MQTT_ENABLE       true   // Enabled

// tcp/ip interface
#define DEFAULT_TCPIP_ENABLE      true   // Enabled
#define DEFAULT_TCPIPPORT         9598
#define DEFAULT_TCPIP_USER        "vscp"
#define DEFAULT_TCPIP_PASSWORD    "secret"
#define DEFAULT_TCPIP_VER         4       // Ipv6 = 6 or Ipv4 = 4
#define TCPSRV_WELCOME_MSG        "Welcome to the Wireless CAN4VSCP Gateway\r\n"                    \
                                  "Copyright (C) 2000-2022 Grodans Paradis AB\r\n"                  \
                                  "https://www.grodansparadis.com\r\n"                              \
                                  "+OK\r\n"

// UDP interface
#define DEFAULT_UDP_ENABLE        true   // Enabled
#define DEFAULT_UDP_RX_ENABLE     true   // Enable UDP server
#define DEFAULT_UDP_TX_ENABLE     true   // Enable UDP client

// Multicast
#define DEFAULT_MULTICAST_ENABLE  false   // Disable

// MQTT broker
#define DEFAULT_MQTT_ENABLE       true
#define DEFAULT_MQTT_ADDRESS      "192.168.1.7"
#define DEFAULT_MQTT_PORT         1883
#define DEFAULT_MQTT_USER         "vscp"
#define DEFAULT_MQTT_PASSWORD     "secret"
#define DEFAULT_TOPIC_SUBSCRIBE   "VSCP"
#define DEFAULT_TOPIC_PUBLISH     "VSCP/PUB"


// TWAI
#define DEFAULT_TWAI_MODE         0   // CAN4VSCP_NORMAL
#define DEFAULT_TWAI_SPEED        CAN4VSCP_125K

// SMTP
#define DEFAULT_SMTP_ENABLE       false

/**
 * @brief Read preocessor on chip temperature
 * @return Temperature as floating point value
 */
float read_onboard_temperature(void);


/**
 * @fn getMilliSeconds
 * @brief Get system time in Milliseconds 
 * 
 * @return Systemtime in milliseconds
 */
uint32_t getMilliSeconds(void);

/**
 * @fn validate_user
 * @brief Validate user
 * 
 * @param user Username to check
 * @param password Password to check
 * @return True if user is valid, False if not.
 */
bool
validate_user(const char *user, const char *password);

#endif