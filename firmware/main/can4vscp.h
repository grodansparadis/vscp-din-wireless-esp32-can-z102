/*
 * This file is part of the WiCAN project.
 *
 * Copyright (C) 2022  Meatpi Electronics.
 * Written by Ali Slim <ali@meatpi.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */


#ifndef __CAN4VSCP_H__
#define __CAN4VSCP_H__

#include "driver/twai.h"

#define CAN4VSCP_TX_GPIO_NUM      9
#define CAN4VSCP_RX_GPIO_NUM      3

#define CAN4VSCP_5K				        0
#define CAN4VSCP_10K				      1
#define CAN4VSCP_20K				      2
#define CAN4VSCP_25K				      3
#define CAN4VSCP_50K				      4
#define CAN4VSCP_100K			        5
#define CAN4VSCP_125K			        6
#define CAN4VSCP_250K			        7
#define CAN4VSCP_500K			        8
#define CAN4VSCP_800K			        9
#define CAN4VSCP_1000K			     10
#define CAN4VSCP_AUTO			       11


typedef struct {
	uint8_t bus_state;
	uint8_t silent;
	uint8_t loopback;
	uint16_t brp;
	uint8_t phase_seg1;
	uint8_t phase_seg2;
	uint8_t sjw;
	uint32_t filter;
	uint32_t mask;
} can4vscp_cfg_t;


/*!
  Block transmission/reception
*/
void
can4vscp_block(void);

/*!
  Unblock transmission/reception
*/
void
can4vscp_unblock(void);

/*!
  Enable TWAI
  Filtering is set so all TWAI messages are received.
*/
void can4vscp_enable(void);

/*!
  Disable TWAI  
*/
void can4vscp_disable(void);

/*!
  Handle silent mode
  I/f must be disabled to set/reset silent mode
  @param flag Set to 1 for silent, 0 for active.
*/
void can4vscp_setSilent(uint8_t flag);

/*!
  Check if CAN i/f is silent
  @return true if enabled
*/
uint8_t can4vscp_isSilent(void);

/*!
  Handle loopback mode
  I/f must be disabled to set/reset silent mode
  @param flag Set to 1 for loopback, 0 for normal mode.
*/
void can4vscp_setLoopback(uint8_t flag);

/*!
  Check if CAN i/f is in loopback mode
  @return true if enabled
*/
uint8_t can4vscp_isLoopback(void);

/*!
  Set filter
  I/f must be disabled to set filter.
  @param filter 32-bit filter value to set
*/
void can4vscp_setFilter(uint32_t filter);

/*!
  Set mask
  I/f must be disabled to set mask.
  @param mask 32-bit mask value to set
*/
void can4vscp_setMask(uint32_t mask);

/*!
  Set bitrate for TWAI bus
  I/f must be disabled to set bitrate.
  @param rate Code for bitrate
*/
void can4vscp_setBitrate(uint8_t rate);

/*!
  Get bitrate for TWAI bus
  @return Code for set bitrate
*/
uint8_t can4vscp_getBitrate(void);

/*!
  Initialize the TWAI interface
  @param bitrate to use
*/
void can4vscp_init(uint8_t bitrate);

/*!
  Receive TWAI message w/ auto bauderate
  @param message Pointer to message that will get receive data
  @param ticks_to_wait Timeout 
  @return ESP_OK if all is OK else error code.
*/
esp_err_t can4vscp_receive(twai_message_t *message, TickType_t ticks_to_wait);

/*!
  Send TWAI message
  @param message Pointer to message that will be sent
  @param ticks_to_wait Timeout 
  @return ESP_OK if all is OK else error code.
*/
esp_err_t can4vscp_send(twai_message_t *message, TickType_t ticks_to_wait);

/*!
  Check if CAN is enabled
  @return true if enabled
*/
bool can4vscp_isEnabled(void);

/*!
  Get Bitrate
  @return Code for set bitrate
*/
uint8_t can4vscp_get_bitrate(void);

/*!

*/
uint32_t can4vscp_msgs_to_rx(void);

// ----------------------------------------------------------------------------
//                                     Tasks
// ----------------------------------------------------------------------------

/*!
  Task that handle receive of messages and fills the 
  rx buffer. The message broker task is informed about
  the received message so it is sent to all other tasks
  @param arg CAN4VSCP context
*/
void twai_receive_task(void *arg);

/*!
  Task that handle trasmit of messages from the
  CAN4VSCP tx buffer.
  @param arg CAN4VSCP context
*/
void twai_transmit_task(void *arg);

#endif