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

/*!
  Modifications done for the VSCP can gw project by
  Ake Hedman, Grodans Paradis AB 2022
  Part of the VSCP project (https://www.vcsp.org)
*/

#include "driver/gpio.h"
#include "driver/twai.h"

#include "esp_event.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "nvs_flash.h"
#include <string.h>

#include "lwip/sockets.h"
#include "main.h"
#include "can4vscp.h"

static EventGroupHandle_t s_can4vscp_event_group;
#define CAN4VSCP_ENABLE_BIT     BIT0

extern SemaphoreHandle_t ctrl_task_sem;
extern QueueHandle_t xmsg_Rx_Queue; 

#define TAG __func__
enum bus_state { OFF_BUS, ON_BUS };
static const twai_timing_config_t can4vscp_timing_config[] = {
  { .brp = 800, .tseg_1 = 15, .tseg_2 = 4, .sjw = 3, .triple_sampling = false },
  { .brp = 400, .tseg_1 = 15, .tseg_2 = 4, .sjw = 3, .triple_sampling = false },
  { .brp = 200, .tseg_1 = 15, .tseg_2 = 4, .sjw = 3, .triple_sampling = false },
  { .brp = 128, .tseg_1 = 16, .tseg_2 = 8, .sjw = 3, .triple_sampling = false },
  { .brp = 80, .tseg_1 = 15, .tseg_2 = 4, .sjw = 3, .triple_sampling = false },
  { .brp = 40, .tseg_1 = 15, .tseg_2 = 4, .sjw = 3, .triple_sampling = false },
  { .brp = 32, .tseg_1 = 15, .tseg_2 = 4, .sjw = 3, .triple_sampling = false },
  { .brp = 16, .tseg_1 = 15, .tseg_2 = 4, .sjw = 3, .triple_sampling = false },
  { .brp = 8, .tseg_1 = 15, .tseg_2 = 4, .sjw = 3, .triple_sampling = false },
  { .brp = 4, .tseg_1 = 16, .tseg_2 = 8, .sjw = 3, .triple_sampling = false },
  { .brp = 4, .tseg_1 = 15, .tseg_2 = 4, .sjw = 3, .triple_sampling = false }
};

// static EventGroupHandle_t s_twai_event_group;
//
static TimerHandle_t xCAN4VSCP_EN_Timer;
static uint8_t datarate = CAN4VSCP_125K;
static can4vscp_cfg_t can4vscp_cfg;

#define TWAI_CONFIG(tx_io_num, rx_io_num, op_mode)                                                                     \
  {                                                                                                                    \
    .mode = op_mode, .tx_io = tx_io_num, .rx_io = rx_io_num, .clkout_io = TWAI_IO_UNUSED,                              \
    .bus_off_io = TWAI_IO_UNUSED, .tx_queue_len = 100, .rx_queue_len = 100, .alerts_enabled = TWAI_ALERT_NONE,         \
    .clkout_divider = 0, .intr_flags = ESP_INTR_FLAG_LEVEL1                                                            \
  }

static const twai_general_config_t g_config_normal =
  TWAI_GENERAL_CONFIG_DEFAULT(CAN4VSCP_TX_GPIO_NUM, CAN4VSCP_RX_GPIO_NUM, TWAI_MODE_NORMAL);

static const twai_general_config_t g_config_silent =
  TWAI_GENERAL_CONFIG_DEFAULT(CAN4VSCP_TX_GPIO_NUM, CAN4VSCP_RX_GPIO_NUM, TWAI_MODE_LISTEN_ONLY);

static twai_filter_config_t f_config = TWAI_FILTER_CONFIG_ACCEPT_ALL();

///////////////////////////////////////////////////////////////////////////////
// can4vscp_block
//
// block tx/rx
//

void
can4vscp_block(void)
{
  // Not enabled
  xEventGroupClearBits(s_can4vscp_event_group, CAN4VSCP_ENABLE_BIT);

  // Turn of timer
  if (xTimerIsTimerActive(xCAN4VSCP_EN_Timer) != pdFALSE) {
    xTimerReset(xCAN4VSCP_EN_Timer, 0);
    xTimerStop(xCAN4VSCP_EN_Timer, 0);
  }

  vTaskDelay(pdMS_TO_TICKS(1)); // wait for rx to finish
}

///////////////////////////////////////////////////////////////////////////////
// can4vscp_unblock
//
// unblock tx/rx
//

void
can4vscp_unblock(void)
{
  if (ON_BUS == can4vscp_cfg.bus_state) {
    return;
  }

  if (xTimerIsTimerActive(xCAN4VSCP_EN_Timer) == pdFALSE) {
    xTimerStart(xCAN4VSCP_EN_Timer, 0);
  }
  else {
    xTimerReset(xCAN4VSCP_EN_Timer, 0);
  }
}

///////////////////////////////////////////////////////////////////////////////
// can4vscp_enable
//

void
can4vscp_enable(void)
{
  if (ON_BUS == can4vscp_cfg.bus_state) {
    return;
  }

  twai_timing_config_t *t_config;
  t_config = (twai_timing_config_t *) &can4vscp_timing_config[datarate];
  f_config.acceptance_code = 0;
  f_config.acceptance_mask = 0xFFFFFFFF;

  //	f_config.acceptance_code = can4vscp_cfg.filter;
  //	f_config.acceptance_mask = can4vscp_cfg.mask;
  f_config.single_filter = 1;

  if (can4vscp_cfg.silent) {
    ESP_ERROR_CHECK(twai_driver_install(&g_config_silent, (const twai_timing_config_t *) t_config, &f_config));
  }
  else {
    ESP_ERROR_CHECK(twai_driver_install(&g_config_normal, (const twai_timing_config_t *) t_config, &f_config));
  }

  ESP_ERROR_CHECK(twai_start());
  twai_clear_receive_queue();
  can4vscp_unblock();
  can4vscp_cfg.bus_state = ON_BUS;
}

///////////////////////////////////////////////////////////////////////////////
// can4vscp_disable
//

void
can4vscp_disable(void)
{
  // Do nothing if already off
  if (OFF_BUS == can4vscp_cfg.bus_state) {
    return;
  }

  can4vscp_block();
  ESP_ERROR_CHECK(twai_stop());
  ESP_ERROR_CHECK(twai_driver_uninstall());
  can4vscp_cfg.bus_state = OFF_BUS;
}

///////////////////////////////////////////////////////////////////////////////
// can4vscp_setSilent
//

void
can4vscp_setSilent(uint8_t flag)
{
  // Do nothing if active
  if (ON_BUS == can4vscp_cfg.bus_state) {
    return;
  }

  can4vscp_cfg.silent = flag;
}

///////////////////////////////////////////////////////////////////////////////
// can4vscp_isSilent
//

uint8_t
can4vscp_isSilent(void)
{
  return can4vscp_cfg.silent;
}


///////////////////////////////////////////////////////////////////////////////
// can4vscp_setLoopback
//

void
can4vscp_setLoopback(uint8_t flag)
{
  // Do nothing if active
  if (ON_BUS == can4vscp_cfg.bus_state) {
    return;
  }

  can4vscp_cfg.loopback = flag;
}

///////////////////////////////////////////////////////////////////////////////
// can4vscp_isLoopback
//

uint8_t
can4vscp_isLoopback(void)
{
  return can4vscp_cfg.loopback;
}

///////////////////////////////////////////////////////////////////////////////
// can4vscp_setFilter

void
can4vscp_setFilter(uint32_t filter)
{
  // Do nothing if active
  if (ON_BUS == can4vscp_cfg.bus_state) {
    return;
  }

  can4vscp_cfg.filter = filter;
}

///////////////////////////////////////////////////////////////////////////////
// can4vscp_setMask

void
can4vscp_setMask(uint32_t mask)
{
  // Do nothing if active
  if (ON_BUS == can4vscp_cfg.bus_state) {
    return;
  }

  can4vscp_cfg.mask = mask;
}

///////////////////////////////////////////////////////////////////////////////
// can4vscp_setBitrate
//

void
can4vscp_setBitrate(uint8_t rate)
{
  // Should be off bus
  if (ON_BUS == can4vscp_cfg.bus_state) {
    return;
  }

  datarate = rate;
}

///////////////////////////////////////////////////////////////////////////////
// can4vscp_getBitrate
//

uint8_t
can4vscp_getBitrate(void)
{
  return datarate;
}

///////////////////////////////////////////////////////////////////////////////
// CAN4VSCP_Timer_Callback
//

static void
CAN4VSCP_Timer_Callback(TimerHandle_t xTimer)
{
  xEventGroupSetBits(s_can4vscp_event_group, CAN4VSCP_ENABLE_BIT);
  //ESP_LOGI(TAG, "CAN4VSCP Timer Callback");
}

///////////////////////////////////////////////////////////////////////////////
// can4vscp_init
//

void
can4vscp_init(uint8_t bitrate)
{
  s_can4vscp_event_group = xEventGroupCreate();
  xCAN4VSCP_EN_Timer     = xTimerCreate(
    // Just a text name, not used by the RTOS kernel. 
    "TwaiTimer",
    // The timer period in ticks, must be greater than 0. 
    pdMS_TO_TICKS(1000),
    // The timer will auto-reload when it expire. 
    pdTRUE,
    // The ID is used to store a count of the number of times the timer
    // has expired, which is initialised to 0. 
    (void *) 0,
    // Each timer calls the same callback when it expires. 
    CAN4VSCP_Timer_Callback);

  if (xTimerIsTimerActive(xCAN4VSCP_EN_Timer) != pdFALSE) {
    xTimerStop(xCAN4VSCP_EN_Timer, 0);
  }

}

///////////////////////////////////////////////////////////////////////////////
// can4vscp_isEnabled
//

bool
can4vscp_isEnabled(void)
{
  if (ON_BUS == can4vscp_cfg.bus_state) {
    return true;
  }
  else {
    return false;
  }
}

///////////////////////////////////////////////////////////////////////////////
// can4vscp_msgs_to_rx
//

uint32_t
can4vscp_msgs_to_rx(void)
{
  twai_status_info_t status_info;
  twai_get_status_info(&status_info);
  return status_info.msgs_to_rx;
}

///////////////////////////////////////////////////////////////////////////////
// twai_receive_task
//

void twai_receive_task(void *arg)
{
  esp_err_t rv;
  transport_t *ptrport_twai_rx = (transport_t *)arg;
  
  while (1) {
    
    twai_message_t rxmsg = {};

    if (ESP_OK == (rv = twai_receive(&rxmsg, portMAX_DELAY))) {
      ESP_LOGI(TAG, "TWAI msg received id= %lu", rxmsg.identifier);
      // Must be extended msg to be VSCP event
      if (rxmsg.extd) {
        ESP_LOGI(TAG, "VSCP Event received");
        if( (rv = xQueueSendToBack( ptrport_twai_rx->msg_queue,
                                    (void *)&rxmsg,
                                    (TickType_t)10)) != pdPASS) {
          ESP_LOGI(TAG, "Buffer full: Failed to save message");
        }
        xSemaphoreTake(ctrl_task_sem, portMAX_DELAY);
        // Tell the controller that there is a received event
        xSemaphoreGive(ctrl_task_sem);
      }
    }
  }

} // while