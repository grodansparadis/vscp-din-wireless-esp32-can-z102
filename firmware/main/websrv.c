/*
  VSCP Wireless CAN4VSCP Gateway (VSCP-WCANG)

  This file is part of the VSCP (https://www.vscp.org)

  The MIT License (MIT)
  Copyright © 2022-2025 Ake Hedman, the VSCP project <info@vscp.org>

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

#include <esp_log.h>
#include <esp_event_base.h>
#include <esp_tls_crypto.h>
#include <esp_http_server.h>

#include "websrv.h"

#define TAG __func__

//-----------------------------------------------------------------------------
//                               Start Basic Auth
//-----------------------------------------------------------------------------

///////////////////////////////////////////////////////////////////////////////
// http_auth_basic
//

static char *
http_auth_basic(const char *username, const char *password)
{
  int out;
  char *user_info = NULL;
  char *digest    = NULL;
  size_t n        = 0;
  asprintf(&user_info, "%s:%s", username, password);
  if (!user_info) {
    ESP_LOGE(TAG, "No enough memory for user information");
    return NULL;
  }
  esp_crypto_base64_encode(NULL, 0, &n, (const unsigned char *) user_info, strlen(user_info));

  /* 6: The length of the "Basic " string
   * n: Number of bytes for a base64 encode format
   * 1: Number of bytes for a reserved which be used to fill zero
   */
  digest = calloc(1, 6 + n + 1);
  if (digest) {
    strcpy(digest, "Basic ");
    esp_crypto_base64_encode((unsigned char *) digest + 6,
                             n,
                             (size_t *) &out,
                             (const unsigned char *) user_info,
                             strlen(user_info));
  }
  free(user_info);
  return digest;
}

///////////////////////////////////////////////////////////////////////////////
// basic_auth_get_handler
//
// An HTTP GET handler
//

static esp_err_t
basic_auth_get_handler(httpd_req_t *req)
{
  char *buf                          = NULL;
  size_t buf_len                     = 0;
  basic_auth_info_t *basic_auth_info = req->user_ctx;

  buf_len = httpd_req_get_hdr_value_len(req, "Authorization") + 1;
  if (buf_len > 1) {
    buf = calloc(1, buf_len);
    if (!buf) {
      ESP_LOGE(TAG, "No enough memory for basic authorization");
      return ESP_ERR_NO_MEM;
    }

    if (httpd_req_get_hdr_value_str(req, "Authorization", buf, buf_len) == ESP_OK) {
      ESP_LOGI(TAG, "Found header => Authorization: %s", buf);
    }
    else {
      ESP_LOGE(TAG, "No auth value received");
    }

    char *auth_credentials = http_auth_basic(basic_auth_info->username, basic_auth_info->password);
    if (!auth_credentials) {
      ESP_LOGE(TAG, "No enough memory for basic authorization credentials");
      free(buf);
      return ESP_ERR_NO_MEM;
    }

    if (strncmp(auth_credentials, buf, buf_len)) {
      ESP_LOGE(TAG, "Not authenticated");
      httpd_resp_set_status(req, HTTPD_401);
      httpd_resp_set_type(req, "application/json");
      httpd_resp_set_hdr(req, "Connection", "keep-alive");
      httpd_resp_set_hdr(req, "WWW-Authenticate", "Basic realm=\"Hello\"");
      httpd_resp_send(req, NULL, 0);
    }
    else {
      ESP_LOGI(TAG, "Authenticated!");
      char *basic_auth_resp = NULL;
      httpd_resp_set_status(req, HTTPD_200);
      httpd_resp_set_type(req, "application/json");
      httpd_resp_set_hdr(req, "Connection", "keep-alive");
      asprintf(&basic_auth_resp, "{\"authenticated\": true,\"user\": \"%s\"}", basic_auth_info->username);
      if (!basic_auth_resp) {
        ESP_LOGE(TAG, "No enough memory for basic authorization response");
        free(auth_credentials);
        free(buf);
        return ESP_ERR_NO_MEM;
      }
      httpd_resp_send(req, basic_auth_resp, strlen(basic_auth_resp));
      free(basic_auth_resp);
    }
    free(auth_credentials);
    free(buf);
  }
  else {
    ESP_LOGE(TAG, "No auth header received");
    httpd_resp_set_status(req, HTTPD_401);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "keep-alive");
    httpd_resp_set_hdr(req, "WWW-Authenticate", "Basic realm=\"Hello\"");
    httpd_resp_send(req, NULL, 0);
  }

  return ESP_OK;
}

static httpd_uri_t basic_auth = {
  .uri     = "/basic_auth",
  .method  = HTTP_GET,
  .handler = basic_auth_get_handler,
};

///////////////////////////////////////////////////////////////////////////////
// httpd_register_basic_auth
//

static void
httpd_register_basic_auth(httpd_handle_t server)
{
  basic_auth_info_t *basic_auth_info = calloc(1, sizeof(basic_auth_info_t));
  if (basic_auth_info) {
    basic_auth_info->username = CONFIG_EXAMPLE_BASIC_AUTH_USERNAME;
    basic_auth_info->password = CONFIG_EXAMPLE_BASIC_AUTH_PASSWORD;

    basic_auth.user_ctx = basic_auth_info;
    httpd_register_uri_handler(server, &basic_auth);
  }
}



//-----------------------------------------------------------------------------
//                               End Basic Auth
//-----------------------------------------------------------------------------



///////////////////////////////////////////////////////////////////////////////
// hello_get_handler
//
// An HTTP GET handler
//

static esp_err_t
hello_get_handler(httpd_req_t *req)
{
  char *buf;
  size_t buf_len;

  // Get header value string length and allocate memory for length + 1,
  // extra byte for null termination 
  buf_len = httpd_req_get_hdr_value_len(req, "Host") + 1;
  if (buf_len > 1) {
    buf = malloc(buf_len);
    // Copy null terminated value string into buffer 
    if (httpd_req_get_hdr_value_str(req, "Host", buf, buf_len) == ESP_OK) {
      ESP_LOGI(TAG, "Found header => Host: %s", buf);
    }
    free(buf);
  }

  buf_len = httpd_req_get_hdr_value_len(req, "Test-Header-2") + 1;
  if (buf_len > 1) {
    buf = malloc(buf_len);
    if (httpd_req_get_hdr_value_str(req, "Test-Header-2", buf, buf_len) == ESP_OK) {
      ESP_LOGI(TAG, "Found header => Test-Header-2: %s", buf);
    }
    free(buf);
  }

  buf_len = httpd_req_get_hdr_value_len(req, "Test-Header-1") + 1;
  if (buf_len > 1) {
    buf = malloc(buf_len);
    if (httpd_req_get_hdr_value_str(req, "Test-Header-1", buf, buf_len) == ESP_OK) {
      ESP_LOGI(TAG, "Found header => Test-Header-1: %s", buf);
    }
    free(buf);
  }

  // Read URL query string length and allocate memory for length + 1,
  // extra byte for null termination 
  buf_len = httpd_req_get_url_query_len(req) + 1;
  if (buf_len > 1) {
    buf = malloc(buf_len);
    if (httpd_req_get_url_query_str(req, buf, buf_len) == ESP_OK) {
      ESP_LOGI(TAG, "Found URL query => %s", buf);
      char param[32];
      // Get value of expected key from query string 
      if (httpd_query_key_value(buf, "query1", param, sizeof(param)) == ESP_OK) {
        ESP_LOGI(TAG, "Found URL query parameter => query1=%s", param);
      }
      if (httpd_query_key_value(buf, "query3", param, sizeof(param)) == ESP_OK) {
        ESP_LOGI(TAG, "Found URL query parameter => query3=%s", param);
      }
      if (httpd_query_key_value(buf, "query2", param, sizeof(param)) == ESP_OK) {
        ESP_LOGI(TAG, "Found URL query parameter => query2=%s", param);
      }
    }
    free(buf);
  }

  // Set some custom headers 
  httpd_resp_set_hdr(req, "Custom-Header-1", "Custom-Value-1");
  httpd_resp_set_hdr(req, "Custom-Header-2", "Custom-Value-2");

  // Send response with custom headers and body set as the
  // string passed in user context
  const char *resp_str = (const char *) req->user_ctx;
  httpd_resp_send(req, resp_str, HTTPD_RESP_USE_STRLEN);

  // After sending the HTTP response the old HTTP request
  // headers are lost. Check if HTTP request headers can be read now. 
  if (httpd_req_get_hdr_value_len(req, "Host") == 0) {
    ESP_LOGI(TAG, "Request headers lost");
  }
  return ESP_OK;
}

static const httpd_uri_t hello = { .uri     = "/hello",
                                   .method  = HTTP_GET,
                                   .handler = hello_get_handler,
                                   // Let's pass response string in user
                                   // context to demonstrate it's usage 
                                   .user_ctx = "Hello World!" };

///////////////////////////////////////////////////////////////////////////////
// echo_post_handler
//
// An HTTP POST handler
//

static esp_err_t
echo_post_handler(httpd_req_t *req)
{
  char buf[100];
  int ret, remaining = req->content_len;

  while (remaining > 0) {
    // Read the data for the request 
    if ((ret = httpd_req_recv(req, buf, MIN(remaining, sizeof(buf)))) <= 0) {
      if (ret == HTTPD_SOCK_ERR_TIMEOUT) {
        // Retry receiving if timeout occurred 
        continue;
      }
      return ESP_FAIL;
    }

    // Send back the same data 
    httpd_resp_send_chunk(req, buf, ret);
    remaining -= ret;

    // Log data received 
    ESP_LOGI(TAG, "=========== RECEIVED DATA ==========");
    ESP_LOGI(TAG, "%.*s", ret, buf);
    ESP_LOGI(TAG, "====================================");
  }

  // End response
  httpd_resp_send_chunk(req, NULL, 0);
  return ESP_OK;
}

static const httpd_uri_t echo = { .uri = "/echo", .method = HTTP_POST, .handler = echo_post_handler, .user_ctx = NULL };

///////////////////////////////////////////////////////////////////////////////
// http_404_error_handler
//
// This handler allows the custom error handling functionality to be
// tested from client side. For that, when a PUT request 0 is sent to
// URI /ctrl, the /hello and /echo URIs are unregistered and following
// custom error handler http_404_error_handler() is registered.
// Afterwards, when /hello or /echo is requested, this custom error
// handler is invoked which, after sending an error message to client,
// either closes the underlying socket (when requested URI is /echo)
// or keeps it open (when requested URI is /hello). This allows the
// client to infer if the custom error handler is functioning as expected
// by observing the socket state.
//

esp_err_t
http_404_error_handler(httpd_req_t *req, httpd_err_code_t err)
{
  if (strcmp("/hello", req->uri) == 0) {
    httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "/hello URI is not available");
    // Return ESP_OK to keep underlying socket open 
    return ESP_OK;
  }
  else if (strcmp("/echo", req->uri) == 0) {
    httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "/echo URI is not available");
    // Return ESP_FAIL to close underlying socket 
    return ESP_FAIL;
  }
  // For any other URI send 404 and close socket 
  httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "Some 404 error message");
  return ESP_FAIL;
}

///////////////////////////////////////////////////////////////////////////////
// ctrl_put_handler
//
// An HTTP PUT handler. This demonstrates realtime
// registration and deregistration of URI handlers
//

static esp_err_t
ctrl_put_handler(httpd_req_t *req)
{
  char buf;
  int ret;

  if ((ret = httpd_req_recv(req, &buf, 1)) <= 0) {
    if (ret == HTTPD_SOCK_ERR_TIMEOUT) {
      httpd_resp_send_408(req);
    }
    return ESP_FAIL;
  }

  if (buf == '0') {
    // URI handlers can be unregistered using the uri string 
    ESP_LOGI(TAG, "Unregistering /hello and /echo URIs");
    httpd_unregister_uri(req->handle, "/hello");
    httpd_unregister_uri(req->handle, "/echo");
    // Register the custom error handler 
    httpd_register_err_handler(req->handle, HTTPD_404_NOT_FOUND, http_404_error_handler);
  }
  else {
    ESP_LOGI(TAG, "Registering /hello and /echo URIs");
    httpd_register_uri_handler(req->handle, &hello);
    httpd_register_uri_handler(req->handle, &echo);
    // Unregister custom error handler 
    httpd_register_err_handler(req->handle, HTTPD_404_NOT_FOUND, NULL);
  }

  // Respond with empty body 
  httpd_resp_send(req, NULL, 0);
  return ESP_OK;
}

static const httpd_uri_t ctrl = { .uri = "/ctrl", .method = HTTP_PUT, .handler = ctrl_put_handler, .user_ctx = NULL };


///////////////////////////////////////////////////////////////////////////////
// start_webserver
//

httpd_handle_t
start_webserver(void)
{
  httpd_handle_t server   = NULL;
  httpd_config_t config   = HTTPD_DEFAULT_CONFIG();
  config.lru_purge_enable = true;

  // Start the httpd server
  ESP_LOGI(TAG, "Starting server on port: '%d'", config.server_port);
  if (httpd_start(&server, &config) == ESP_OK) {
    
    // Set URI handlers
    ESP_LOGI(TAG, "Registering URI handlers");
    httpd_register_uri_handler(server, &hello);
    httpd_register_uri_handler(server, &echo);
    httpd_register_uri_handler(server, &ctrl);
    httpd_register_basic_auth(server);

    return server;
  }

  ESP_LOGI(TAG, "Error starting server!");
  return NULL;
}

///////////////////////////////////////////////////////////////////////////////
// stop_webserver
//

esp_err_t
stop_webserver(httpd_handle_t server)
{
  // Stop the httpd server
  return httpd_stop(server);
}

///////////////////////////////////////////////////////////////////////////////
// disconnect_handler
//

static void
disconnect_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data)
{
  httpd_handle_t *server = (httpd_handle_t *) arg;
  if (*server) {
    ESP_LOGI(TAG, "Stopping webserver");
    if (stop_webserver(*server) == ESP_OK) {
      *server = NULL;
    }
    else {
      ESP_LOGE(TAG, "Failed to stop http server");
    }
  }
}

///////////////////////////////////////////////////////////////////////////////
// connect_handler
//

static void
connect_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data)
{
  httpd_handle_t *server = (httpd_handle_t *) arg;
  if (*server == NULL) {
    ESP_LOGI(TAG, "Starting webserver");
    *server = start_webserver();
  }
}

