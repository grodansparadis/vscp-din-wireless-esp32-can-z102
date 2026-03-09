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

/*!
 The VSCP Websocket Server (WS1) protocol is a simple text-based protocol designed
 for communication between a VSCP device and a client over a WebSocket connection.
 The protocol allows clients to send commands to the device and receive responses,
 as well as receive events from the device in real-time.

 It is documented here
 https://grodansparadis.github.io/vscp-doc-spec/#/./vscp_websocket?id=ws1-description
*/

#ifndef __VSCP_WS1_H__
#define __VSCP_WS1_H__

#include "vscp-compiler.h"
#include "vscp-projdefs.h"

#include <stdbool.h>

#include "vscp.h"
#include "vscp-firmware-helper.h"

// Defines in vscp-projdefs.h that should be used by the ws1 protocol implementation
// VSCP_WS1_MAX_CLIENTS - Maximum number of clients that can be connected at the same time

#define VSCP_WS1_MAX_PACKET_SIZE 512
#define VSCP_WS1_MAX_CLIENTS     10
#define VSCP_WS1_MAX_PACKET_SIZE 512 // Maximum size of received data packet

// ws1 packet types
#define VSCP_WS1_PKT_TYPE_UNKNOWN           0
#define VSCP_WS1_PKT_TYPE_COMMAND           1
#define VSCP_WS1_PKT_TYPE_EVENT             2
#define VSCP_WS1_PKT_TYPE_POSITIVE_RESPONSE 3
#define VSCP_WS1_PKT_TYPE_NEGATIVE_RESPONSE 4

/*!
  Define the version for the ws1 protocol supported
  by this driver
*/
#define VSCP_WS1_PROTOCOL_VERSION         1
#define VSCP_WS1_PROTOCOL_MINOR_VERSION   0
#define VSCP_WS1_PROTOCOL_RELEASE_VERSION 0
#define VSCP_WS1_PROTOCOL_BUILD_VERSION   0

// VSCP ws1 error codes
#define VSCP_WS1_ERROR_NONE                0 // No error
#define VSCP_WS1_ERROR_SYNTAX              1 // Syntax error
#define VSCP_WS1_ERROR_UNKNOWN_COMMAND     2 // Unknown command
#define VSCP_WS1_ERROR_TX_BUFFER_FULL      3 // Transmit buffer full
#define VSCP_WS1_ERROR_MEMORY              4 // Problem allocating memory
#define VSCP_WS1_ERROR_NOT_AUTHORIZED      5 // Not authorized
#define VSCP_WS1_ERROR_NOT_AUTHORIZED_SEND 6 // Not authorized to send events
#define VSCP_WS1_ERROR_NOT_ALLOWED         7 // Not allowed to do that
#define VSCP_WS1_ERROR_PARSE               8 // Parse error, invalid format
#define VSCP_WS1_ERROR_UNKNOWN_TYPE        9 // Unknown ws1 message type, only know "COMMAND" and "EVENT"

#define VSCP_WS1_STR_ERROR_NONE                      "Everything is OK."
#define VSCP_WS1_STR_ERROR_SYNTAX                    "Syntax error."
#define VSCP_WS1_STR_ERROR_UNKNOWN_COMMAND           "Unknown command."
#define VSCP_WS1_STR_ERROR_TX_BUFFER_FULL            "Transmit buffer full."
#define VSCP_WS1_STR_ERROR_MEMORY_ALLOCATION         "Having problems to allocate memory."
#define VSCP_WS1_STR_ERROR_NOT_AUTHORISED            "Not authorised."
#define VSCP_WS1_STR_ERROR_NOT_ALLOWED_TO_SEND_EVENT "Not allowed to send event."
#define VSCP_WS1_STR_ERROR_NOT_ALLOWED_TO_DO_THAT    "Not allowed to do that (check privileges)"
#define VSCP_WS1_STR_ERROR_PARSE_FORMAT              "Parse error, invalid format."
#define VSCP_WS1_STR_ERROR_UNKNOWN_TYPE              "Unknown type, only know 'COMMAND' and 'EVENT'."
#define VSCP_WS1_STR_ERROR_GENERAL                   "Exception or other general error."

/*
  This structure contains information about an authenticated user.
  It is used in the authentication process and may be populated with information
  from a user database or other source of user information. Some system may only
  allow for one user. In that case this structure can be populated with the information
  for that single user and the authentication process can simply check if the provided
  credentials match the information in this structure.

  Only the callbacks see this structure so the implementer may change it as he/she pleases.

  The fields in the structure are as follows:
  - username: The username of the user.
  - password: The password of the user (this should be encrypted or hashed in a secure manner).
  - fullname: The full name of the user.
  - filtermask: The filter mask for the user.
  - rights: The rights or permissions of the user. This can hold bits for rights this user has.
  - remotes: The remote access information for the user. This can be a comma-separated list of IP addresses or hostnames
  that the user is allowed to connect from.
  - events: The events associated with the user. This can be a comma-separated list of event types or IDs that the user
  is allowed to receive.
  - note: Any additional notes about the user.
*/
typedef struct _ws1_user {

  // Username of user
  char username[32];

  // Full name of user
#ifndef VSCP_WS1_DISABLE_USER_FULL_NAME  
  char fullname[64];
#endif  

  /*
    Default filter mask for the user. Set after authentication. The user is allowed to change the
    filter mask after authentication if he/she has the right to do so.
    The filter mask is used to determine which events the user receives from the server.
  */
  vscpEventFilter rxfilter;

  /*
    Bitfield for user rights/permissions, see vscp.h for defined rights.
    This field is used to determine what the user is allowed to do and not to do.
  */
  uint64_t user_rights;

  /*
    Remote IP addresses the user is allowed to connect from. 
    The list is binary and the IPs are stored in network byte order. 
    The list is terminated by an all-zero entry. For IPv4 addresses, 
    the first 12 bytes should be set to 0 and the last 4 bytes should 
    contain the IPv4 address in network byte order.
    All zeros = end of list. 
    An empty list (first entry is all zeros) means all remotes are allowed.
    For IPv4: store in last 4 bytes, first 12 = 0x00...00FFFF prefix
  */
  uint8_t allowed_remotes[16][16];

  /*
    The list can be used to specify which events a user is allowed to send if the
    user has the right to send events.  Events are stored binary as 16-bit value (MSB first) 
    pairs (class,type). Two zeros (class=0, type=0) indicate the end of the list. An empty 
    list (zeros on the first position) means all events are allowed. 
  */
  uint16_t events[16][2]; // Events the user is allowed to send

  /*
     Additional notes about the user.
     If disabled by defining VSCP_WS1_DISABLE_USER_NOTES this field is not included in the 
     structure to save memory. Notes will in this case be left blank on reports.
  */
#ifndef VSCP_WS1_DISABLE_USER_NOTES 
  char note[256];
#endif
} ws1_user_t;

typedef struct _vscp_ws1_connection_context {
  uint8_t sid[16];                    // Session ID for authentication and encryption
  bool bOpen;                         // Flag for open/closed channel- True oif open
  bool bAuthenticated;                // Whether the client is authenticated. True if authenticated
  vscpEventFilter filter;             // Filter/mask for received VSCP events for this connection
  ws1_user_t user;                    // User information for athenticated user
  void *pdata;                        // Pointer to user data that can be used to store connection-specific information
} vscp_ws1_connection_context_t;

/*!
  Initialize the WS1 protocol handler. This function should be called before any other functions
  in this module are used.
  @param pctx Pointer to a ws1_connection_context_t structure that will be initialized.
  This structure will be used to store connection-specific information for the WS1 protocol handler.
  @param pdata Pointer to user data that can be used to store connection-specific information.
  @return Returns VSCP_ERROR_SUCCESS if the initialization was successful, or an appropriate error code if there was a
  failure.
*/
int
vscp_ws1_init(vscp_ws1_connection_context_t *pctx, void *pdata);

/*!
  Clean up any resources used by the WS1 protocol handler. This function should be called when the
  protocol handler is no longer needed.
  @return Returns VSCP_ERROR_SUCCESS if the cleanup was successful, or an appropriate error code if there was a failure.
*/
int
vscp_ws1_clearup();

/*!
  Stock generate session id (sid). The sid is used as an IV for encrypting credentials and may
  also be used as a session identifier for the connection. The sid value is set in the
  vscp_ws1_callback_generate_sid callback which in turn often calls this function to generate
  the sid.
  @param sid Pointer to a 16-byte buffer that will be populated with the session id.
  @param size The size of the buffer (16). This should be at least 16 bytes to hold the 128 bit session id.
  @param pctx Pointer to the connection context for this command. This will contain information about the connection
  and can be used to store connection-specific data as needed.
  @return Returns VSCP_ERROR_SUCCESS if the command was successfully processed, or an appropriate error code if there
  was a failure.
*/
int
vscp_ws1_generate_sid(uint8_t *sid, size_t size, vscp_ws1_connection_context_t *pctx);

/*!
  Handle a received WS1 protocol packet. This function should be called when a packet is received from the client.
  The function will parse the packet, determine the type of packet (command, event, etc.), and call the appropriate
  callback function to handle the packet.
  @param packet The received packet as a null-terminated string.
  @param len The length of the received packet.
  @param pctx Pointer to the connection context for this command. This will contain information about the connection
  and can be used to store connection-specific data as needed.
  @return Returns VSCP_ERROR_SUCCESS if the packet was successfully processed, or an appropriate error code if there was
  a failure.
*/
int
vscp_ws1_handle_protocol_request(const char *packet, uint16_t len, vscp_ws1_connection_context_t *pctx);

/*!
  Function called when a command is received via the WS1 protocol.
  The callback should process the command and send an appropriate reply using the
  vscp_ws1_callback_reply function.
  @fn vscp_ws1_callback_command
  @param command The command that was received. This will be a null-terminated string.
  @param parg The argument part of the command, if any. This will be a null-terminated string or NULL if there is no
  argument.
  @param pctx Pointer to the connection context for this command. This will contain information about
  @return Returns VSCP_ERROR_SUCCESS if the command was successfully processed,
  or an appropriate error code if there was a failure.
*/
int
vscp_ws1_handle_command(const char *command, const char *parg, vscp_ws1_connection_context_t *pctx);

///////////////////////////////////////////////////////////////////////////////
//                               CALLBACKS
///////////////////////////////////////////////////////////////////////////////

/*!
  This callback is called after the framework has completed its initialisation. Just return
  VSCP_ERROR_SUCCESS if no special intialisatrion is needed.
  @param pctx Pointer to the connection context for this command. This will contain information
  about the connection and can be used to store connection-specific data as needed.
  @return Returns VSCP_ERROR_SUCCESS if the reply was successfully sent, or an appropriate error code if there was a
  failure.
*/
int
vscp_ws1_callback_init(vscp_ws1_connection_context_t *pctx);

/*!
  This callback is called before the framework is about to terminate. The callback can be used to clean up any
  resources associated with the connection. Just return VSCP_ERROR_SUCCESS if no special cleanup is needed.
  @param pctx Pointer to the connection context for this command. This will contain information
  about the connection and can be used to store connection-specific data as needed.
  @return Returns VSCP_ERROR_SUCCESS if the reply was successfully sent, or an appropriate
  error code if there was a failure.
*/
int
vscp_ws1_callback_cleanup(vscp_ws1_connection_context_t *pctx);

/*!
  Function called when a session id is needed to be generated for a new connection.
  The callback should generate a random session id and populate the provided buffer
  with the session id.
  @param sid Pointer to a buffer that will be populated with the session id.
  @param size The size of the buffer. This should be at least 16 bytes to hold the
  128 bit session id.
  @return Returns VSCP_ERROR_SUCCESS if the session id was successfully generated,
  or an appropriate error code if there was a failure.
*/
int
vscp_ws1_callback_generate_sid(uint8_t *sid, size_t size, vscp_ws1_connection_context_t *pctx);

/*!
  @fn vscp_ws1_callback_get_key
  @brief Callback function to get the 128 bit encryption key for a given session.
  @param pkey A pointer to a 128 bit encryption key is returned here.
  @param pdata Pointer to user data that can be used to store connection-specific information.
  @return Returns VSCP_ERROR_SUCCESS if the encryption key was successfully returned in pkey,
  or an appropriate error code if there was a failure (e.g. connection not found, key not available).
*/
int
vscp_ws1_callback_get_key(uint8_t **pkey, vscp_ws1_connection_context_t *pctx);

/*!
@fn vscp_ws1_callback_validate_user
  @brief Callback function to validate a user based on client-supplied credentials.
  This function should validate the user information for the given credentials fetched
  from the AUTH command and return a positive reply if authentication was successful,
  or a negative reply if authentication failed.
  The encrypted credentials is encrypted using the session ID (SID) as the IV and a
  pre-shared encryption key. The callback should decrypt the credentials using the session ID
  as the IV and the pre-shared secret key using AES-128 decryption. The decrypted credentials
  should be in the format "username:password".
  @param pcrypto A pointer to the encrypted credentials provided by the client for authentication.
  This should be a binary buffer containing the AES-128 encrypted credentials over "user:password".
  @param psid A pointer to a buffer holding a 128 bit session ID in binary form  that is used
  as the IV.
  @param pctx Pointer to the connection context.
  @return Returns VSCP_ERROR_SUCCESS if authentication was successful, or an appropriate error code if there was a
  failure.

  The callback should respond with

  "+;AUTH1;userid;name;;fullname;filtermask;rights;remotes;events;note"

  if the credentials are valid. The fields in the response are as follows:
  - userid: A unique identifier for the user (e.g. a numeric ID or UUID).
  - name: The username of the authenticated user.
  - fullname: The full name of the authenticated user.
  - filtermask: The event filter mask for the authenticated user in the standard comma seperated form.
  - rights: The permissions or rights assigned to the authenticated user as 63-bit number,
      represented as a hexadecimal string.
  - remotes: The remote hosts or clients that the authenticated user is allowed to connect from.
  - events: The events that the authenticated user is allowed to receive
  - note: Additional notes or information about the authenticated user.
*/

int
vscp_ws1_callback_validate_user(const uint8_t *pcrypto, uint8_t crypto_len, const uint8_t *psid, vscp_ws1_connection_context_t *pctx);

/*!
  Return VSCP_ERROR_SUCCESS if the user is allowed to send the event based on  user's permissions. Just return
  VSCP_ERROR_SUCCESS if all events are allowed.
  @param pEvent Pointer to the VSCP event that is being evaluated for sending to the client.
  @param pctx Pointer to the connection context for this command. This will contain information about the connection and
  can be used to store connection-specific data as needed.
  @return Returns VSCP_ERROR_SUCCESS if the user is allowed to send the event, or an appropriate error code if not.
*/
int
vscp_ws1_callback_is_allowed_event(vscpEvent *pEvent, vscp_ws1_connection_context_t *pctx);

/*!
  @fn vscp_ws1_callback_is_allowed_connection
  @brief Callback function to check if a connection from a given IP address is allowed. This function should
  check the provided IP address against the allowed remote hosts for the authenticated user and return
  an appropriate response. Just return VSCP_ERROR_SUCCESS if all connections are allowed.
  @param pip The IP address of the incoming connection, represented as a null-terminated string (e.g. "192.168.1.100").
  @param pctx Pointer to the connection context for this command. This will contain information about the connection and
  can be used to store connection-specific data as needed.
  @return Returns VSCP_ERROR_SUCCESS if the connection from the given IP address is allowed, or an appropriate error
  code if there was a failure (e.g. connection not allowed).
*/
int
vscp_ws1_callback_is_allowed_connection(const char *pip, vscp_ws1_connection_context_t *pctx);

/*!
  Send a reply to a command received via the WS1 protocol. The reply will be sent
  asynchronously and the caller will not be blocked while waiting for the reply to be sent.
  @param response The response to send. This should be a null-terminated string.
  @param pdata Pointer to user data that can be used to store connection-specific information.
  @note The response should not include the leading '+' or '-' character, as this
  will be added automatically based on the success or failure of the command.
  @return Returns VSCP_ERROR_SUCCESS if the reply was successfully queued for sending,
  or an appropriate error code if there was a failure.
*/
int
vscp_ws1_callback_reply(const char *response, vscp_ws1_connection_context_t *pctx);

/*!
  @fn vscp_ws1_callback_event
  @brief Callback function that is called when an event is received. The callback
  should process the event and respond appropriately.
  @param pEvent Pointer to the VSCP event that was received.
  @return Returns VSCP_ERROR_SUCCESS if the event was successfully processed and sent,
  or an appropriate error code if there was a failure.
*/
int
vscp_ws1_callback_event(vscpEvent *pEvent, vscp_ws1_connection_context_t *pctx);

/*!
  @fn vscp_ws1_callback_copyright
  @brief Callback function for the COPYRIGHT command. This command should return the copyright
  information for the VSCP firmware running on the device as something like
  "+;COPYRIGHT;Copyright (C) 2027 Company Name. All rights reserved.".
  @param pdata Pointer to user data that can be used to store connection-specific information.
  @return Returns VSCP_ERROR_SUCCESS if the copyright information was successfully sent,
  or an appropriate error code if there was a failure.
*/
int
vscp_ws1_callback_copyright(vscp_ws1_connection_context_t *pctx);


/*!
  @fn vscp_ws1_callback_open
  @brief Callback function for the OPEN command. This command should open the connection for receiving
  events and return a positive reply if the connection was successfully opened, or a negative reply if
  there was a failure.
    @param pdata Pointer to user data that can be used to store connection-specific information.
    @note When the connection is opened, the server should start sending events to the client based on the
    event filter that has been set for the connection. The server should also be prepared to receive commands
    from the client and respond to them appropriately while the connection is open.
  @return Returns VSCP_ERROR_SUCCESS if the connection was successfully opened, or an appropriate error code if there
  was a failure.
*/
int
vscp_ws1_callback_open(vscp_ws1_connection_context_t *pctx);

/*!
  @fn vscp_ws1_callback_close
  @brief Callback function for the CLOSE command. This command should close the connection for receiving
  events and return a positive reply if the connection was successfully closed, or a negative reply if there was a
  failure.
    @param pdata Pointer to user data that can be used to store connection-specific information.
    @note When the connection is closed, the server should stop sending events to the client and should not
    expect to receive any more commands from the client until a new connection is opened. The server should also
    clean up any resources associated with the connection as needed.
    @return Returns VSCP_ERROR_SUCCESS if the connection was successfully closed, or an appropriate error code if there
    was a failure.
*/
int
vscp_ws1_callback_close(vscp_ws1_connection_context_t *pctx);

/*!
  @fn vscp_ws1_callback_setfilter
  @brief Callback function for the SETFILTER command. This command should set the event filter based on the provided
  data and return a positive reply if the filter was successfully set, or a negative reply if there was a failure.
  @param pfilter The filter data provided by the client for setting the event filter. This will be a null-terminated
  string and may contain additional data separated by semicolons.
  @param pdata Pointer to user data that can be used to store connection-specific information.
  @return Returns VSCP_ERROR_SUCCESS if the event filter was successfully set, or an appropriate error code if there was
  a failure.
*/
int
vscp_ws1_callback_setfilter(const vscpEventFilter *pfilter, vscp_ws1_connection_context_t *pctx);

/*!
  @fn vscp_ws1_callback_clrqueue
  @brief Callback function for the CLRQUEUE command. This command should clear the event queue and return a positive
  reply if the queue was successfully cleared, or a negative reply if there was a failure.
    @param pdata Pointer to user data that can be used to store connection-specific information.
    @note When the event queue is cleared, any events that were queued for sending to the client should be discarded,
    and the server should not send those events to the client. The server should also ensure that any resources
    associated with the queued events are properly cleaned up.
    @
  @return Returns VSCP_ERROR_SUCCESS if the event queue was successfully cleared, or an appropriate error code if there
  was a failure.
*/
int
vscp_ws1_callback_clrqueue(vscp_ws1_connection_context_t *pctx);

#endif /* __VSCP_WS1_H__ */