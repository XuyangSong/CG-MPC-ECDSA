#include <stdint.h>

typedef struct ExternError {
  int32_t code;
  char *message; // error message
} Error;

typedef struct ByteBuffer {
  // Note: This should never be negative, but values above
  // INT64_MAX / i64::MAX are not allowed.
  int64_t len;
  uint8_t *data;
} ResultBuffer;

/** Multi party threshold ecdsa keygen init.
 *
 *  In:     party_index:     the index of user.
 *  In:     share_count:     the num of share member.
 *  In:     threshold:       the num of threshold.
 *
 *  Out:    error:           output a ExternError. 'code' 0 represents success,
 *  all other values represent failure. If the `code` field is nonzero, there
 *  should always be a message, and if it's zero, the message will always be
 *  null.
 *
 *  Returns: if success, return pointer and len of the first round message to
 *  send. Otherwise return null.
 */
ResultBuffer multi_party_key_gen_init(int32_t party_index, int32_t share_count,
                                      int32_t threshold, Error *error);

/** Keygen phase received message handler.
 *
 *  In:     msg:        the pointer to message.
 *  In:     msg_len:    the size of message.
 *
 *  Out:    error:      output a ExternError. 'code' 0 represents success, all
 *  other values represent failure. If the `code` field is nonzero, there should
 *  always be a message, and if it's zero, the message will always be null.
 *
 *  Returns: if success, return pointer and len of the next message. Otherwise
 *  return null. When geting the the next message, decode it and decide to
 *  broadcast or send separately.
 */
ResultBuffer multi_party_key_gen_message_handler(const uint8_t *msg,
                                                 int32_t msg_len, Error *error);

/** Multi party threshold ecdsa sign init.
 *
 *  In:     party_index:            the index of user.
 *  In:     party_num:              the num of users that participate in sign.
 *  In:     share_count:            the num of share member.
 *  In:     threshold:              the num of threshold.
 *  In:     keygen_result:          the pointer to keygen_result. keygen_result
 *                                  is the output of keygen phase.
 *  In:     keygen_result_len:      the size of keygen_result.
 *
 *  Out:    error:                  output a ExternError. 'code' 0
 *  represents success, all other values represent failure. If the `code` field
 *  is nonzero, there should always be a message, and if it's zero, the message
 *  will always be null.
 *
 *  Returns: if success, return pointer and len of the first round message to
 *  send. Otherwise return null.
 */
ResultBuffer multi_party_sign_init(int32_t party_index, int32_t party_num,
                                   int32_t share_count, int32_t threshold,
                                   const uint8_t *keygen_result,
                                   int32_t keygen_result_len, Error *error);

/** Sign phase received message handler.
 *
 *  In:     msg:        the pointer to message.
 *  In:     msg_len:    the size of message.
 *
 *  Out:    error:      output a ExternError. 'code' 0 represents success, all
 *  other values represent failure. If the `code` field is nonzero, there should
 *  always be a message, and if it's zero, the message will always be null.
 *
 *  Returns: if success, return pointer and len of the next message. Otherwise
 *  return null. When geting the the next message, decode it and decide to
 *  broadcast or send separately.
 */
ResultBuffer multi_party_sign_message_handler(const uint8_t *msg,
                                              int32_t msg_len, Error *error);