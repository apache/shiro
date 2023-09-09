/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.shiro.crypto.support.hashes.bcrypt;


/**
 * Encoder for the custom Base64 variant of BCrypt (called Radix64 here). It has the same rules as Base64 but uses a
 * different mapping table than the various RFCs
 * <p>
 * According to Wikipedia:
 *
 * <blockquote>
 * Unix stores password hashes computed with crypt in the /etc/passwd file using radix-64 encoding called B64. It uses a
 * mostly-alphanumeric set of characters, plus . and /.
 * Its 64-character set is "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz".
 * Padding is not used.
 * </blockquote>
 *
 * @since 2.0
 */
@SuppressWarnings({"checkstyle:MagicNumber", "checkstyle:BooleanExpressionComplexity",
"checkstyle:NPathComplexity", "checkstyle:CyclomaticComplexity"})
interface OpenBSDBase64 {


    /**
     * Encode given raw byte array to a Radix64 style, UTF-8 encoded byte array.
     *
     * @param rawBytes to encode
     * @return UTF-8 encoded string representing radix64 encoded data
     */
    byte[] encode(byte[] rawBytes);

    /**
     * From a UTF-8 encoded string representing radix64 encoded data as byte array,
     * decodes the raw bytes from it.
     *
     * @param utf8EncodedRadix64String from a string get it with
     *        <code>"m0CrhHm10qJ3lXRY.5zDGO".getBytes(StandardCharsets.UTF8)</code>
     * @return the raw bytes encoded by this utf-8 radix4 string
     */
    byte[] decode(byte[] utf8EncodedRadix64String);

    /**
     * A mod of Square's Okio Base64 encoder
     * <p>
     * Original author: Alexander Y. Kleymenov
     *
     * @see <a href="https://github.com/square/okio/blob/okio-parent-1.15.0/okio/src/main/java/okio/Base64.java">Okio</a>
     */
    class Default implements OpenBSDBase64 {
        private static final byte[] DECODE_TABLE = {
                -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0, 1, 54, 55, 56, 57,
                58, 59, 60, 61, 62, 63, -1, -1, -1, -2, -1, -1, -1, 2, 3, 4, 5, 6, 7,
                8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
                26, 27, -1, -1, -1, -1, -1, -1, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37,
                38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53};

        private static final byte[] MAP = new byte[]{
                '.', '/', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J',
                'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V',
                'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
                'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't',
                'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5',
                '6', '7', '8', '9'
        };

        @Override
        public byte[] encode(final byte[] in) {
            return encode(in, MAP);
        }

        @Override
        public byte[] decode(final byte[] in) {
            // Ignore trailing '=' padding and whitespace from the input.
            int limit = in.length;
            for (; limit > 0; limit--) {
                final byte c = in[limit - 1];
                if (c != '=' && c != '\n' && c != '\r' && c != ' ' && c != '\t') {
                    break;
                }
            }

            // If the input includes whitespace, this output array will be longer than necessary.
            final byte[] out = new byte[(int) (limit * 6L / 8L)];
            int outCount = 0;
            int inCount = 0;

            int word = 0;
            for (int pos = 0; pos < limit; pos++) {
                final byte c = in[pos];

                final int bits;
                if (c == '.' || c == '/' || (c >= 'A' && c <= 'z') || (c >= '0' && c <= '9')) {
                    bits = DECODE_TABLE[c];
                } else if (c == '\n' || c == '\r' || c == ' ' || c == '\t') {
                    continue;
                } else {
                    throw new IllegalArgumentException("invalid character to decode: " + c);
                }

                // Append this char's 6 bits to the word.
                word = (word << 6) | (byte) bits;

                // For every 4 chars of input, we accumulate 24 bits of output. Emit 3 bytes.
                inCount++;
                if (inCount % 4 == 0) {
                    out[outCount++] = (byte) (word >> 16);
                    out[outCount++] = (byte) (word >> 8);
                    out[outCount++] = (byte) word;
                }
            }

            final int lastWordChars = inCount % 4;
            if (lastWordChars == 1) {
                // We read 1 char followed by "===". But 6 bits is a truncated byte! Fail.
                return new byte[0];
            } else if (lastWordChars == 2) {
                // We read 2 chars followed by "==". Emit 1 byte with 8 of those 12 bits.
                word = word << 12;
                out[outCount++] = (byte) (word >> 16);
            } else if (lastWordChars == 3) {
                // We read 3 chars, followed by "=". Emit 2 bytes for 16 of those 18 bits.
                word = word << 6;
                out[outCount++] = (byte) (word >> 16);
                out[outCount++] = (byte) (word >> 8);
            }

            // If we sized our out array perfectly, we're done.
            if (outCount == out.length) {
                return out;
            }

            // Copy the decoded bytes to a new, right-sized array.
            final byte[] prefix = new byte[outCount];
            System.arraycopy(out, 0, prefix, 0, outCount);
            return prefix;
        }

        private static byte[] encode(final byte[] in, final byte[] map) {
            final int length = 4 * (in.length / 3) + (in.length % 3 == 0 ? 0 : in.length % 3 + 1);
            final byte[] out = new byte[length];
            int index = 0;
            final int end = in.length - in.length % 3;
            for (int i = 0; i < end; i += 3) {
                out[index++] = map[(in[i] & 0xff) >> 2];
                out[index++] = map[((in[i] & 0x03) << 4) | ((in[i + 1] & 0xff) >> 4)];
                out[index++] = map[((in[i + 1] & 0x0f) << 2) | ((in[i + 2] & 0xff) >> 6)];
                out[index++] = map[(in[i + 2] & 0x3f)];
            }
            switch (in.length % 3) {
                case 1:
                    out[index++] = map[(in[end] & 0xff) >> 2];
                    out[index] = map[(in[end] & 0x03) << 4];
                    break;
                case 2:
                    out[index++] = map[(in[end] & 0xff) >> 2];
                    out[index++] = map[((in[end] & 0x03) << 4) | ((in[end + 1] & 0xff) >> 4)];
                    out[index] = map[((in[end + 1] & 0x0f) << 2)];
                    break;
                default:
            }
            return out;
        }
    }
}
