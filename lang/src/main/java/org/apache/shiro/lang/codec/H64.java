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
/*
 * The apr_md5_encode() routine in the APR project's apr_md5.c file uses much
 * code obtained from the FreeBSD 3.0 MD5 crypt() function, which is licenced
 * as follows:
 * ----------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <phk@login.dknet.dk> wrote this file.  As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return.   Poul-Henning Kamp
 * ----------------------------------------------------------------------------
 */
package org.apache.shiro.lang.codec;

import java.io.IOException;

/**
 * Codec for <a href="http://en.wikipedia.org/wiki/Crypt_(Unix)">Unix Crypt</a>-style encoding.  While similar to
 * Base64, it is not compatible with Base64.
 * <p/>
 * This implementation is based on encoding algorithms found in the Apache Portable Runtime library's
 * <a href="http://svn.apache.org/viewvc/apr/apr/trunk/crypto/apr_md5.c?revision=HEAD&view=markup">apr_md5.c</a>
 * implementation for its {@code crypt}-style support.  The APR team in turn received inspiration for its encoding
 * implementation based on FreeBSD 3.0's {@code /usr/src/lib/libcrypt/crypt.c} implementation.  The
 * accompanying license headers have been retained at the top of this source file.
 * <p/>
 * This file and all that it contains is ASL 2.0 compatible.
 *
 * @since 1.2
 */
public class H64 {

    private static final char[] itoa64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz".toCharArray();

    private static short toShort(byte b) {
        return (short) (b & 0xff);
    }

    private static int toInt(byte[] bytes, int offset, int numBytes) {
        if (numBytes < 1 || numBytes > 4) {
            throw new IllegalArgumentException("numBytes must be between 1 and 4.");
        }
        int val = toShort(bytes[offset]); //1st byte
        for (int i = 1; i < numBytes; i++) { //any remaining bytes:
            short s = toShort(bytes[offset + i]);
            switch (i) {
                case 1: val |= s << 8; break;
                case 2: val |= s << 16; break;
                case 3: val |= s << 24; break;
            }
        }
        return val;
    }

    /**
     * Appends the specified character into the buffer, rethrowing any encountered
     * {@link IOException} as an {@link IllegalStateException} (since this method is used for internal
     * implementation needs and we only ever use StringBuilders, we should never encounter an IOException).
     *
     * @param buf the buffer to append to
     * @param c   the character to append.
     */
    private static void append(Appendable buf, char c) {
        try {
            buf.append(c);
        } catch (IOException e) {
            throw new IllegalStateException("Unable to append character to internal buffer.", e);
        }
    }

    /**
     * Encodes the specified integer to {@code numChars} H64-compatible characters and appends them into {@code buf}.
     *
     * @param value    the integer to encode to H64-compatible characters
     * @param buf      the output buffer
     * @param numChars the number of characters the value should be converted to.  3, 2 or 1.
     */
    private static void encodeAndAppend(int value, Appendable buf, int numChars) {
        for (int i = 0; i < numChars; i++) {
            append(buf, itoa64[value & 0x3f]);
            value >>= 6;
        }
    }

    /**
     * Encodes the specified bytes to an {@code H64}-encoded String.
     *
     * @param bytes
     * @return
     */
    public static String encodeToString(byte[] bytes) {
        if (bytes == null || bytes.length == 0) return null;

        StringBuilder buf = new StringBuilder();

        int length = bytes.length;
        int remainder = length % 3;
        int i = 0; //starting byte
        int last3ByteIndex = length - remainder; //last byte whose index is a multiple of 3

        for(; i < last3ByteIndex; i += 3) {
            int twentyFourBit = toInt(bytes, i, 3);
            encodeAndAppend(twentyFourBit, buf, 4);
        }
        if (remainder > 0) {
            //one or two bytes that we still need to encode:
            int a = toInt(bytes, i, remainder);
            encodeAndAppend(a, buf, remainder + 1);
        }
        return buf.toString();
    }
}
