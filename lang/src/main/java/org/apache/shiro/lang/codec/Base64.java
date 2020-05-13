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
package org.apache.shiro.lang.codec;

/**
 * Provides <a href="http://en.wikipedia.org/wiki/Base64">Base 64</a> encoding and decoding as defined by
 * <a href="http://www.ietf.org/rfc/rfc2045.txt">RFC 2045</a>.
 * <p/>
 * This class implements section <cite>6.8. Base64 Content-Transfer-Encoding</cite> from RFC 2045 <cite>Multipurpose
 * Internet Mail Extensions (MIME) Part One: Format of Internet Message Bodies</cite> by Freed and Borenstein.
 * <p/>
 * This class was borrowed from Apache Commons Codec SVN repository (rev. 618419) with modifications
 * to enable Base64 conversion without a full dependency on Commons Codec.  We didn't want to reinvent the wheel of
 * great work they've done, but also didn't want to force every Shiro user to depend on the commons-codec.jar
 * <p/>
 * As per the Apache 2.0 license, the original copyright notice and all author and copyright information have
 * remained in tact.
 *
 * @see <a href="http://en.wikipedia.org/wiki/Base64">Wikipedia: Base 64</a>
 * @see <a href="http://www.ietf.org/rfc/rfc2045.txt">RFC 2045</a>
 * @since 0.9
 */
public class Base64 {

    /**
     * Base64 encodes the specified byte array and then encodes it as a String using Shiro's preferred character
     * encoding (UTF-8).
     *
     * @param bytes the byte array to Base64 encode.
     * @return a UTF-8 encoded String of the resulting Base64 encoded byte array.
     */
    public static String encodeToString(byte[] bytes) {
        byte[] encoded = encode(bytes);
        return CodecSupport.toString(encoded);
    }

    /**
     * Encodes a byte[] containing binary data, into a byte[] containing characters in the Base64 alphabet.
     *
     * @param pArray a byte array containing binary data
     * @return A byte array containing only Base64 character data
     */
    public static byte[] encode(byte[] pArray) {
        return java.util.Base64.getEncoder().encode(pArray);
    }


    /**
     * Converts the specified UTF-8 Base64 encoded String and decodes it to a resultant UTF-8 encoded string.
     *
     * @param base64Encoded a UTF-8 Base64 encoded String
     * @return the decoded String, UTF-8 encoded.
     */
    public static String decodeToString(String base64Encoded) {
        byte[] encodedBytes = CodecSupport.toBytes(base64Encoded);
        return decodeToString(encodedBytes);
    }

    /**
     * Decodes the specified Base64 encoded byte array and returns the decoded result as a UTF-8 encoded.
     *
     * @param base64Encoded a Base64 encoded byte array
     * @return the decoded String, UTF-8 encoded.
     */
    public static String decodeToString(byte[] base64Encoded) {
        byte[] decoded = decode(base64Encoded);
        return CodecSupport.toString(decoded);
    }

    /**
     * Converts the specified UTF-8 Base64 encoded String and decodes it to a raw Base64 decoded byte array.
     *
     * @param base64Encoded a UTF-8 Base64 encoded String
     * @return the raw Base64 decoded byte array.
     */
    public static byte[] decode(String base64Encoded) {
        byte[] bytes = CodecSupport.toBytes(base64Encoded);
        return decode(bytes);
    }

    /**
     * Decodes Base64 data into octets
     *
     * @param base64Data Byte array containing Base64 data
     * @return Array containing decoded data.
     */
    public static byte[] decode(byte[] base64Data) {
        return java.util.Base64.getDecoder().decode(base64Data);
    }

}
