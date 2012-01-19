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
package org.apache.shiro.codec;

/**
 * Provides <a href="http://en.wikipedia.org/wiki/Base64">Base 64</a> encoding and decoding as defined by
 * <a href="http://www.ietf.org/rfc/rfc2045.txt">RFC 2045</a>.
 * <p/>
 * This class implements section <cite>6.8. Base64 Content-Transfer-Encoding</cite> from RFC 2045 <cite>Multipurpose
 * Internet Mail Extensions (MIME) Part One: Format of Internet Message Bodies</cite> by Freed and Borenstein.
 * <p/>
 * This class was borrowed from Apache Commons Codec SVN repository (rev. 618419) with modifications
 * to enable Base64 conversion without a full dependecny on Commons Codec.  We didn't want to reinvent the wheel of
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
     * Chunk size per RFC 2045 section 6.8.
     * <p/>
     * The character limit does not count the trailing CRLF, but counts all other characters, including any
     * equal signs.
     *
     * @see <a href="http://www.ietf.org/rfc/rfc2045.txt">RFC 2045 section 6.8</a>
     */
    static final int CHUNK_SIZE = 76;

    /**
     * Chunk separator per RFC 2045 section 2.1.
     *
     * @see <a href="http://www.ietf.org/rfc/rfc2045.txt">RFC 2045 section 2.1</a>
     */
    static final byte[] CHUNK_SEPARATOR = "\r\n".getBytes();

    /**
     * The base length.
     */
    private static final int BASELENGTH = 255;

    /**
     * Lookup length.
     */
    private static final int LOOKUPLENGTH = 64;

    /**
     * Used to calculate the number of bits in a byte.
     */
    private static final int EIGHTBIT = 8;

    /**
     * Used when encoding something which has fewer than 24 bits.
     */
    private static final int SIXTEENBIT = 16;

    /**
     * Used to determine how many bits data contains.
     */
    private static final int TWENTYFOURBITGROUP = 24;

    /**
     * Used to get the number of Quadruples.
     */
    private static final int FOURBYTE = 4;

    /**
     * Used to test the sign of a byte.
     */
    private static final int SIGN = -128;

    /**
     * Byte used to pad output.
     */
    private static final byte PAD = (byte) '=';

    /**
     * Contains the Base64 values <code>0</code> through <code>63</code> accessed by using character encodings as
     * indices.
     * <p/>
     * <p>For example, <code>base64Alphabet['+']</code> returns <code>62</code>.</p>
     * <p/>
     * <p>The value of undefined encodings is <code>-1</code>.</p>
     */
    private static final byte[] base64Alphabet = new byte[BASELENGTH];

    /**
     * <p>Contains the Base64 encodings <code>A</code> through <code>Z</code>, followed by <code>a</code> through
     * <code>z</code>, followed by <code>0</code> through <code>9</code>, followed by <code>+</code>, and
     * <code>/</code>.</p>
     * <p/>
     * <p>This array is accessed by using character values as indices.</p>
     * <p/>
     * <p>For example, <code>lookUpBase64Alphabet[62] </code> returns <code>'+'</code>.</p>
     */
    private static final byte[] lookUpBase64Alphabet = new byte[LOOKUPLENGTH];

    // Populating the lookup and character arrays

    static {
        for (int i = 0; i < BASELENGTH; i++) {
            base64Alphabet[i] = (byte) -1;
        }
        for (int i = 'Z'; i >= 'A'; i--) {
            base64Alphabet[i] = (byte) (i - 'A');
        }
        for (int i = 'z'; i >= 'a'; i--) {
            base64Alphabet[i] = (byte) (i - 'a' + 26);
        }
        for (int i = '9'; i >= '0'; i--) {
            base64Alphabet[i] = (byte) (i - '0' + 52);
        }

        base64Alphabet['+'] = 62;
        base64Alphabet['/'] = 63;

        for (int i = 0; i <= 25; i++) {
            lookUpBase64Alphabet[i] = (byte) ('A' + i);
        }

        for (int i = 26, j = 0; i <= 51; i++, j++) {
            lookUpBase64Alphabet[i] = (byte) ('a' + j);
        }

        for (int i = 52, j = 0; i <= 61; i++, j++) {
            lookUpBase64Alphabet[i] = (byte) ('0' + j);
        }

        lookUpBase64Alphabet[62] = (byte) '+';
        lookUpBase64Alphabet[63] = (byte) '/';
    }

    /**
     * Returns whether or not the <code>octect</code> is in the base 64 alphabet.
     *
     * @param octect The value to test
     * @return <code>true</code> if the value is defined in the the base 64 alphabet, <code>false</code> otherwise.
     */
    private static boolean isBase64(byte octect) {
        if (octect == PAD) {
            return true;
        } else //noinspection RedundantIfStatement
            if (octect < 0 || base64Alphabet[octect] == -1) {
                return false;
            } else {
                return true;
            }
    }

    /**
     * Tests a given byte array to see if it contains only valid characters within the Base64 alphabet.
     *
     * @param arrayOctect byte array to test
     * @return <code>true</code> if all bytes are valid characters in the Base64 alphabet or if the byte array is
     *         empty; false, otherwise
     */
    public static boolean isBase64(byte[] arrayOctect) {

        arrayOctect = discardWhitespace(arrayOctect);

        int length = arrayOctect.length;
        if (length == 0) {
            // shouldn't a 0 length array be valid base64 data?
            // return false;
            return true;
        }
        for (int i = 0; i < length; i++) {
            if (!isBase64(arrayOctect[i])) {
                return false;
            }
        }
        return true;
    }

    /**
     * Discards any whitespace from a base-64 encoded block.
     *
     * @param data The base-64 encoded data to discard the whitespace from.
     * @return The data, less whitespace (see RFC 2045).
     */
    static byte[] discardWhitespace(byte[] data) {
        byte groomedData[] = new byte[data.length];
        int bytesCopied = 0;

        for (byte aByte : data) {
            switch (aByte) {
                case (byte) ' ':
                case (byte) '\n':
                case (byte) '\r':
                case (byte) '\t':
                    break;
                default:
                    groomedData[bytesCopied++] = aByte;
            }
        }

        byte packedData[] = new byte[bytesCopied];

        System.arraycopy(groomedData, 0, packedData, 0, bytesCopied);

        return packedData;
    }

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
     * Encodes binary data using the base64 algorithm and chunks the encoded output into 76 character blocks
     *
     * @param binaryData binary data to encodeToChars
     * @return Base64 characters chunked in 76 character blocks
     */
    public static byte[] encodeChunked(byte[] binaryData) {
        return encode(binaryData, true);
    }

    /**
     * Encodes a byte[] containing binary data, into a byte[] containing characters in the Base64 alphabet.
     *
     * @param pArray a byte array containing binary data
     * @return A byte array containing only Base64 character data
     */
    public static byte[] encode(byte[] pArray) {
        return encode(pArray, false);
    }

    /**
     * Encodes binary data using the base64 algorithm, optionally chunking the output into 76 character blocks.
     *
     * @param binaryData Array containing binary data to encodeToChars.
     * @param isChunked  if <code>true</code> this encoder will chunk the base64 output into 76 character blocks
     * @return Base64-encoded data.
     * @throws IllegalArgumentException Thrown when the input array needs an output array bigger than {@link Integer#MAX_VALUE}
     */
    public static byte[] encode(byte[] binaryData, boolean isChunked) {
        long binaryDataLength = binaryData.length;
        long lengthDataBits = binaryDataLength * EIGHTBIT;
        long fewerThan24bits = lengthDataBits % TWENTYFOURBITGROUP;
        long tripletCount = lengthDataBits / TWENTYFOURBITGROUP;
        long encodedDataLengthLong;
        int chunckCount = 0;

        if (fewerThan24bits != 0) {
            // data not divisible by 24 bit
            encodedDataLengthLong = (tripletCount + 1) * 4;
        } else {
            // 16 or 8 bit
            encodedDataLengthLong = tripletCount * 4;
        }

        // If the output is to be "chunked" into 76 character sections,
        // for compliance with RFC 2045 MIME, then it is important to
        // allow for extra length to account for the separator(s)
        if (isChunked) {

            chunckCount = (CHUNK_SEPARATOR.length == 0 ? 0 : (int) Math
                    .ceil((float) encodedDataLengthLong / CHUNK_SIZE));
            encodedDataLengthLong += chunckCount * CHUNK_SEPARATOR.length;
        }

        if (encodedDataLengthLong > Integer.MAX_VALUE) {
            throw new IllegalArgumentException(
                    "Input array too big, output array would be bigger than Integer.MAX_VALUE=" + Integer.MAX_VALUE);
        }
        int encodedDataLength = (int) encodedDataLengthLong;
        byte encodedData[] = new byte[encodedDataLength];

        byte k, l, b1, b2, b3;

        int encodedIndex = 0;
        int dataIndex;
        int i;
        int nextSeparatorIndex = CHUNK_SIZE;
        int chunksSoFar = 0;

        // log.debug("number of triplets = " + numberTriplets);
        for (i = 0; i < tripletCount; i++) {
            dataIndex = i * 3;
            b1 = binaryData[dataIndex];
            b2 = binaryData[dataIndex + 1];
            b3 = binaryData[dataIndex + 2];

            // log.debug("b1= " + b1 +", b2= " + b2 + ", b3= " + b3);

            l = (byte) (b2 & 0x0f);
            k = (byte) (b1 & 0x03);

            byte val1 = ((b1 & SIGN) == 0) ? (byte) (b1 >> 2) : (byte) ((b1) >> 2 ^ 0xc0);
            byte val2 = ((b2 & SIGN) == 0) ? (byte) (b2 >> 4) : (byte) ((b2) >> 4 ^ 0xf0);
            byte val3 = ((b3 & SIGN) == 0) ? (byte) (b3 >> 6) : (byte) ((b3) >> 6 ^ 0xfc);

            encodedData[encodedIndex] = lookUpBase64Alphabet[val1];
            // log.debug( "val2 = " + val2 );
            // log.debug( "k4 = " + (k<<4) );
            // log.debug( "vak = " + (val2 | (k<<4)) );
            encodedData[encodedIndex + 1] = lookUpBase64Alphabet[val2 | (k << 4)];
            encodedData[encodedIndex + 2] = lookUpBase64Alphabet[(l << 2) | val3];
            encodedData[encodedIndex + 3] = lookUpBase64Alphabet[b3 & 0x3f];

            encodedIndex += 4;

            // If we are chunking, let's put a chunk separator down.
            if (isChunked) {
                // this assumes that CHUNK_SIZE % 4 == 0
                if (encodedIndex == nextSeparatorIndex) {
                    System.arraycopy(CHUNK_SEPARATOR, 0, encodedData, encodedIndex, CHUNK_SEPARATOR.length);
                    chunksSoFar++;
                    nextSeparatorIndex = (CHUNK_SIZE * (chunksSoFar + 1)) + (chunksSoFar * CHUNK_SEPARATOR.length);
                    encodedIndex += CHUNK_SEPARATOR.length;
                }
            }
        }

        // form integral number of 6-bit groups
        dataIndex = i * 3;

        if (fewerThan24bits == EIGHTBIT) {
            b1 = binaryData[dataIndex];
            k = (byte) (b1 & 0x03);
            // log.debug("b1=" + b1);
            // log.debug("b1<<2 = " + (b1>>2) );
            byte val1 = ((b1 & SIGN) == 0) ? (byte) (b1 >> 2) : (byte) ((b1) >> 2 ^ 0xc0);
            encodedData[encodedIndex] = lookUpBase64Alphabet[val1];
            encodedData[encodedIndex + 1] = lookUpBase64Alphabet[k << 4];
            encodedData[encodedIndex + 2] = PAD;
            encodedData[encodedIndex + 3] = PAD;
        } else if (fewerThan24bits == SIXTEENBIT) {

            b1 = binaryData[dataIndex];
            b2 = binaryData[dataIndex + 1];
            l = (byte) (b2 & 0x0f);
            k = (byte) (b1 & 0x03);

            byte val1 = ((b1 & SIGN) == 0) ? (byte) (b1 >> 2) : (byte) ((b1) >> 2 ^ 0xc0);
            byte val2 = ((b2 & SIGN) == 0) ? (byte) (b2 >> 4) : (byte) ((b2) >> 4 ^ 0xf0);

            encodedData[encodedIndex] = lookUpBase64Alphabet[val1];
            encodedData[encodedIndex + 1] = lookUpBase64Alphabet[val2 | (k << 4)];
            encodedData[encodedIndex + 2] = lookUpBase64Alphabet[l << 2];
            encodedData[encodedIndex + 3] = PAD;
        }

        if (isChunked) {
            // we also add a separator to the end of the final chunk.
            if (chunksSoFar < chunckCount) {
                System.arraycopy(CHUNK_SEPARATOR, 0, encodedData, encodedDataLength - CHUNK_SEPARATOR.length,
                        CHUNK_SEPARATOR.length);
            }
        }

        return encodedData;
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
     * Decodes Base64 data into octects
     *
     * @param base64Data Byte array containing Base64 data
     * @return Array containing decoded data.
     */
    public static byte[] decode(byte[] base64Data) {
        // RFC 2045 requires that we discard ALL non-Base64 characters
        base64Data = discardNonBase64(base64Data);

        // handle the edge case, so we don't have to worry about it later
        if (base64Data.length == 0) {
            return new byte[0];
        }

        int numberQuadruple = base64Data.length / FOURBYTE;
        byte decodedData[];
        byte b1, b2, b3, b4, marker0, marker1;

        // Throw away anything not in base64Data

        int encodedIndex = 0;
        int dataIndex;
        {
            // this sizes the output array properly - rlw
            int lastData = base64Data.length;
            // ignore the '=' padding
            while (base64Data[lastData - 1] == PAD) {
                if (--lastData == 0) {
                    return new byte[0];
                }
            }
            decodedData = new byte[lastData - numberQuadruple];
        }

        for (int i = 0; i < numberQuadruple; i++) {
            dataIndex = i * 4;
            marker0 = base64Data[dataIndex + 2];
            marker1 = base64Data[dataIndex + 3];

            b1 = base64Alphabet[base64Data[dataIndex]];
            b2 = base64Alphabet[base64Data[dataIndex + 1]];

            if (marker0 != PAD && marker1 != PAD) {
                // No PAD e.g 3cQl
                b3 = base64Alphabet[marker0];
                b4 = base64Alphabet[marker1];

                decodedData[encodedIndex] = (byte) (b1 << 2 | b2 >> 4);
                decodedData[encodedIndex + 1] = (byte) (((b2 & 0xf) << 4) | ((b3 >> 2) & 0xf));
                decodedData[encodedIndex + 2] = (byte) (b3 << 6 | b4);
            } else if (marker0 == PAD) {
                // Two PAD e.g. 3c[Pad][Pad]
                decodedData[encodedIndex] = (byte) (b1 << 2 | b2 >> 4);
            } else {
                // One PAD e.g. 3cQ[Pad]
                b3 = base64Alphabet[marker0];
                decodedData[encodedIndex] = (byte) (b1 << 2 | b2 >> 4);
                decodedData[encodedIndex + 1] = (byte) (((b2 & 0xf) << 4) | ((b3 >> 2) & 0xf));
            }
            encodedIndex += 3;
        }
        return decodedData;
    }

    /**
     * Discards any characters outside of the base64 alphabet, per the requirements on page 25 of RFC 2045 - "Any
     * characters outside of the base64 alphabet are to be ignored in base64 encoded data."
     *
     * @param data The base-64 encoded data to groom
     * @return The data, less non-base64 characters (see RFC 2045).
     */
    static byte[] discardNonBase64(byte[] data) {
        byte groomedData[] = new byte[data.length];
        int bytesCopied = 0;

        for (byte aByte : data) {
            if (isBase64(aByte)) {
                groomedData[bytesCopied++] = aByte;
            }
        }

        byte packedData[] = new byte[bytesCopied];

        System.arraycopy(groomedData, 0, packedData, 0, bytesCopied);

        return packedData;
    }

}
