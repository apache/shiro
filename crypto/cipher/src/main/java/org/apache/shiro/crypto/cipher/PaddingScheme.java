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
package org.apache.shiro.crypto.cipher;

/**
 * A {@code CipherPaddingScheme} represents well-known
 * <a href="http://en.wikipedia.org/wiki/Padding_(cryptography)">padding schemes</a> supported by JPA providers in a
 * type-safe manner.
 * <p/>
 * When encrypted data is transferred, it is usually desirable to ensure that all 'chunks' transferred are a fixed-length:
 * different length blocks might give cryptanalysts clues about what the data might be, among other reasons.  Of course
 * not all data will convert to neat fixed-length blocks, so padding schemes are used to 'fill in' (pad) any remaining
 * space with unintelligible data.
 * <p/>
 * Padding schemes can be used in both asymmetric key ciphers as well as symmetric key ciphers (e.g. block ciphers).
 * Block-ciphers especially regularly use padding schemes as they are based on the notion of fixed-length block sizes.
 *
 * @see <a href="http://en.wikipedia.org/wiki/Padding_(cryptography)">Wikipedia: Cryptographic Padding</a>
 * @since 1.0
 */
public enum PaddingScheme {

    /**
     * No padding.  Useful when the block size is 8 bits for block cipher streaming operations. (Because
     * a byte is the most primitive block size, there is nothing to pad).
     */
    NONE("NoPadding"),

    /**
     * Padding scheme as defined in the W3C's &quot;XML Encryption Syntax and Processing&quot; document,
     * <a href="http://www.w3.org/TR/xmlenc-core/#sec-Alg-Block">Section 5.2 - Block Encryption Algorithms</a>.
     */
    ISO10126("ISO10126Padding"),

    /**
     * Optimal Asymmetric Encryption Padding defined in RSA's <a href="http://en.wikipedia.org/wiki/PKCS1">PKSC#1
     * standard</a> (aka <a href="http://tools.ietf.org/html/rfc3447">RFC 3447</a>).
     * <p/>
     * <b>NOTE:</b> using this padding requires initializing {@link javax.crypto.Cipher Cipher} instances with a
     * {@link javax.crypto.spec.OAEPParameterSpec OAEPParameterSpec} object which provides the 1) message digest and
     * 2) mask generation function to use for the scheme.
     * <h3>Convenient Alternatives</h3>
     * While using this scheme enables you full customization of the message digest + mask generation function
     * combination, it does require the extra burden of providing your own {@code OAEPParameterSpec} object.  This is
     * often unnecessary, because most combinations are fairly standard.  These common combinations are pre-defined
     * in this enum in the {@code OAEP}* variants.
     * <p/>
     * If you find that these common combinations still do not meet your needs, then you will need to
     * specify your own message digest and mask generation function, either as an {@code OAEPParameterSpec} object
     * during Cipher initialization or, maybe more easily, in the scheme name directly.  If you want to use scheme name
     * approach, the name format is specified in the
     * <a href="http://java.sun.com/javase/6/docs/technotes/guides/security/StandardNames.html">Standard Names</a>
     * document in the <code>Cipher Algorithm Padding</code> section.
     *
     * @see #OAEPWithMd5AndMgf1
     * @see #OAEPWithSha1AndMgf1
     * @see #OAEPWithSha256AndMgf1
     * @see #OAEPWithSha384AndMgf1
     * @see #OAEPWithSha512AndMgf1
     */
    OAEP("OAEPPadding"),

    /**
     * Optimal Asymmetric Encryption Padding with {@code MD5} message digest and {@code MGF1} mask generation function.
     * <p/>
     * This is a convenient pre-defined OAEP padding scheme that embeds the message digest and mask generation function.
     * When using this padding scheme, there is no need to init the {@code Cipher} instance with an
     * {@link javax.crypto.spec.OAEPParameterSpec OAEPParameterSpec} object, as it is already 'built in' to the scheme
     * name (unlike the {@link #OAEP OAEP} scheme, which requires a bit more work).
     */
    OAEPWithMd5AndMgf1("OAEPWithMD5AndMGF1Padding"),

    /**
     * Optimal Asymmetric Encryption Padding with {@code SHA-1} message digest and {@code MGF1} mask generation function.
     * <p/>
     * This is a convenient pre-defined OAEP padding scheme that embeds the message digest and mask generation function.
     * When using this padding scheme, there is no need to init the {@code Cipher} instance with an
     * {@link javax.crypto.spec.OAEPParameterSpec OAEPParameterSpec} object, as it is already 'built in' to the scheme
     * name (unlike the {@link #OAEP OAEP} scheme, which requires a bit more work).
     */
    OAEPWithSha1AndMgf1("OAEPWithSHA-1AndMGF1Padding"),

    /**
     * Optimal Asymmetric Encryption Padding with {@code SHA-256} message digest and {@code MGF1} mask generation function.
     * <p/>
     * This is a convenient pre-defined OAEP padding scheme that embeds the message digest and mask generation function.
     * When using this padding scheme, there is no need to init the {@code Cipher} instance with an
     * {@link javax.crypto.spec.OAEPParameterSpec OAEPParameterSpec} object, as it is already 'built in' to the scheme
     * name (unlike the {@link #OAEP OAEP} scheme, which requires a bit more work).
     */
    OAEPWithSha256AndMgf1("OAEPWithSHA-256AndMGF1Padding"),

    /**
     * Optimal Asymmetric Encryption Padding with {@code SHA-384} message digest and {@code MGF1} mask generation function.
     * <p/>
     * This is a convenient pre-defined OAEP padding scheme that embeds the message digest and mask generation function.
     * When using this padding scheme, there is no need to init the {@code Cipher} instance with an
     * {@link javax.crypto.spec.OAEPParameterSpec OAEPParameterSpec} object, as it is already 'built in' to the scheme
     * name (unlike the {@link #OAEP OAEP} scheme, which requires a bit more work).
     */
    OAEPWithSha384AndMgf1("OAEPWithSHA-384AndMGF1Padding"),

    /**
     * Optimal Asymmetric Encryption Padding with {@code SHA-512} message digest and {@code MGF1} mask generation function.
     * <p/>
     * This is a convenient pre-defined OAEP padding scheme that embeds the message digest and mask generation function.
     * When using this padding scheme, there is no need to init the {@code Cipher} instance with an
     * {@link javax.crypto.spec.OAEPParameterSpec OAEPParameterSpec} object, as it is already 'built in' to the scheme
     * name (unlike the {@link #OAEP OAEP} scheme, which requires a bit more work).
     */
    OAEPWithSha512AndMgf1("OAEPWithSHA-512AndMGF1Padding"),

    /**
     * Padding scheme used with the {@code RSA} algorithm defined in RSA's
     * <a href="http://en.wikipedia.org/wiki/PKCS1">PKSC#1 standard</a> (aka
     * <a href="http://tools.ietf.org/html/rfc3447">RFC 3447</a>).
     */
    PKCS1("PKCS1Padding"),

    /**
     * Padding scheme defined in RSA's <a href="http://www.rsa.com/rsalabs/node.asp?id=2127">Password-Based
     * Cryptography Standard</a>.
     */
    PKCS5("PKCS5Padding"),

    /**
     * Padding scheme defined in the <a href="http://www.mozilla.org/projects/security/pki/nss/ssl/draft302.txt">SSL
     * 3.0 specification</a>, section <code>5.2.3.2 (CBC block cipher)</code>.
     */
    SSL3("SSL3Padding");

    private final String transformationName;

    private PaddingScheme(String transformationName) {
        this.transformationName = transformationName;
    }

    /**
     * Returns the actual string name to use when building the {@link javax.crypto.Cipher Cipher}
     * {@code transformation string}.
     *
     * @return the actual string name to use when building the {@link javax.crypto.Cipher Cipher}
     *         {@code transformation string}.
     * @see javax.crypto.Cipher#getInstance(String)
     */
    public String getTransformationName() {
        return this.transformationName;
    }
}
