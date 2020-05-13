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
 * A cipher <a href="http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation">mode of operation</a>
 * directs a cipher algorithm how to convert data during the encryption or decryption process.  This enum represents
 * all JDK-standard Cipher operation mode names as defined in
 * <a href="http://java.sun.com/javase/6/docs/technotes/guides/security/StandardNames.html">JDK Security Standard
 * Names</a>, as well as a few more that are well-known and supported by other JCA Providers.
 * <p/>
 * This {@code enum} exists to provide Shiro end-users type-safety when declaring an operation mode.  This helps reduce
 * error by providing a compile-time mechanism to specify a mode and guarantees a valid name that will be
 * recognized by an underlying JCA Provider.
 * <h2>Standard or Non-Standard?</h2>
 * All modes listed specify whether they are a JDK standard mode or a non-standard mode.  Standard modes are included
 * in all JDK distributions.  Non-standard modes can
 * sometimes result in better performance or more secure output, but may not be available on the target JDK
 * platform and rely on an external JCA Provider to be installed.  Some providers
 * (like <a href="http://www.bouncycastle.org">Bouncy Castle</a>) may support these modes however.
 *
 * @see <a href="http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation">Block Cipher Modes of Operation<a/>
 * @since 1.0
 */
public enum OperationMode {

    /**
     * <a href="http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation#Cipher-block_chaining_.28CBC.29">
     * Cipher-block Chaining</a> mode, defined in <a href="http://csrc.nist.gov/publications/fips/index.html">FIPS
     * PUB 81</a>.
     * <p/>
     * This is a standard JDK operation mode and should be supported by all JDK environments.
     */
    CBC,

    /**
     * <a href="http://en.wikipedia.org/wiki/CCM_mode">Counter with CBC-MAC</a> mode<b>*</b> - for block ciphers with
     * 128 bit block-size only. See <a href="http://www.ietf.org/rfc/rfc3610.txt">RFC 3610</a> for AES Ciphers.
     * This mode has essentially been replaced by the more-capable {@link #EAX EAX} mode.
     * <p/>
     * <b>*THIS IS A NON-STANDARD MODE</b>. It is not guaranteed to be supported across JDK installations.  You must
     * ensure you have a JCA Provider that can support this cipher operation mode.
     * <a href="http://www.bouncycastle.org">Bouncy Castle</a> <em>may</em> be one such provider.
     */
    CCM,

    /**
     * <a href="http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation#Cipher_feedback_.28CFB.29">Cipher
     * Feedback<a/> mode, defined in <a href="http://csrc.nist.gov/publications/fips/index.html">FIPS PUB 81</a>.
     * <p/>
     * This is a standard JDK operation mode and should be supported by all JDK environments.
     */
    CFB,

    /**
     * <a href="http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation#Counter_.28CTR.29">Counter Mode</a>, aka
     * Integer Counter Mode (ICM) and Segmented Integer Counter (SIC).  Counter is a simplification of {@link #OFB OFB}
     * and updates the input block as a counter.
     * <p/>
     * This is a standard JDK operation mode and should be supported by all JDK environments.
     */
    CTR,

    /**
     * <a href="http://en.wikipedia.org/wiki/EAX_mode">EAX Mode</a><b>*</b>.  This is a patent-free but less-effecient
     * alternative to {@link #OCB OCB} and has capabilities beyond what {@link #CCM CCM} can provide.
     * <p/>
     * <b>*THIS IS A NON-STANDARD MODE</b>. It is not guaranteed to be supported across JDK installations.  You must
     * ensure you have a JCA Provider that can support this cipher operation mode.
     * <a href="http://www.bouncycastle.org">Bouncy Castle</a> <em>may</em> be one such provider.
     */
    EAX,

    /**
     * <a href="http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation#Electronic_codebook_.28ECB.29">Electronic
     * Codebook</a> mode, defined in <a href="http://csrc.nist.gov/publications/fips/index.html">FIPS PUB 81</a>.
     * ECB is the only mode that does <em>not</em> require an Initialization Vector, but because of this, can be seen
     * as less secure than operation modes that require an IV.
     * <p/>
     * This is a standard JDK operation mode and should be supported by all JDK environments.
     */
    ECB,

    /**
     * <a href="http://en.wikipedia.org/wiki/GCM_mode">Galois/Counter</a> mode<b>*</b> - for block ciphers with 128
     * bit block-size only.
     * <p/>
     * <b>*THIS IS A NON-STANDARD MODE</b>. It is not guaranteed to be supported across JDK installations.  You must
     * ensure you have a JCA Provider that can support this cipher operation mode.
     * <a href="http://www.bouncycastle.org">Bouncy Castle</a> <em>may</em> be one such provider.
     */
    GCM,

    /**
     * No mode.
     * <p/>
     * This is a standard JDK operation mode and should be supported by all JDK environments.
     */
    NONE,

    /**
     * <a href="http://en.wikipedia.org/wiki/OCB_mode">Offset Codebook</a> mode<b>*</b>.  Parallel mode that provides
     * both message privacy and authenticity in a single pass.  This is a very efficient mode, but is patent-encumbered.
     * A less-efficient (two pass) alternative is available by using {@link #EAX EAX} mode.
     * <p/>
     * <b>*THIS IS A NON-STANDARD MODE</b>. It is not guaranteed to be supported across JDK installations.  You must
     * ensure you have a JCA Provider that can support this cipher operation mode.
     * <a href="http://www.bouncycastle.org">Bouncy Castle</a> <em>may</em> be one such provider.
     */
    OCB,

    /**
     * <a href="http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation#Output_feedback_.28OFB.29">Output
     * Feedback</a> mode, defined in <a href="http://csrc.nist.gov/publications/fips/index.html">FIPS PUB 81</a>.
     * <p/>
     * This is a standard JDK operation mode and should be supported by all JDK environments.
     */
    OFB,

    /**
     * <a href="http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation#Propagating_cipher-block_chaining_.28PCBC.29">
     * Propagating Cipher Block Chaining</a> mode, defined in <a href="http://web.mit.edu/kerberos/">Kerberos version 4<a/>.
     * <p/>
     * This is a standard JDK operation mode and should be supported by all JDK environments.
     */
    PCBC
}
