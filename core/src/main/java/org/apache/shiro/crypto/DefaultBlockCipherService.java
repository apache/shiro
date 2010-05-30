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
package org.apache.shiro.crypto;

import org.apache.shiro.util.StringUtils;

/**
 * Base abstract class for block cipher algorithms.
 *
 * <h2>Usage</h2>
 * Note that this class exists mostly to simplify algorithm-specific subclasses.  Unless you understand the concepts of
 * cipher modes of operation, block sizes, and padding schemes, and you want direct control of these things, you should
 * typically not uses instances of this class directly.  Instead, algorithm-specific subclasses, such as
 * {@link AesCipherService}, {@link BlowfishCipherService}, and others are usually better suited for regular use.
 * <p/>
 * However, if you have the need to create a custom block cipher service where no sufficient algorithm-specific subclass
 * exists in Shiro, this class would be very useful.
 *
 * <h2>Configuration</h2>
 * Block ciphers can accept configuration parameters that direct how they operate.  These parameters concatenated
 * together in a single String comprise what the JDK JCA documentation calls a
 * <a href="http://java.sun.com/javase/6/docs/technotes/guides/security/crypto/CryptoSpec.html#trans">transformation
 * string</a>.  We think that it is better for Shiro to construct this transformation string automatically based on its
 * constituent parts instead of having the end-user construct the string manually, which may be error prone or
 * confusing.  To that end, Shiro {@link DefaultBlockCipherService}s have attributes that can be set individually in
 * a type-safe manner based on your configuration needs, and Shiro will build the transformation string for you.
 * <p/>
 * The following sections typically document the configuration options for block (byte array)
 * {@link #encrypt(byte[], byte[])} and {@link #decrypt(byte[], byte[])} method invocations.  Streaming configuration
 * for those same attributes are done via mirrored {@code streaming}* attributes, and their purpose is identical, but
 * they're only used during streaming {@link #encrypt(java.io.InputStream, java.io.OutputStream, byte[])} and
 * {@link #decrypt(java.io.InputStream, java.io.OutputStream, byte[])} methods.  See the &quot;Streaming&quot;
 * section below for more.
 *
 * <h3>Block Size</h3>
 * The block size specifies the number of bits (not bytes) that the cipher operates on when performing an operation.
 * It can be specified explicitly via the {@link #setBlockSize blockSize} attribute.  If not set, the JCA Provider
 * default will be used based on the cipher algorithm.  Block sizes are usually very algorithm specific, so set this
 * value only if you know you don't want the JCA Provider's default for the desired algorithm.  For example, the
 * AES algorithm's Rijndael implementation <em>only</em> supports a 128 bit block size and will not work with any other
 * size.
 * <p/>
 * Also note that the {@link #setInitializationVectorSize initializationVectorSize} is usually the same as the
 * {@link #setBlockSize blockSize} in block ciphers.  If you change either attribute, you should ensure that the other
 * attribute is correct for the target cipher algorithm.
 *
 * <h3>Operation Mode</h3>
 * You may set the block cipher's<a href="http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation">mode of
 * operation</a> via the {@link #setMode(OperationMode) mode} attribute, which accepts a type-safe
 * {@link OperationMode OperationMode} enum instance.  This type safety helps avoid typos when specifying the mode and
 * guarantees that the mode name will be recognized by the underlying JCA Provider.
 * <p/>
 * <b>*</b>If no operation mode is specified, Shiro defaults all of its block {@code CipherService} instances to the
 * {@link OperationMode#CFB CFB} mode, specifically to support auto-generation of initialization vectors during
 * encryption.  This is different than the JDK's default {@link OperationMode#ECB ECB} mode because {@code ECB} does
 * not support initialization vectors, which are necessary for strong encryption.  See  the
 * {@link org.apache.shiro.crypto.JcaCipherService JcaCipherService parent class} class JavaDoc for an extensive
 * explanation on why we do this and why we do not use the Sun {@code ECB} default.  You also might also want read
 * the <a href="http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation#Electronic_codebook_.28ECB.29">Wikipedia
 * section on ECB<a/> and look at the encrypted image to see an example of why {@code ECB} should not be used in
 * security-sensitive environments.
 * <p/>
 * In the rare case that you need to override the default with a mode not represented
 * by the {@link OperationMode} enum, you may specify the raw mode name string that will be recognized by your JCA
 * provider via the {@link #setModeName modeName} attribute.  Because this is not type-safe, it is recommended only to
 * use this attribute if the {@link OperationMode} enum does not represent your desired mode.
 * <p/>
 * <b>NOTE:</b> If you change the mode to one that does not support initialization vectors (such as
 * {@link OperationMode#ECB ECB} or {@link OperationMode#NONE NONE}), you <em>must</em> turn off auto-generated
 * initialization vectors by setting {@link #setGenerateInitializationVectors(boolean) generateInitializationVectors}
 * to {@code false}.  Abandoning initialization vectors significantly weakens encryption, so think twice before
 * disabling this feature.
 *
 * <h3>Padding Scheme</h3>
 * Because block ciphers process messages in fixed-length blocks, if the final block in a message is not equal to the
 * block length, <a href="http://en.wikipedia.org/wiki/Padding_(cryptography)">padding</a> is applied to match that
 * size to maintain the total length of the message.  This is good because it protects data patterns from being
 * identified  - when all chunks look the same length, it is much harder to infer what that data might be.
 * <p/>
 * You may set a padding scheme via the {@link #setPaddingScheme(PaddingScheme) paddingScheme} attribute, which
 * accepts a type-safe {@link PaddingScheme PaddingScheme} enum instance.  Like the {@link OperationMode} enum,
 * this enum offers type safety to help avoid typos and guarantees that the mode will be recongized by the underlying
 * JCA provider.
 * <p/>
 * <b>*</b>If no padding scheme is specified, this class defaults to the {@link PaddingScheme#PKCS5} scheme, specifically
 * to be compliant with the default behavior of auto-generating initialization vectors during encryption (see the
 * {@link org.apache.shiro.crypto.JcaCipherService JcaCipherService parent class} class JavaDoc for why).
 * <p/>
 * In the rare case that you need to override the default with a scheme not represented by the {@link PaddingScheme}
 * enum, you may specify the raw padding scheme name string that will be recognized by your JCA provider via the
 * {@link #setPaddingScheme paddingSchemeName} attribute.  Because this is not type-safe, it is recommended only to
 * use this attribute if the {@link PaddingScheme} enum does not represent your desired scheme.
 *
 * <h2>Streaming</h2>
 * Most people don't think of using block ciphers as stream ciphers, since their name implies working
 * with block data (i.e. byte arrays) only.  However, block ciphers can be turned into byte-oriented stream ciphers by
 * using an appropriate {@link OperationMode operation mode} with a {@link #getStreamingBlockSize() streaming block size}
 * of 8 bits.  This is why the {@link CipherService} interface provides both block and streaming operations.
 * <p/>
 * Because this streaming 8-bit block size rarely changes across block-cipher algorithms, default values have been set
 * for all three streaming configuration parameters.  The defaults are:
 * <ul>
 * <li>{@link #setStreamingBlockSize(int) streamingBlockSize} = {@code 8} (bits)</li>
 * <li>{@link #setStreamingMode streamingMode} = {@link OperationMode#CFB CFB}</li>
 * <li>{@link #setStreamingPaddingScheme(PaddingScheme) streamingPaddingScheme} = {@link PaddingScheme#NONE none} (since
 * the block size is already the most atomic size of a single byte)</li>
 * </ul>
 * <p/>
 * These attributes have the same meaning as the {@code mode}, {@code blockSize}, and {@code paddingScheme} attributes
 * described above, but they are applied during streaming method invocations only ({@link #encrypt(java.io.InputStream, java.io.OutputStream, byte[])}
 * and {@link #decrypt(java.io.InputStream, java.io.OutputStream, byte[])}).
 *
 * @see BlowfishCipherService
 * @see AesCipherService
 * @see <a href="http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation">Wikipedia: Block Cipher Modes of Operation</a>
 * @since 1.0
 */
public class DefaultBlockCipherService extends AbstractSymmetricCipherService {

    private static final int DEFAULT_BLOCK_SIZE = 0;

    private static final String TRANSFORMATION_STRING_DELIMITER = "/";
    private static final int DEFAULT_STREAMING_BLOCK_SIZE = 8; //8 bits (1 byte)

    private String modeName;
    private int blockSize; //size in bits (not bytes) - i.e. a blockSize of 8 equals 1 byte. negative or zero value = use system default
    private String paddingSchemeName;

    private String streamingModeName;
    private int streamingBlockSize;
    private String streamingPaddingSchemeName;

    private String transformationString; //cached value - rebuilt whenever any of its constituent parts change
    private String streamingTransformationString; //cached value - rebuilt whenever any of its constituent parts change


    /**
     * Creates a new {@link DefaultBlockCipherService} using the specified block cipher {@code algorithmName}.  Per this
     * class's JavaDoc, this constructor also sets the following defaults:
     * <ul>
     * <li>{@code streamingMode} = {@link OperationMode#CFB CFB}</li>
     * <li>{@code streamingPaddingScheme} = {@link PaddingScheme#NONE none}</li>
     * <li>{@code streamingBlockSize} = 8</li>
     * </ul>
     * All other attributes are null/unset, indicating the JCA Provider defaults will be used.
     *
     * @param algorithmName the block cipher algorithm to use when encrypting and decrypting
     */
    public DefaultBlockCipherService(String algorithmName) {
        super(algorithmName);

        this.modeName = OperationMode.CFB.name();
        this.paddingSchemeName = PaddingScheme.PKCS5.getTransformationName();
        this.blockSize = DEFAULT_BLOCK_SIZE; //0 = use the JCA provider's default

        this.streamingModeName = OperationMode.CFB.name();
        this.streamingPaddingSchemeName = PaddingScheme.NONE.getTransformationName();
        this.streamingBlockSize = DEFAULT_STREAMING_BLOCK_SIZE;
    }

    /**
     * Returns the cipher operation mode name (as a String) to be used when constructing
     * {@link javax.crypto.Cipher Cipher} transformation string or {@code null} if the JCA Provider default mode for
     * the specified {@link #getAlgorithmName() algorithm} should be used.
     * <p/>
     * This attribute is used <em>only</em> when constructing the transformation string for block (byte array)
     * operations ({@link #encrypt(byte[], byte[])} and {@link #decrypt(byte[], byte[])}).  The
     * {@link #getStreamingModeName() streamingModeName} attribute is used when the block cipher is used for
     * streaming operations.
     * <p/>
     * The default value is {@code null} to retain the JCA Provider default.
     *
     * @return the cipher operation mode name (as a String) to be used when constructing the
     *         {@link javax.crypto.Cipher Cipher} transformation string, or {@code null} if the JCA Provider default
     *         mode for the specified {@link #getAlgorithmName() algorithm} should be used.
     */
    public String getModeName() {
        return modeName;
    }

    /**
     * Sets the cipher operation mode name to be used when constructing the
     * {@link javax.crypto.Cipher Cipher} transformation string.  A {@code null} value indicates that the JCA Provider
     * default mode for the specified {@link #getAlgorithmName() algorithm} should be used.
     * <p/>
     * This attribute is used <em>only</em> when constructing the transformation string for block (byte array)
     * operations ({@link #encrypt(byte[], byte[])} and {@link #decrypt(byte[], byte[])}).  The
     * {@link #getStreamingModeName() streamingModeName} attribute is used when the block cipher is used for
     * streaming operations.
     * <p/>
     * The default value is {@code null} to retain the JCA Provider default.
     * <p/>
     * <b>NOTE:</b> most standard mode names are represented by the {@link OperationMode OperationMode} enum.  That enum
     * should be used with the {@link #setMode mode} attribute when possible to retain type-safety and reduce the
     * possibility of errors.  This method is better used if the {@link OperationMode} enum does not represent the
     * necessary mode.
     *
     * @param modeName the cipher operation mode name to be used when constructing
     *                 {@link javax.crypto.Cipher Cipher} transformation string, or {@code null} if the JCA Provider
     *                 default mode for the specified {@link #getAlgorithmName() algorithm} should be used.
     * @see #setMode
     */
    public void setModeName(String modeName) {
        this.modeName = modeName;
        //clear out the transformation string so the next invocation will rebuild it with the new mode:
        this.transformationString = null;
    }

    /**
     * Sets the cipher operation mode of operation to be used when constructing the
     * {@link javax.crypto.Cipher Cipher} transformation string.  A {@code null} value indicates that the JCA Provider
     * default mode for the specified {@link #getAlgorithmName() algorithm} should be used.
     * <p/>
     * This attribute is used <em>only</em> when constructing the transformation string for block (byte array)
     * operations ({@link #encrypt(byte[], byte[])} and {@link #decrypt(byte[], byte[])}).  The
     * {@link #setStreamingMode streamingMode} attribute is used when the block cipher is used for
     * streaming operations.
     * <p/>
     * If the {@link OperationMode} enum cannot represent your desired mode, you can set the name explicitly
     * via the {@link #setModeName modeName} attribute directly.  However, because {@link OperationMode} represents all
     * standard JDK mode names already, ensure that your underlying JCA Provider supports the non-standard name first.
     *
     * @param mode the cipher operation mode to be used when constructing
     *             {@link javax.crypto.Cipher Cipher} transformation string, or {@code null} if the JCA Provider
     *             default mode for the specified {@link #getAlgorithmName() algorithm} should be used.
     */
    public void setMode(OperationMode mode) {
        setModeName(mode.name());
    }

    /**
     * Returns the cipher algorithm padding scheme name (as a String) to be used when constructing
     * {@link javax.crypto.Cipher Cipher} transformation string or {@code null} if the JCA Provider default mode for
     * the specified {@link #getAlgorithmName() algorithm} should be used.
     * <p/>
     * This attribute is used <em>only</em> when constructing the transformation string for block (byte array)
     * operations ({@link #encrypt(byte[], byte[])} and {@link #decrypt(byte[], byte[])}).  The
     * {@link #getStreamingPaddingSchemeName() streamingPaddingSchemeName} attribute is used when the block cipher is
     * used for streaming operations.
     * <p/>
     * The default value is {@code null} to retain the JCA Provider default.
     *
     * @return the padding scheme name (as a String) to be used when constructing the
     *         {@link javax.crypto.Cipher Cipher} transformation string, or {@code null} if the JCA Provider default
     *         padding scheme for the specified {@link #getAlgorithmName() algorithm} should be used.
     */
    public String getPaddingSchemeName() {
        return paddingSchemeName;
    }

    /**
     * Sets the padding scheme name to be used when constructing the
     * {@link javax.crypto.Cipher Cipher} transformation string, or {@code null} if the JCA Provider default mode for
     * the specified {@link #getAlgorithmName() algorithm} should be used.
     * <p/>
     * This attribute is used <em>only</em> when constructing the transformation string for block (byte array)
     * operations ({@link #encrypt(byte[], byte[])} and {@link #decrypt(byte[], byte[])}).  The
     * {@link #getStreamingPaddingSchemeName() streamingPaddingSchemeName} attribute is used when the block cipher is
     * used for streaming operations.
     * <p/>
     * The default value is {@code null} to retain the JCA Provider default.
     * <p/>
     * <b>NOTE:</b> most standard padding schemes are represented by the {@link PaddingScheme PaddingScheme} enum.
     * That enum should be used with the {@link #setPaddingScheme paddingScheme} attribute when possible to retain
     * type-safety and reduce the possibility of errors.  Calling this method however is suitable if the
     * {@code PaddingScheme} enum does not represent the desired scheme.
     *
     * @param paddingSchemeName the padding scheme name to be used when constructing
     *                          {@link javax.crypto.Cipher Cipher} transformation string, or {@code null} if the JCA
     *                          Provider default padding scheme for the specified {@link #getAlgorithmName() algorithm}
     *                          should be used.
     * @see #setPaddingScheme
     */
    public void setPaddingSchemeName(String paddingSchemeName) {
        this.paddingSchemeName = paddingSchemeName;
        //clear out the transformation string so the next invocation will rebuild it with the new padding scheme:
        this.transformationString = null;
    }

    /**
     * Sets the padding scheme to be used when constructing the
     * {@link javax.crypto.Cipher Cipher} transformation string. A {@code null} value indicates that the JCA Provider
     * default padding scheme for the specified {@link #getAlgorithmName() algorithm} should be used.
     * <p/>
     * This attribute is used <em>only</em> when constructing the transformation string for block (byte array)
     * operations ({@link #encrypt(byte[], byte[])} and {@link #decrypt(byte[], byte[])}).  The
     * {@link #setStreamingPaddingScheme streamingPaddingScheme} attribute is used when the block cipher is used for
     * streaming operations.
     * <p/>
     * If the {@link PaddingScheme PaddingScheme} enum does represent your desired scheme, you can set the name explicitly
     * via the {@link #setPaddingSchemeName paddingSchemeName} attribute directly.  However, because
     * {@code PaddingScheme} represents all standard JDK scheme names already, ensure that your underlying JCA Provider
     * supports the non-standard name first.
     *
     * @param paddingScheme the padding scheme to be used when constructing
     *                      {@link javax.crypto.Cipher Cipher} transformation string, or {@code null} if the JCA Provider
     *                      default padding scheme for the specified {@link #getAlgorithmName() algorithm} should be used.
     */
    public void setPaddingScheme(PaddingScheme paddingScheme) {
        setPaddingSchemeName(paddingScheme.getTransformationName());
    }

    /**
     * Returns the block cipher's block size to be used when constructing
     * {@link javax.crypto.Cipher Cipher} transformation string or {@code 0} if the JCA Provider default block size
     * for the specified {@link #getAlgorithmName() algorithm} should be used.
     * <p/>
     * This attribute is used <em>only</em> when constructing the transformation string for block (byte array)
     * operations ({@link #encrypt(byte[], byte[])} and {@link #decrypt(byte[], byte[])}).  The
     * {@link #getStreamingBlockSize() streamingBlockSize} attribute is used when the block cipher is used for
     * streaming operations.
     * <p/>
     * The default value is {@code 0} which retains the JCA Provider default.
     *
     * @return the block cipher block size to be used when constructing the
     *         {@link javax.crypto.Cipher Cipher} transformation string, or {@code 0} if the JCA Provider default
     *         block size for the specified {@link #getAlgorithmName() algorithm} should be used.
     */
    public int getBlockSize() {
        return blockSize;
    }

    /**
     * Sets the block cipher's block size to be used when constructing
     * {@link javax.crypto.Cipher Cipher} transformation string.  {@code 0} indicates that the JCA Provider default
     * block size for the specified {@link #getAlgorithmName() algorithm} should be used.
     * <p/>
     * This attribute is used <em>only</em> when constructing the transformation string for block (byte array)
     * operations ({@link #encrypt(byte[], byte[])} and {@link #decrypt(byte[], byte[])}).  The
     * {@link #getStreamingBlockSize() streamingBlockSize} attribute is used when the block cipher is used for
     * streaming operations.
     * <p/>
     * The default value is {@code 0} which retains the JCA Provider default.
     * <p/>
     * <b>NOTE:</b> block cipher block sizes are very algorithm-specific.  If you change this value, ensure that it
     * will work with the specified {@link #getAlgorithmName() algorithm}.
     *
     * @param blockSize the block cipher block size to be used when constructing the
     *                  {@link javax.crypto.Cipher Cipher} transformation string, or {@code 0} if the JCA Provider
     *                  default block size for the specified {@link #getAlgorithmName() algorithm} should be used.
     */
    public void setBlockSize(int blockSize) {
        this.blockSize = Math.max(DEFAULT_BLOCK_SIZE, blockSize);
        //clear out the transformation string so the next invocation will rebuild it with the new block size:
        this.transformationString = null;
    }

    /**
     * Same purpose as the {@link #getModeName modeName} attribute, but is used instead only for for streaming
     * operations ({@link #encrypt(java.io.InputStream, java.io.OutputStream, byte[])} and
     * {@link #decrypt(java.io.InputStream, java.io.OutputStream, byte[])}).
     * <p/>
     * Note that unlike the {@link #getModeName modeName} attribute, the default value of this attribute is not
     * {@code null} - it is {@link OperationMode#CFB CFB} for reasons described in the class-level JavaDoc in the
     * {@code Streaming} section.
     *
     * @return the transformation string mode name to be used for streaming operations only.
     */
    public String getStreamingModeName() {
        return streamingModeName;
    }

    private boolean isModeStreamingCompatible(String modeName) {
        return modeName != null &&
                !modeName.equalsIgnoreCase(OperationMode.ECB.name()) &&
                !modeName.equalsIgnoreCase(OperationMode.NONE.name());
    }

    /**
     * Sets the transformation string mode name to be used for streaming operations only.  The default value is
     * {@link OperationMode#CFB CFB} for reasons described in the class-level JavaDoc in the {@code Streaming} section.
     *
     * @param streamingModeName transformation string mode name to be used for streaming operations only
     */
    public void setStreamingModeName(String streamingModeName) {
        if (!isModeStreamingCompatible(streamingModeName)) {
            String msg = "mode [" + streamingModeName + "] is not a valid operation mode for block cipher streaming.";
            throw new IllegalArgumentException(msg);
        }
        this.streamingModeName = streamingModeName;
        //clear out the streaming transformation string so the next invocation will rebuild it with the new mode:
        this.streamingTransformationString = null;
    }

    /**
     * Sets the transformation string mode to be used for streaming operations only.  The default value is
     * {@link OperationMode#CFB CFB} for reasons described in the class-level JavaDoc in the {@code Streaming} section.
     *
     * @param mode the transformation string mode to be used for streaming operations only
     */
    public void setStreamingMode(OperationMode mode) {
        setStreamingModeName(mode.name());
    }

    public String getStreamingPaddingSchemeName() {
        return streamingPaddingSchemeName;
    }

    public void setStreamingPaddingSchemeName(String streamingPaddingSchemeName) {
        this.streamingPaddingSchemeName = streamingPaddingSchemeName;
        //clear out the streaming transformation string so the next invocation will rebuild it with the new scheme:
        this.streamingTransformationString = null;
    }

    public void setStreamingPaddingScheme(PaddingScheme scheme) {
        setStreamingPaddingSchemeName(scheme.getTransformationName());
    }

    public int getStreamingBlockSize() {
        return streamingBlockSize;
    }

    public void setStreamingBlockSize(int streamingBlockSize) {
        this.streamingBlockSize = Math.max(DEFAULT_BLOCK_SIZE, streamingBlockSize);
        //clear out the streaming transformation string so the next invocation will rebuild it with the new block size:
        this.streamingTransformationString = null;
    }

    /**
     * Returns the transformation string to use with the {@link javax.crypto.Cipher#getInstance} call.  If
     * {@code streaming} is {@code true}, a block-cipher transformation string compatible with streaming operations will
     * be constructed and cached for re-use later (see the class-level JavaDoc for more on using block ciphers
     * for streaming).  If {@code streaming} is {@code false} a normal block-cipher transformation string will
     * be constructed and cached for later re-use.
     *
     * @param streaming if the transformation string is going to be used for a Cipher performing stream-based encryption or not.
     * @return the transformation string
     */
    protected String getTransformationString(boolean streaming) {
        if (streaming) {
            if (this.streamingTransformationString == null) {
                this.streamingTransformationString = buildStreamingTransformationString();
            }
            return this.streamingTransformationString;
        } else {
            if (this.transformationString == null) {
                this.transformationString = buildTransformationString();
            }
            return this.transformationString;
        }
    }

    private String buildTransformationString() {
        return buildTransformationString(getModeName(), getPaddingSchemeName(), getBlockSize());
    }

    private String buildStreamingTransformationString() {
        return buildTransformationString(getStreamingModeName(), getStreamingPaddingSchemeName(), getStreamingBlockSize());
    }

    private String buildTransformationString(String modeName, String paddingSchemeName, int blockSize) {
        StringBuilder sb = new StringBuilder(getAlgorithmName());
        if (StringUtils.hasText(modeName)) {
            sb.append(TRANSFORMATION_STRING_DELIMITER).append(modeName);
        }
        if (blockSize > 0) {
            sb.append(blockSize);
        }
        if (StringUtils.hasText(paddingSchemeName)) {
            sb.append(TRANSFORMATION_STRING_DELIMITER).append(paddingSchemeName);
        }
        return sb.toString();
    }

    /**
     * Returns {@code true} if the specified cipher operation mode name supports initialization vectors,
     * {@code false} otherwise.
     *
     * @param modeName the raw text name of the mode of operation
     * @return {@code true} if the specified cipher operation mode name supports initialization vectors,
     *         {@code false} otherwise.
     */
    private boolean isModeInitializationVectorCompatible(String modeName) {
        return modeName != null &&
                !modeName.equalsIgnoreCase(OperationMode.ECB.name()) &&
                !modeName.equalsIgnoreCase(OperationMode.NONE.name());
    }

    /**
     * Overrides the parent implementation to ensure initialization vectors are always generated if streaming is
     * enabled (block ciphers <em>must</em> use initialization vectors if they are to be used as a stream cipher).  If
     * not being used as a stream cipher, then the value is computed based on whether or not the currently configured
     * {@link #getModeName modeName} is compatible with initialization vectors as well as the result of the configured
     * {@link #setGenerateInitializationVectors(boolean) generateInitializationVectors} value.
     *
     * @param streaming whether or not streaming is being performed
     * @return {@code true} if streaming or a value computed based on if the currently configured mode is compatible
     *         with initialization vectors.
     */
    @Override
    protected boolean isGenerateInitializationVectors(boolean streaming) {
        return streaming || super.isGenerateInitializationVectors() && isModeInitializationVectorCompatible(getModeName());
    }

    @Override
    protected byte[] generateInitializationVector(boolean streaming) {
        if (streaming) {
            String streamingModeName = getStreamingModeName();
            if (!isModeInitializationVectorCompatible(streamingModeName)) {
                String msg = "streamingMode attribute value [" + streamingModeName + "] does not support " +
                        "Initialization Vectors.  Ensure the streamingMode value represents an operation mode " +
                        "that is compatible with initialization vectors.";
                throw new IllegalStateException(msg);
            }
        } else {
            String modeName = getModeName();
            if (!isModeInitializationVectorCompatible(modeName)) {
                String msg = "mode attribute value [" + modeName + "] does not support " +
                        "Initialization Vectors.  Ensure the mode value represents an operation mode " +
                        "that is compatible with initialization vectors.";
                throw new IllegalStateException(msg);
            }
        }
        return super.generateInitializationVector(streaming);
    }
}
