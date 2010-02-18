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
package org.apache.shiro.mgt;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.RememberMeAuthenticationToken;
import org.apache.shiro.codec.Base64;
import org.apache.shiro.codec.Hex;
import org.apache.shiro.crypto.BlowfishCipher;
import org.apache.shiro.crypto.Cipher;
import org.apache.shiro.io.DefaultSerializer;
import org.apache.shiro.io.Serializer;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;

/**
 * Abstract implementation of the {@code RememberMeManager} interface that handles
 * {@link #setSerializer(org.apache.shiro.io.Serializer) serialization} and
 * {@link #setCipher(org.apache.shiro.crypto.Cipher) encryption} of the remembered user identity.
 * <p/>
 * The remembered identity storage location and details are left to subclasses.
 *
 * @author Les Hazlewood
 * @author Jeremy Haile
 * @since 0.9
 */
public abstract class AbstractRememberMeManager implements RememberMeManager {

    /**
     * private inner log instance.
     */
    private static final Logger log = LoggerFactory.getLogger(AbstractRememberMeManager.class);

    /**
     * Serializer to use for converting PrincipalCollection instances to/from byte arrays
     */
    private Serializer<PrincipalCollection> serializer;

    /**
     * Cipher to use for encrypting/decrypting serialized byte arrays for added security
     */
    private Cipher cipher;

    /**
     * Cipher encryption key to use with the Cipher when encrypting data
     */
    private byte[] encryptionCipherKey;

    /**
     * Cipher decryption key to use with the Cipher when decrypting data
     */
    private byte[] decryptionCipherKey;

    /**
     * Default constructor that initializes a {@link DefaultSerializer} as the {@link #getSerializer() serializer} and
     * a {@link BlowfishCipher BlowfishCipher} as the {@link #getCipher() cipher}.
     */
    public AbstractRememberMeManager() {
        this.serializer = new DefaultSerializer<PrincipalCollection>();
        this.cipher = new BlowfishCipher();
    }

    /**
     * Returns the {@code Serializer} used to serialize and deserialize {@link PrincipalCollection} instances for
     * persistent remember me storage.
     * <p/>
     * Unless overridden by the {@link #setSerializer} method, the default instance is a
     * {@link org.apache.shiro.io.DefaultSerializer}.
     *
     * @return the {@code Serializer} used to serialize and deserialize {@link PrincipalCollection} instances for
     *         persistent remember me storage.
     */
    public Serializer<PrincipalCollection> getSerializer() {
        return serializer;
    }

    /**
     * Sets the {@code Serializer} used to serialize and deserialize {@link PrincipalCollection} instances for
     * persistent remember me storage.
     * <p/>
     * Unless overridden by this method, the default instance is a {@link DefaultSerializer}.
     *
     * @param serializer the {@code Serializer} used to serialize and deserialize {@link PrincipalCollection} instances
     *                   for persistent remember me storage.
     */
    public void setSerializer(Serializer<PrincipalCollection> serializer) {
        this.serializer = serializer;
    }

    /**
     * Returns the {@code Cipher} to use for encrypting and decrypting serialized identity data to prevent easy
     * inspection of Subject identity data.
     * <p/>
     * Unless overridden by the {@link #setCipher} method, the default instance is a {@link BlowfishCipher}.
     *
     * @return the {@code Cipher} to use for encrypting and decrypting serialized identity data to prevent easy
     *         inspection of Subject identity data
     */
    public Cipher getCipher() {
        return cipher;
    }

    /**
     * Sets the {@code Cipher} to use for encrypting and decrypting serialized identity data to prevent easy
     * inspection of Subject identity data.
     * <p/>
     * If the cipher is an symmetric cipher (using the same key for both encryption and decryption), you
     * should set your key via one of the three following methods:
     * <ul>
     * <li>{@link #setCipherKey(byte[])}</li>
     * <li>{@link #setCipherKeyBase64(String)}, or</li>
     * <li>{@link #setCipherKeyHex(String)}</li>
     * </ul>
     * <p/>
     * If the cipher is an asymmetric cipher (different keys for encryption and decryption, such as public/private key
     * pairs), you should set your encryption key via one of these methods:
     * <ul>
     * <li>{@link #setEncryptionCipherKey(byte[])}</li>
     * <li>{@link #setEncryptionCipherKeyHex(String)}, or</li>
     * <li>{@link #setEncryptionCipherKeyBase64(String)}</li>
     * </ul>
     * Similarly, you can set the decryption key via one of these methods:
     * <ul>
     * <li>{@link #setDecryptionCipherKey(byte[])}</li>
     * <li>{@link #setDecryptionCipherKeyHex(String)}, or</li>
     * <li>{@link #setDecryptionCipherKeyBase64(String)}</li>
     * </ul>
     * <p/>
     * <b>N.B.</b> Unless overridden by this method, the default Cipher instance is a
     * {@link BlowfishCipher}.  Shiro's {@code BlowfishCipher} already has a configured symmetric key to use for
     * encryption and decryption, but it is recommended to provide your own for added security.  See the
     * {@link BlowfishCipher} class-level JavaDoc for more information and why it might be good to provide your own.
     *
     * @param cipher the {@code Cipher} to use for encrypting and decrypting serialized identity data to prevent easy
     *               inspection of Subject identity data.
     */
    public void setCipher(Cipher cipher) {
        this.cipher = cipher;
    }

    /**
     * Returns the cipher key to use for encryption operations.
     *
     * @return the cipher key to use for encryption operations.
     * @see #setCipher for a description of the various {@code get/set*Key} methods.
     */
    public byte[] getEncryptionCipherKey() {
        return encryptionCipherKey;
    }

    /**
     * Sets the encryption key to use for encryption operations.  If setting the key via text configuration mechanisms,
     * the {@link #setEncryptionCipherKeyHex(String) encryptionCipherKeyHex} or
     * {@link #setEncryptionCipherKeyBase64(String) encryptionCipherKeyBase64} methods are probably more convenient.
     *
     * @param encryptionCipherKey the encryption key to use for encryption operations.
     * @see #setCipher for a description of the various {@code get/set*Key} methods.
     */
    public void setEncryptionCipherKey(byte[] encryptionCipherKey) {
        this.encryptionCipherKey = encryptionCipherKey;
    }

    /**
     * Convenience method that allows configuration of the encryption {@link Cipher cipher} key by specifying a
     * {@code hex}-encoded string.  The string is {@code hex}-decoded and the resulting byte array is used
     * as the {@link #setEncryptionCipherKey(byte[]) encryption cipher key}.
     *
     * @param hex hex-encoded encryption cipher key to decode into the raw encryption cipher key bytes.
     * @see #setCipher for a description of the various {@code get/set*Key} methods.
     */
    public void setEncryptionCipherKeyHex(String hex) {
        setEncryptionCipherKey(Hex.decode(hex));
    }

    /**
     * Convenience method that allows configuration of the encryption {@link Cipher cipher} key by specifying a
     * {@code BASE 64}-encoded string.  The string is {@code BASE 64}-decoded and the resulting byte array is used
     * as the {@link #setEncryptionCipherKey(byte[]) cipher key}.
     *
     * @param base64 base64-encoded encryption cipher key to decode into the raw encryption cipher key bytes
     * @see #setCipher for a description of the various {@code get/set*Key} methods.
     */
    public void setEncryptionCipherKeyBase64(String base64) {
        setEncryptionCipherKey(Base64.decode(base64));
    }

    /**
     * Returns the decryption cipher key to use for decryption operations.
     *
     * @return the cipher key to use for decryption operations.
     * @see #setCipher for a description of the various {@code get/set*Key} methods.
     */
    public byte[] getDecryptionCipherKey() {
        return decryptionCipherKey;
    }

    /**
     * Sets the decryption key to use for decryption operations.  If setting the key via text configuration mechanisms,
     * the {@link #setDecryptionCipherKeyHex(String) decryptionCipherKeyHex} or
     * {@link #setDecryptionCipherKeyBase64(String) decryptionCipherKeyBase64} methods are probably more convenient.
     *
     * @param decryptionCipherKey the decryption key to use for decryption operations.
     * @see #setCipher for a description of the various {@code get/set*Key} methods.
     */
    public void setDecryptionCipherKey(byte[] decryptionCipherKey) {
        this.decryptionCipherKey = decryptionCipherKey;
    }

    /**
     * Convenience method that allows configuration of the decryption {@link Cipher cipher} key by specifying a
     * {@code hex}-encoded string.  The string is {@code hex}-decoded and the resulting byte array is used
     * as the {@link #setDecryptionCipherKey(byte[]) decryption cipher key}.
     *
     * @param hex hex-encoded decryption cipher key to decode into the raw decryption cipher key bytes.
     * @see #setCipher for a description of the various {@code get/set*Key} methods.
     */
    public void setDecryptionCipherKeyHex(String hex) {
        setDecryptionCipherKey(Hex.decode(hex));
    }

    /**
     * Convenience method that allows configuration of the decryption {@link Cipher cipher} key by specifying a
     * {@code BASE 64}-encoded string.  The string is {@code BASE 64}-decoded and the resulting byte array is used
     * as the {@link #setDecryptionCipherKey(byte[]) cipher key}.
     *
     * @param base64 base64-encoded decryption cipher key to decode into the raw decryption cipher key bytes
     * @see #setCipher for a description of the various {@code get/set*Key} methods.
     */
    public void setDecryptionCipherKeyBase64(String base64) {
        setDecryptionCipherKey(Base64.decode(base64));
    }

    /**
     * Convenience method that returns the cipher key to use for <em>both</em> encryption and decryption.
     * <p/>
     * <b>N.B.</b> This method can only be called if the underlying {@link #getCipher() cipher} is a symmetric cipher
     * which by definition uses the same key for both encryption and decryption.  If using an asymmetric cipher
     * (such as a public/private key pair), you cannot use this method, and should instead use the
     * {@link #getEncryptionCipherKey()} and {@link #getDecryptionCipherKey()} methods individually.
     * <p/>
     * The default {@link BlowfishCipher} instance is a symmetric cipher, so this method can be used if you are using
     * the default.
     *
     * @return the symmetric cipher key used for both encryption and decryption.
     */
    public byte[] getCipherKey() {
        //Since this method should only be used with symmetric ciphers
        //(where the enc and dec keys are the same), either is fine, just return one of them:
        return getEncryptionCipherKey();
    }

    /**
     * Convenience method that sets the cipher key to use for <em>both</em> encryption and decryption.
     * <p/>
     * <b>N.B.</b> This method can only be called if the underlying {@link #getCipher() cipher} is a symmetric cipher
     * which by definition uses the same key for both encryption and decryption.  If using an asymmetric cipher
     * (such as a public/private key pair), you cannot use this method, and should instead use the
     * {@link #setEncryptionCipherKey(byte[])} and {@link #setDecryptionCipherKey(byte[])} methods individually.
     * <p/>
     * The default {@link BlowfishCipher} instance is a symmetric cipher, so this method can be used if you are using
     * the default.
     *
     * @param cipherKey the symmetric cipher key to use for both encryption and decryption.
     */
    public void setCipherKey(byte[] cipherKey) {
        //Since this method should only be used in symmetric ciphers
        //(where the enc and dec keys are the same), set it on both:
        setEncryptionCipherKey(cipherKey);
        setDecryptionCipherKey(cipherKey);
    }

    /**
     * Convenience method that allows configuration of the (symmetric) {@link Cipher cipher} key by specifying a
     * {@code hex}-encoded string.  The string is {@code hex}-decoded and the resulting byte array is used
     * as the {@link #setCipherKey(byte[]) cipher key}.
     * <p/>
     * <b>N.B.</b> This is a convenience method to set <em>both</em> the {@link Cipher} encryption key and the
     * decryption key and should only be called if using a symmetric cipher.  If using an asymmetric cipher (such
     * as a public/private key pair) you cannot
     * call this method and instead should use the {@link #setEncryptionCipherKeyHex(String)} and
     * {@link #setDecryptionCipherKeyHex(String)} methods instead.
     * <p/>
     * The default {@link BlowfishCipher} instance is a symmetric cipher, so this method can be used if you are using
     * the default.
     *
     * @param hex hex-encoded symmetric cipher key to decode into the raw cipher key bytes.
     */
    public void setCipherKeyHex(String hex) {
        setCipherKey(Hex.decode(hex));
    }

    /**
     * Convenience method that allows configuration of the (symmetric) {@link Cipher cipher} key by specifying a
     * {@code BASE 64}-encoded string.  The string is {@code BASE 64}-decoded and the resulting byte array is used
     * as the {@link #setCipherKey(byte[]) cipher key}.
     * <p/>
     * <b>N.B.</b> This is a convenience method to set <em>both</em> the {@link Cipher} encryption key and the
     * decryption key and should only be called if using a symmetric cipher.  If using an asymmetric cipher, you cannot
     * call this method and instead should use the {@link #setEncryptionCipherKeyBase64(String)} and
     * {@link #setDecryptionCipherKeyBase64(String)} methods instead.
     * <p/>
     * The default {@link BlowfishCipher} instance is a symmetric cipher, so this method can be used if you are using
     * the default.
     *
     * @param base64 base64-encoded symmetric cipher key to decode into the raw cipher key bytes.
     */
    public void setCipherKeyBase64(String base64) {
        setCipherKey(Base64.decode(base64));
    }

    /**
     * Forgets (removes) any remembered identity data for the subject being built by the specified {@code context}
     * argument.  The context map is usually populated by a {@link Subject.Builder} implementation.  See the
     * {@link SubjectFactory} class constants for Shiro's known map keys.
     *
     * @param subjectContext the contextual data, usually provided by a {@link Subject.Builder} implementation, that
     *                       is being used to construct a {@link Subject} instance.
     */
    protected abstract void forgetIdentity(Map subjectContext);

    /**
     * Forgets (removes) any remembered identity data for the specified {@link Subject} instance.
     *
     * @param subject the subject instance for which identity data should be forgotten from the underlying persistence
     *                mechanism.
     */
    protected abstract void forgetIdentity(Subject subject);

    /**
     * Determines whether or not remember me services should be performed for the specified token.  This method returns
     * {@code true} iff:
     * <ol>
     * <li>The token is not {@code null} and</li>
     * <li>The token is an {@code instanceof} {@link RememberMeAuthenticationToken} and</li>
     * <li>{@code token}.{@link org.apache.shiro.authc.RememberMeAuthenticationToken#isRememberMe() isRememberMe()} is
     * {@code true}</li>
     * </ol>
     *
     * @param token the authentication token submitted during the successful authentication attempt.
     * @return true if remember me services should be performed as a result of the successful authentication attempt.
     */
    protected boolean isRememberMe(AuthenticationToken token) {
        return token != null && (token instanceof RememberMeAuthenticationToken) &&
                ((RememberMeAuthenticationToken) token).isRememberMe();
    }

    /**
     * Reacts to the successful login attempt by first always {@link #forgetIdentity(Subject) forgetting} any previously
     * stored identity.  Then if the {@code token}
     * {@link #isRememberMe(org.apache.shiro.authc.AuthenticationToken) is a RememberMe} token, the associated identity
     * will be {@link #rememberIdentity(org.apache.shiro.subject.Subject, org.apache.shiro.authc.AuthenticationToken, org.apache.shiro.authc.AuthenticationInfo) remembered}
     * for later retrieval during a new user session.
     *
     * @param subject the subject for which the principals are being remembered.
     * @param token   the token that resulted in a successful authentication attempt.
     * @param info    the authentication info resulting from the successful authentication attempt.
     */
    public void onSuccessfulLogin(Subject subject, AuthenticationToken token, AuthenticationInfo info) {
        //always clear any previous identity:
        forgetIdentity(subject);

        //now save the new identity:
        if (isRememberMe(token)) {
            rememberIdentity(subject, token, info);
        } else {
            if (log.isDebugEnabled()) {
                log.debug("AuthenticationToken did not indicate RememberMe is requested.  " +
                        "RememberMe functionality will not be executed for corresponding account.");
            }
        }
    }

    /**
     * Remembers a subject-unique identity for retrieval later.  This implementation first
     * {@link #getIdentityToRemember resolves} the exact
     * {@link PrincipalCollection principals} to remember.  It then remembers the principals by calling
     * {@link #rememberIdentity(org.apache.shiro.subject.Subject, org.apache.shiro.subject.PrincipalCollection)}.
     * <p/>
     * This implementation ignores the {@link AuthenticationToken} argument, but it is available to subclasses if
     * necessary for custom logic.
     *
     * @param subject   the subject for which the principals are being remembered.
     * @param token     the token that resulted in a successful authentication attempt.
     * @param authcInfo the authentication info resulting from the successful authentication attempt.
     */
    public void rememberIdentity(Subject subject, AuthenticationToken token, AuthenticationInfo authcInfo) {
        PrincipalCollection principals = getIdentityToRemember(subject, authcInfo);
        rememberIdentity(subject, principals);
    }

    /**
     * Returns {@code info}.{@link org.apache.shiro.authc.AuthenticationInfo#getPrincipals() getPrincipals()} and
     * ignores the {@link Subject} argument.
     *
     * @param subject the subject for which the principals are being remembered.
     * @param info    the authentication info resulting from the successful authentication attempt.
     * @return the {@code PrincipalCollection} to remember.
     */
    protected PrincipalCollection getIdentityToRemember(Subject subject, AuthenticationInfo info) {
        return info.getPrincipals();
    }

    /**
     * Remembers the specified account principals by first
     * {@link #convertPrincipalsToBytes(org.apache.shiro.subject.PrincipalCollection) converting} them to a byte
     * array and then {@link #rememberSerializedIdentity(org.apache.shiro.subject.Subject, byte[]) remembers} that
     * byte array.
     *
     * @param subject           the subject for which the principals are being remembered.
     * @param accountPrincipals the principals to remember for retrieval later.
     */
    protected void rememberIdentity(Subject subject, PrincipalCollection accountPrincipals) {
        byte[] bytes = convertPrincipalsToBytes(accountPrincipals);
        rememberSerializedIdentity(subject, bytes);
    }

    /**
     * Converts the given principal collection the byte array that will be persisted to be 'remembered' later.
     * <p/>
     * This implementation first {@link #serialize(org.apache.shiro.subject.PrincipalCollection) serializes} the
     * principals to a byte array and then {@link #encrypt(byte[]) encrypts} that byte array.
     *
     * @param principals the {@code PrincipalCollection} to convert to a byte array
     * @return the representative byte array to be persisted for remember me functionality.
     */
    protected byte[] convertPrincipalsToBytes(PrincipalCollection principals) {
        byte[] bytes = serialize(principals);
        if (getCipher() != null) {
            bytes = encrypt(bytes);
        }
        return bytes;
    }

    /**
     * Persists the identity bytes to a persistent store for retrieval later via the
     * {@link #getRememberedSerializedIdentity(java.util.Map)} method.
     *
     * @param subject    the Subject for which the identity is being serialized.
     * @param serialized the serialized bytes to be persisted.
     */
    protected abstract void rememberSerializedIdentity(Subject subject, byte[] serialized);

    /**
     * Implements the interface method by first {@link #getRememberedSerializedIdentity(java.util.Map) acquiring}
     * the remembered serialized byte array.  Then it {@link #convertBytesToPrincipals(byte[], java.util.Map) converts}
     * them and returns the re-constituted {@link PrincipalCollection}.  If no remembered principals could be
     * obtained, {@code null} is returned.
     * <p/>
     * If any exceptions are thrown, the {@link #onRememberedPrincipalFailure(RuntimeException, java.util.Map)} method
     * is called to allow any necessary post-processing (such as immediately removing any previously remembered
     * values for safety).
     *
     * @param subjectContext the contextual data, usually provided by a {@link Subject.Builder} implementation, that
     *                       is being used to construct a {@link Subject} instance.
     * @return the remembered principals or {@code null} if none could be acquired.
     */
    public PrincipalCollection getRememberedPrincipals(Map subjectContext) {
        PrincipalCollection principals = null;
        try {
            byte[] bytes = getRememberedSerializedIdentity(subjectContext);
            //SHIRO-138 - only call convertBytesToPrincipals if bytes exist:
            if ( bytes != null && bytes.length > 0 ) {
                principals = convertBytesToPrincipals(bytes, subjectContext);
            }
        } catch (RuntimeException re) {
            principals = onRememberedPrincipalFailure(re, subjectContext);
        }

        return principals;
    }

    /**
     * Based on the given subject context data, retrieves the previously persisted serialized identity, or
     * {@code null} if there is no available data.  The context map is usually populated by a {@link Subject.Builder}
     * implementation.  See the {@link SubjectFactory} class constants for Shiro's known map keys.
     *
     * @param subjectContext the contextual data, usually provided by a {@link Subject.Builder} implementation, that
     *                       is being used to construct a {@link Subject} instance.  To be used to assist with data
     *                       lookup.
     * @return the previously persisted serialized identity, or {@code null} if there is no available data for the
     *         Subject.
     */
    protected abstract byte[] getRememberedSerializedIdentity(Map subjectContext);

    /**
     * If a {@link #getCipher() cipher} is available, it will be used to first decrypt the byte array.  Then the
     * bytes are then {@link #deserialize(byte[]) deserialized} and then returned.
     *
     * @param bytes          the bytes to decrypt if necessary and then deserialize.
     * @param subjectContext the contextual data, usually provided by a {@link Subject.Builder} implementation, that
     *                       is being used to construct a {@link Subject} instance.
     * @return the de-serialized and possibly decrypted principals
     */
    protected PrincipalCollection convertBytesToPrincipals(byte[] bytes, Map subjectContext) {
        if (getCipher() != null) {
            bytes = decrypt(bytes);
        }
        return deserialize(bytes);
    }

    /**
     * Called when an exception is thrown while trying to retrieve principals.  The default implementation logs a
     * debug message and forgets ('unremembers') the problem identity by calling
     * {@link #forgetIdentity(java.util.Map) forgetIdentity(context)} and then immediately re-throws the
     * exception to allow the calling component to react accordingly.
     * <p/>
     * This method implementation never returns an
     * object - it always rethrows, but can be overridden by subclasses for custom handling behavior.
     * <p/>
     * This most commonly would be called when an encryption key is updated and old principals are retrieved that have
     * been encrypted with the previous key.
     *
     * @param e       the exception that was thrown.
     * @param context the contextual data, usually provided by a {@link Subject.Builder} implementation, that
     *                is being used to construct a {@link Subject} instance.
     * @return nothing - the original {@code RuntimeException} is propagated in all cases.
     */
    protected PrincipalCollection onRememberedPrincipalFailure(RuntimeException e, Map context) {
        if (log.isDebugEnabled()) {
            log.debug("There was a failure while trying to retrieve remembered principals.  This could be due to a " +
                    "configuration problem or corrupted principals.  This could also be due to a recently " +
                    "changed encryption key.  The remembered identity will be forgotten and not used for this " +
                    "request.", e);
        }
        forgetIdentity(context);
        //propagate - security manager implementation will handle and warn appropriately
        throw e;
    }

    /**
     * Encrypts the byte array by using the configured {@link #getCipher() cipher}.
     *
     * @param serialized the serialized object byte array to be encrypted
     * @return an encrypted byte array returned by the configured {@link #getCipher() cipher}.
     */
    protected byte[] encrypt(byte[] serialized) {
        byte[] value = serialized;
        Cipher cipher = getCipher();
        if (cipher != null) {
            value = cipher.encrypt(serialized, getEncryptionCipherKey());
        }
        return value;
    }

    /**
     * Decrypts the byte array using the configured {@link #getCipher() cipher}.
     *
     * @param encrypted the encrypted byte array to decrypt
     * @return the decrypted byte array returned by the configured {@link #getCipher() cipher}.
     */
    protected byte[] decrypt(byte[] encrypted) {
        byte[] serialized = encrypted;
        Cipher cipher = getCipher();
        if (cipher != null) {
            serialized = cipher.decrypt(encrypted, getDecryptionCipherKey());
        }
        return serialized;
    }

    /**
     * Serializes the given {@code principals} by serializing them to a byte array by using the
     * {@link #getSerializer() serializer}'s {@link Serializer#serialize(Object) serialize} method.
     *
     * @param principals the principal collection to serialize to a byte array
     * @return the serialized principal collection in the form of a byte array
     */
    protected byte[] serialize(PrincipalCollection principals) {
        return getSerializer().serialize(principals);
    }

    /**
     * De-serializes the given byte array by using the {@link #getSerializer() serializer}'s
     * {@link Serializer#deserialize deserialize} method.
     *
     * @param serializedIdentity the previously serialized {@code PrincipalCollection} as a byte array
     * @return the de-serialized (reconstituted) {@code PrincipalCollection}
     */
    protected PrincipalCollection deserialize(byte[] serializedIdentity) {
        return getSerializer().deserialize(serializedIdentity);
    }

    /**
     * Reacts to a failed login by immediately {@link #forgetIdentity(org.apache.shiro.subject.Subject) forgetting} any
     * previously remembered identity.  This is an additional security feature to prevent any remenant identity data
     * from being retained in case the authentication attempt is not being executed by the expected user.
     *
     * @param subject the subject which executed the failed login attempt
     * @param token   the authentication token resulting in a failed login attempt - ignored by this implementation
     * @param ae      the exception thrown as a result of the failed login attempt - ignored by this implementation
     */
    public void onFailedLogin(Subject subject, AuthenticationToken token, AuthenticationException ae) {
        forgetIdentity(subject);
    }

    /**
     * Reacts to a subject logging out of the application and immediately
     * {@link #forgetIdentity(org.apache.shiro.subject.Subject) forgets} any previously stored identity and returns.
     *
     * @param subject the subject logging out.
     */
    public void onLogout(Subject subject) {
        forgetIdentity(subject);
    }
}
