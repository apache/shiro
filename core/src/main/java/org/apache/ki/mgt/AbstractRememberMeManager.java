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
package org.apache.ki.mgt;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.apache.ki.authc.AuthenticationException;
import org.apache.ki.authc.AuthenticationInfo;
import org.apache.ki.authc.AuthenticationToken;
import org.apache.ki.authc.RememberMeAuthenticationToken;
import org.apache.ki.codec.Base64;
import org.apache.ki.codec.Hex;
import org.apache.ki.crypto.BlowfishCipher;
import org.apache.ki.crypto.Cipher;
import org.apache.ki.io.DefaultSerializer;
import org.apache.ki.io.SerializationException;
import org.apache.ki.io.Serializer;
import org.apache.ki.subject.PrincipalCollection;


/**
 * Abstract implementation of the <code>RememberMeManager</code> interface that handles
 * {@link #setSerializer(org.apache.ki.io.Serializer) serialization} and
 * {@link #setCipher(org.apache.ki.crypto.Cipher) encryption} of the remembered user identity.
 * <p/>
 * The remembered identity storage location is implementation-specific.
 *
 * @author Les Hazlewood
 * @author Jeremy Haile
 * @since 0.9
 */
public abstract class AbstractRememberMeManager implements RememberMeManager {

    //TODO - complete JavaDoc

    /**
     * private inner log instance.
     */
    private static final Logger log = LoggerFactory.getLogger(AbstractRememberMeManager.class);

    private Serializer serializer = new DefaultSerializer();
    private Cipher cipher = new BlowfishCipher();
    private byte[] encryptionCipherKey = null;
    private byte[] decryptionCipherKey = null;

    public AbstractRememberMeManager() {
    }

    public Serializer getSerializer() {
        return serializer;
    }

    public void setSerializer(Serializer serializer) {
        this.serializer = serializer;
    }

    public Cipher getCipher() {
        return cipher;
    }

    public void setCipher(Cipher cipher) {
        this.cipher = cipher;
    }

    public byte[] getEncryptionCipherKey() {
        return encryptionCipherKey;
    }

    public void setEncryptionCipherKey(byte[] encryptionCipherKey) {
        this.encryptionCipherKey = encryptionCipherKey;
    }

    public void setEncryptionCipherKeyHex(String hex) {
        setEncryptionCipherKey(Hex.decode(hex));
    }

    public void setEncryptionCipherKeyBase64(String base64) {
        setEncryptionCipherKey(Base64.decode(base64));
    }

    public byte[] getDecryptionCipherKey() {
        return decryptionCipherKey;
    }

    public void setDecryptionCipherKey(byte[] decryptionCipherKey) {
        this.decryptionCipherKey = decryptionCipherKey;
    }

    public void setDecryptionCipherKeyHex(String hex) {
        setDecryptionCipherKey(Hex.decode(hex));
    }

    public void setDecryptionCipherKeyBase64(String base64) {
        setDecryptionCipherKey(Base64.decode(base64));
    }

    public byte[] getCipherKey() {
        //Since this method should only be used with symmetric ciphers
        //(where the enc and dec keys are the same), either is fine, just return one of them:
        return getEncryptionCipherKey();
    }

    public void setCipherKey(byte[] cipherKey) {
        //Since this method should only be used in symmetric ciphers
        //(where the enc and dec keys are the same), set it on both:
        setEncryptionCipherKey(cipherKey);
        setDecryptionCipherKey(cipherKey);
    }

    public void setCipherKeyHex(String hex) {
        setCipherKey(Hex.decode(hex));
    }

    public void setCipherKeyBase64(String base64) {
        setCipherKey(Base64.decode(base64));
    }

    // Abstract methods to be implemented by subclasses
    protected abstract void rememberSerializedIdentity(byte[] serialized);

    protected abstract byte[] getSerializedRememberedIdentity();

    protected abstract void forgetIdentity();


    protected boolean isRememberMe(AuthenticationToken token) {
        return token != null && (token instanceof RememberMeAuthenticationToken) &&
                ((RememberMeAuthenticationToken) token).isRememberMe();
    }

    public void onSuccessfulLogin(AuthenticationToken token, AuthenticationInfo info) {
        //always clear any previous identity:
        forgetIdentity(token);

        //reset it if necessary:
        if (isRememberMe(token)) {
            rememberIdentity(token, info);
        } else {
            if (log.isDebugEnabled()) {
                log.debug("AuthenticationToken did not indicate RememberMe is requested.  " +
                        "RememberMe functionality will not be executed for corresponding account.");
            }
        }
    }

    public void rememberIdentity(AuthenticationToken submittedToken, AuthenticationInfo successfullyAuthenticated) {
        rememberIdentity(successfullyAuthenticated);
    }

    public void rememberIdentity(AuthenticationInfo successfullyAuthenticated) {
        PrincipalCollection principals = getIdentityToRemember(successfullyAuthenticated);
        rememberIdentity(principals);
    }

    protected PrincipalCollection getIdentityToRemember(AuthenticationInfo info) {
        return info.getPrincipals();
    }

    protected void rememberIdentity(PrincipalCollection accountPrincipals) {
        try {
            byte[] bytes = serialize(accountPrincipals);
            if (getCipher() != null) {
                bytes = encrypt(bytes);
            }
            rememberSerializedIdentity(bytes);
        } catch (SerializationException se) {
            if (log.isWarnEnabled()) {
                log.warn("Unable to serialize account principals [" + accountPrincipals + "].  Identity " +
                        "cannot be remembered!  This is a non fatal exception as RememberMe identity services " +
                        "are not considered critical and execution can continue as normal.  But please " +
                        "investigate and resolve to prevent seeing this message again.", se);
            }
        }
    }

    public PrincipalCollection getRememberedPrincipals() {
        try {

            PrincipalCollection principals = null;
            byte[] bytes = getSerializedRememberedIdentity();
            if (bytes != null) {
                if (getCipher() != null) {
                    bytes = decrypt(bytes);
                }
                try {
                    principals = deserialize(bytes);
                } catch (SerializationException e) {
                    if (log.isWarnEnabled()) {
                        log.warn("Unable to deserialize stored identity byte array.  Remembered identity " +
                                "cannot be reconstituted!  This is a non fatal exception as RememberMe identity services " +
                                "are not considered critical and execution can continue as normal, but please " +
                                "investigate and resolve to prevent seeing this message again.", e);
                    }
                }
            }
            return principals;

        } catch (Exception e) {
            return onRememberedPrincipalFailure(e);
        }
    }

    /**
     * Called when an exception is thrown while trying to retrieve principals.  The default implementation logs a
     * warning and forgets ('unremembers') the problem identity by calling {@link #forgetIdentity() forgetIdentity()}.
     * This most commonly would occur when an encryption key is updated and old principals are retrieved that have
     * been encrypted with the previous key.\
     *
     * @param e the exception that was thrown.
     * @return <code>null</code> in all cases.
     */
    protected PrincipalCollection onRememberedPrincipalFailure(Exception e) {
        if (log.isWarnEnabled()) {
            log.warn("There was a failure while trying to retrieve remembered principals.  This could be due to a " +
                    "configuration problem or corrupted principals.  This could also be due to a recently " +
                    "changed encryption key.  The remembered identity will be forgotten and not used for this " +
                    "request.", e);
        }
        forgetIdentity();
        return null;
    }

    protected byte[] encrypt(byte[] serialized) {
        byte[] value = serialized;
        Cipher cipher = getCipher();
        if (cipher != null) {
            value = cipher.encrypt(serialized, getEncryptionCipherKey());
        }
        return value;
    }

    protected byte[] decrypt(byte[] encrypted) {
        byte[] serialized = encrypted;
        Cipher cipher = getCipher();
        if (cipher != null) {
            serialized = cipher.decrypt(encrypted, getDecryptionCipherKey());
        }
        return serialized;
    }


    protected byte[] serialize(PrincipalCollection principals) {
        return getSerializer().serialize(principals);
    }

    protected PrincipalCollection deserialize(byte[] serializedIdentity) {
        return (PrincipalCollection) getSerializer().deserialize(serializedIdentity);
    }

    public void onFailedLogin(AuthenticationToken token, AuthenticationException ae) {
        forgetIdentity(token, ae);
    }

    public void onLogout(PrincipalCollection subjectPrincipals) {
        forgetIdentity();
    }

    protected void forgetIdentity(AuthenticationToken token, AuthenticationException ae) {
        forgetIdentity(token);
    }

    protected void forgetIdentity(AuthenticationToken token) {
        forgetIdentity();
    }

}
