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
package org.jsecurity.subject;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.authc.AuthenticationException;
import org.jsecurity.authc.AuthenticationInfo;
import org.jsecurity.authc.AuthenticationToken;
import org.jsecurity.authc.RememberMeAuthenticationToken;
import org.jsecurity.codec.Base64;
import org.jsecurity.codec.Hex;
import org.jsecurity.crypto.BlowfishCipher;
import org.jsecurity.crypto.Cipher;
import org.jsecurity.io.DefaultSerializer;
import org.jsecurity.io.SerializationException;
import org.jsecurity.io.Serializer;

/**
 * @author Les Hazlewood
 * @author Jeremy Haile
 * @since 0.9
 */
public abstract class AbstractRememberMeManager implements RememberMeManager {

    protected transient final Log log = LogFactory.getLog(getClass());

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
