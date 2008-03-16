/*
 * Copyright 2005-2008 Les Hazlewood
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.jsecurity.subject;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.authc.Account;
import org.jsecurity.authc.AuthenticationException;
import org.jsecurity.authc.AuthenticationToken;
import org.jsecurity.authc.RememberMeAuthenticationToken;
import org.jsecurity.crypto.BlowfishCipher;
import org.jsecurity.crypto.Cipher;
import org.jsecurity.util.Serializer;
import org.jsecurity.util.XmlSerializer;

/**
 * @author Les Hazlewood
 * @since 0.9
 */
public abstract class AbstractRememberMeManager implements RememberMeManager {

    protected transient final Log log = LogFactory.getLog(getClass());

    private Serializer serializer = new XmlSerializer();
    private Cipher cipher = new BlowfishCipher();

    public AbstractRememberMeManager() {
    }

    public AbstractRememberMeManager(Serializer serializer) {
        setSerializer(serializer);
    }

    public AbstractRememberMeManager(Serializer serializer, Cipher cipher) {
        setSerializer(serializer);
        setCipher(cipher);
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

    protected boolean isRememberMe(AuthenticationToken token) {
        return token != null && (token instanceof RememberMeAuthenticationToken) &&
            ((RememberMeAuthenticationToken) token).isRememberMe();
    }

    public void onSuccessfulLogin(AuthenticationToken token, Account account) {
        if (isRememberMe(token)) {
            rememberIdentity(token, account);
        } else {
            if (log.isDebugEnabled()) {
                log.debug("AuthenticationToken did not indicate RememberMe is requested.  " +
                    "RememberMe functionality will not be executed for corresponding Account.");
            }
        }
    }

    public void rememberIdentity(AuthenticationToken submittedToken, Account successfullyAuthenticated) {
        rememberIdentity(successfullyAuthenticated);
    }

    public void rememberIdentity(Account successfullyAuthenticated) {
        Object identityToRemember = getIdentityToRemember(successfullyAuthenticated);
        rememberIdentity(identityToRemember);
    }

    protected Object getIdentityToRemember(Account account) {
        return account.getPrincipal();
    }

    protected byte[] encrypt(byte[] serialized) {
        Cipher cipher = getCipher();
        if (cipher != null) {
            return cipher.encrypt(serialized, null);
        }
        return serialized;
    }

    protected byte[] decrypt(byte[] encrypted) {
        byte[] serialized = encrypted;
        Cipher cipher = getCipher();
        if (cipher != null) {
            serialized = cipher.decrypt(encrypted, null);
        }
        return serialized;
    }

    protected void rememberIdentity(Object accountPrincipals) {
        byte[] bytes = serialize(accountPrincipals);
        if (getCipher() != null) {
            bytes = encrypt(bytes);
        }
        rememberSerializedIdentity(bytes);
    }

    protected byte[] serialize(Object accountPrincipals) {
        return getSerializer().serialize(accountPrincipals);
    }

    protected abstract void rememberSerializedIdentity(byte[] serialized);

    public Object getRememberedIdentity() {
        byte[] bytes = getSerializedRememberedIdentity();
        if (bytes != null) {
            if (getCipher() != null) {
                bytes = decrypt(bytes);
            }
            return deserialize(bytes);
        }
        return null;
    }

    protected Object deserialize(byte[] serializedIdentity) {
        return getSerializer().deserialize(serializedIdentity);
    }

    protected abstract byte[] getSerializedRememberedIdentity();

    public void onFailedLogin(AuthenticationToken token, AuthenticationException ae) {
        forgetIdentity(token, ae);
    }

    public void onLogout(Object subjectPrincipals) {
        forgetIdentity(subjectPrincipals);
    }

    protected void forgetIdentity(AuthenticationToken token, AuthenticationException ae) {
        forgetIdentity(token);
    }

    protected void forgetIdentity(AuthenticationToken token) {
        forgetIdentity(token.getPrincipal());
    }

    public void forgetIdentity(Object principals) {
        forgetIdentity();
    }

    protected abstract void forgetIdentity();
}
