/*
 * Copyright (C) 2005-2008 Les Hazlewood
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General
 * Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the
 *
 * Free Software Foundation, Inc.
 * 59 Temple Place, Suite 330
 * Boston, MA 02111-1307
 * USA
 *
 * Or, you may view it online at
 * http://www.opensource.org/licenses/lgpl-license.php
 */
package org.jsecurity.subject;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.authc.Account;
import org.jsecurity.authc.AuthenticationException;
import org.jsecurity.authc.AuthenticationToken;
import org.jsecurity.authc.RememberMeAuthenticationToken;
import org.jsecurity.crypto.Cipher;
import org.jsecurity.util.*;

/**
 * @author Les Hazlewood
 * @since 1.0
 */
public abstract class AbstractRememberMeManager implements RememberMeManager, Initializable, Destroyable {

    protected transient final Log log = LogFactory.getLog(getClass());

    private Serializer serializer = null;
    private Cipher cipher = null;

    public AbstractRememberMeManager() {
    }

    public AbstractRememberMeManager(Serializer serializer) {
        this(serializer, null);
    }

    public AbstractRememberMeManager(Serializer serializer, Cipher cipher) {
        setSerializer(serializer);
        setCipher(cipher);
        init();
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

    protected void ensureSerializer() {
        Serializer serializer = getSerializer();
        if (serializer == null) {
            serializer = new XmlSerializer();
            setSerializer(serializer);
        }
    }

    public void init() {
        ensureSerializer();
        onInit();
    }

    protected void onInit() {
    }

    public void destroy() throws Exception {
        LifecycleUtils.destroy(getSerializer());
        setSerializer(null);
        LifecycleUtils.destroy(getCipher());
        setCipher(null);
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
