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
package org.jsecurity.context.support;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.authc.Account;
import org.jsecurity.authc.AuthenticationToken;
import org.jsecurity.authc.RememberMeAuthenticationToken;
import org.jsecurity.authc.event.AuthenticationEvent;
import org.jsecurity.authc.event.FailedAuthenticationEvent;
import org.jsecurity.authc.event.LogoutEvent;
import org.jsecurity.authc.event.SuccessfulAuthenticationEvent;
import org.jsecurity.crypto.Cipher;
import org.jsecurity.util.*;

/**
 * @author Les Hazlewood
 * @since 1.0
 */
public abstract class AbstractRememberMeManager implements RememberMeManager, Initializable, Destroyable {

    protected transient final Log log = LogFactory.getLog( getClass() );

    private Serializer serializer = null;
    private boolean serializerImplicitlyCreated = false;

    private Cipher cipher = null;

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
        if ( serializer == null ) {
            serializer = new XmlSerializer();
            setSerializer( serializer );
            this.serializerImplicitlyCreated = true;
        }
    }

    public void init() throws Exception {
        ensureSerializer();
        onInit();
    }

    protected void onInit(){}

    public void destroy() throws Exception {
        if ( this.serializerImplicitlyCreated) {
            LifecycleUtils.destroy( getSerializer() );
            this.serializerImplicitlyCreated = false;
        }
    }

    public void onEvent(AuthenticationEvent event) {
        accept( event );
    }

    protected void accept( AuthenticationEvent event ) {
        if ( log.isDebugEnabled() ) {
            log.debug( "Received an AuthenticationEvent for subject identity [" +
                    event.getPrincipals() + "] not handled by this class." );
        }
    }

    protected void accept( SuccessfulAuthenticationEvent event ) {
        AuthenticationToken token = event.getToken();
        if ( token != null &&
             (token instanceof RememberMeAuthenticationToken) &&
             ((RememberMeAuthenticationToken)token).isRememberMe() ) {
            Account account = event.getAccount();
            rememberIdentity( token, account );
        } else {
            if ( log.isTraceEnabled() ) {
                log.trace( "SuccessfulAuthenticationEvent received, but event did not contain " +
                        "a RememberMeAuthenticationToken with isRememberMe() == true.  RememberMe " +
                        "functionality will not be executed for the Account associated with this event." );
            }
        }

    }

    public void rememberIdentity( AuthenticationToken submittedToken, Account successfullyAuthenticated ) {
        rememberIdentity( successfullyAuthenticated );
    }

    public void rememberIdentity( Account successfullyAuthenticated ) {
        Object identityToRemember = getIdentityToRemember( successfullyAuthenticated );
        rememberIdentity( identityToRemember );
    }

    protected Object getIdentityToRemember( Account account ) {
        return account.getPrincipals();
    }

    protected byte[] encrypt( byte[] serialized ) {
        Cipher cipher = getCipher();
        if ( cipher != null ) {
            return cipher.encrypt( serialized, null );
        }
        return serialized;
    }

    protected byte[] decrypt( byte[] encrypted ) {
        byte[] serialized = encrypted;
        Cipher cipher = getCipher();
        if ( cipher != null ) {
            serialized = cipher.decrypt( encrypted, null );
        }
        return serialized;
    }

    protected void rememberIdentity( Object accountPrincipals ) {
        byte[] bytes = serialize( accountPrincipals );
        if ( getCipher() != null ) {
            bytes = encrypt( bytes );
        }
        rememberSerializedIdentity( bytes );
    }

    protected byte[] serialize( Object accountPrincipals ) {
        return getSerializer().serialize( accountPrincipals );
    }

    protected abstract void rememberSerializedIdentity( byte[] serialized );

    public Object getRememberedIdentity() {
        byte[] bytes = getRememberedSerializedIdentity();
        if ( getCipher() != null ) {
            bytes = decrypt( bytes );
        }
        return deserialize( bytes );
    }

    protected Object deserialize( byte[] serializedIdentity ) {
        return getSerializer().deserialize( serializedIdentity );
    }

    protected abstract byte[] getRememberedSerializedIdentity();

    protected Object getIdentity( AuthenticationEvent event ) {
        return event.getPrincipals();
    }

    protected void accept( FailedAuthenticationEvent event ) {
        forgetIdentity( event );
    }

    protected void accept( LogoutEvent event ) {
        forgetIdentity( event );
    }

    protected void forgetIdentity( AuthenticationEvent event ) {
        Object identityToForget = getIdentity( event );
        forgetIdentity( identityToForget );
    }

    public void forgetIdentity( Object principals ) {
        forgetIdentity();
    }

    protected void forgetIdentity() {
        throw new UnsupportedOperationException( "the forgetIdentity() method (or one of its overloaded " +
                "variants) must be overridden by subclasses." );
    }

}
