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
package org.apache.ki.authc;

import java.util.ArrayList;
import java.util.Collection;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.apache.ki.subject.PrincipalCollection;


/**
 * Superclass for almost all {@link Authenticator} implementations that performs the common work around authentication
 * attempts.
 *
 * <p>This class delegates the actual authentication attempt to subclasses but supports notification for
 * successful and failed logins as well as logouts. Notification is sent to one or more registered
 * {@link AuthenticationListener AuthenticationListener}s to allow for custom processing logic
 * when these conditions occur.
 *
 * <p>In most cases, the only thing a subclass needs to do (via its {@link #doAuthenticate} implementation)
 * is perform the actual principal/credential verification process for the submitted <tt>AuthenticationToken</tt>.
 *
 * @author Jeremy Haile
 * @author Les Hazlewood
 * @since 0.1
 */
public abstract class AbstractAuthenticator implements Authenticator, LogoutAware, AuthenticationListenerRegistrar {

    /*--------------------------------------------
    |             C O N S T A N T S             |
    ============================================*/
    /** Private class log instance. */
    private static final Log log = LogFactory.getLog(AbstractAuthenticator.class);

    /*--------------------------------------------
    |    I N S T A N C E   V A R I A B L E S    |
    ============================================*/
    /** Any registered listeners that wish to know about things during the authentication process. */
    private Collection<AuthenticationListener> listeners;

    /*--------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*/
    /**
     * Default no-argument constructor. Ensures the internal
     * {@link AuthenticationListener AuthenticationListener} collection is a non-null <code>ArrayList</code>.
     */
    public AbstractAuthenticator() {
        listeners = new ArrayList<AuthenticationListener>();
    }

    /*--------------------------------------------
    |  A C C E S S O R S / M O D I F I E R S    |
    ============================================*/
    public void setAuthenticationListeners(Collection<AuthenticationListener> listeners) {
        if (listeners == null) {
            this.listeners = new ArrayList<AuthenticationListener>();
        } else {
            this.listeners = listeners;
        }
    }

    public void add(AuthenticationListener listener) {
        this.listeners.add(listener);
    }

    public boolean remove(AuthenticationListener listener) {
        return this.listeners.remove(listener);
    }

    /*-------------------------------------------
    |               M E T H O D S               |
    ============================================*/
    /**
     * Notifies any registered {@link AuthenticationListener AuthenticationListener}s that
     * authentication was successful for the specified <code>token</code> which resulted in the specified
     * <code>info</code>.  This implementation merely iterates over the internal <code>listeners</code> collection and
     * calls {@link AuthenticationListener#onSuccess(AuthenticationToken, AuthenticationInfo) onSuccess}
     * for each.
     * @param token the submitted <code>AuthenticationToken</code> that resulted in a successful authentication.
     * @param info the returned <code>AuthenticationInfo</code> resulting from the successful authentication.
     */
    protected void notifySuccess(AuthenticationToken token, AuthenticationInfo info) {
        for (AuthenticationListener listener : this.listeners) {
            listener.onSuccess(token, info);
        }
    }

    /**
     * Notifies any registered {@link AuthenticationListener AuthenticationListener}s that
     * authentication failed for the
     * specified <code>token</code> which resulted in the specified <code>ae</code> exception.  This implementation merely
     * iterates over the internal <code>listeners</code> collection and calls
     * {@link AuthenticationListener#onFailure(AuthenticationToken, AuthenticationException) onFailure}
     * for each.
     * @param token the submitted <code>AuthenticationToken</code> that resulted in a failed authentication.
     * @param ae the resulting <code>AuthenticationException<code> that caused the authentication to fail.
     */
    protected void notifyFailure(AuthenticationToken token, AuthenticationException ae) {
        for (AuthenticationListener listener : this.listeners) {
            listener.onFailure(token, ae);
        }
    }

    /**
     * Notifies any registered {@link AuthenticationListener AuthenticationListener}s that a
     * <code>Subject</code> has logged-out.  This implementation merely
     * iterates over the internal <code>listeners</code> collection and calls
     * {@link AuthenticationListener#onLogout(org.apache.ki.subject.PrincipalCollection) onLogout}
     * for each.
     * @param principals the identifying principals of the <code>Subject</code>/account logging out.
     */
    protected void notifyLogout(PrincipalCollection principals) {
        for (AuthenticationListener listener : this.listeners) {
            listener.onLogout(principals);
        }
    }

    /**
     * This implementation merely calls
     * {@link #notifyLogout(org.apache.ki.subject.PrincipalCollection) notifyLogout} to allow any registered listeners
     * to react to the logout.
     * @param principals the identifying principals of the <code>Subject</code>/account logging out.
     */
    public void onLogout(PrincipalCollection principals) {
        notifyLogout(principals);
    }

    /**
     * Implementation of the {@link Authenticator} interface that functions in the following manner:
     *
     * <ol>
     * <li>Calls template {@link #doAuthenticate doAuthenticate} method for subclass execution of the actual
     * authentication behavior.</li>
     * <li>If an <tt>AuthenticationException</tt> is thrown during <tt>doAuthenticate</tt>,
     * {@link #notifyFailure(AuthenticationToken, AuthenticationException) notify} any registered
     * {@link AuthenticationListener AuthenticationListener}s of the exception and then propogate the exception
     * for the caller to handle.</li>
     * <li>If no exception is thrown (indicating a successful login),
     * {@link #notifySuccess(AuthenticationToken, AuthenticationInfo) notify} any registered
     * {@link AuthenticationListener AuthenticationListener}s of the successful attempt.</li>
     * <li>Return the <tt>AuthenticationInfo</tt></li>
     * </ol>
     *
     * @param token the submitted token representing the subject's (user's) login principals and credentials.
     * @return the AuthenticationInfo referencing the authenticated user's account data.
     * @throws AuthenticationException if there is any problem during the authentication process - see the
     *                                 interface's JavaDoc for a more detailed explanation.
     */
    public final AuthenticationInfo authenticate(AuthenticationToken token)
            throws AuthenticationException {

        if (token == null) {
            throw new IllegalArgumentException("Method argumet (authentication token) cannot be null.");
        }

        if (log.isTraceEnabled()) {
            log.trace("Authentication attempt received for token [" + token + "]");
        }

        AuthenticationInfo info;
        try {
            info = doAuthenticate(token);
            if (info == null) {
                String msg = "No account information found for authentication token [" + token + "] by this " +
                        "Authenticator instance.  Please check that it is configured correctly.";
                throw new AuthenticationException(msg);
            }
        } catch (Throwable t) {
            AuthenticationException ae = null;
            if (t instanceof AuthenticationException) {
                ae = (AuthenticationException) t;
            }
            if (ae == null) {
                //Exception thrown was not an expected AuthenticationException.  Therefore it is probably a little more
                //severe or unexpected.  So, wrap in an AuthenticationException, log to warn, and propagate:
                String msg = "Authentication failed for token submission [" + token + "].  Possible unexpected " +
                        "error? (Typical or expected login exceptions should extend from AuthenticationException).";
                ae = new AuthenticationException(msg, t);
                if (log.isWarnEnabled()) {
                    log.warn(msg, t);
                }
            }
            try {
                notifyFailure(token, ae);
            } catch (Throwable t2) {
                String msg = "Unable to send notification for failed authentication attempt - listener error?.  " +
                        "Please check your AuthenticationListener implementation(s).  Logging sending exception and " +
                        "propagating original AuthenticationException instead...";
                if (log.isWarnEnabled()) {
                    log.warn(msg, t2);
                }
            }


            throw ae;
        }

        if (log.isDebugEnabled()) {
            log.debug("Authentication successful for token [" + token + "].  Returned account: [" + info + "]");
        }

        notifySuccess(token, info);

        return info;
    }

    /**
     * Template design pattern hook for subclasses to implement specific authentication behavior.
     *
     * <p>Common behavior for most authentication attempts is encapsulated in the
     * {@link #authenticate} method and that method invokes this one for custom behavior.
     *
     * <p><b>N.B.</b> Subclasses <em>should</em> throw some kind of
     * <tt>AuthenticationException</tt> if there is a problem during
     * authentication instead of returning <tt>null</tt>.  A <tt>null</tt> return value indicates
     * a configuration or programming error, since <tt>AuthenticationException</tt>s should
     * indicate any expected problem (such as an unknown account or username, or invalid password, etc).
     *
     * @param token the authentication token encapsulating the user's login information.
     * @return an <tt>AuthenticationInfo</tt> object encapsulating the user's account information
     *         important to Ki.
     * @throws AuthenticationException if there is a problem logging in the user.
     */
    protected abstract AuthenticationInfo doAuthenticate(AuthenticationToken token)
            throws AuthenticationException;


}
