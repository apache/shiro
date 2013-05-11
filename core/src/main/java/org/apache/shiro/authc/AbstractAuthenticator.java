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
package org.apache.shiro.authc;

import org.apache.shiro.subject.PrincipalCollection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collection;


/**
 * Superclass for almost all {@link Authenticator} implementations that performs the common work around authentication
 * attempts.
 * <p/>
 * This class delegates the actual authentication attempt to subclasses but supports notification for
 * successful and failed logins as well as logouts. Notification is sent to one or more registered
 * {@link AuthenticationListener AuthenticationListener}s to allow for custom processing logic
 * when these conditions occur.
 * <p/>
 * In most cases, the only thing a subclass needs to do (via its {@link #doAuthenticate} implementation)
 * is perform the actual principal/credential verification process for the submitted {@code AuthenticationToken}.
 *
 * @since 0.1
 */
public abstract class AbstractAuthenticator implements Authenticator, LogoutAware {

    /*-------------------------------------------
    |             C O N S T A N T S             |
    ============================================*/
    /**
     * Private class log instance.
     */
    private static final Logger log = LoggerFactory.getLogger(AbstractAuthenticator.class);

    /*-------------------------------------------
    |    I N S T A N C E   V A R I A B L E S    |
    ============================================*/
    /**
     * Any registered listeners that wish to know about things during the authentication process.
     */
    private Collection<AuthenticationListener> listeners;

    /*-------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*/

    /**
     * Default no-argument constructor. Ensures the internal
     * {@link AuthenticationListener AuthenticationListener} collection is a non-null {@code ArrayList}.
     */
    public AbstractAuthenticator() {
        listeners = new ArrayList<AuthenticationListener>();
    }

    /*--------------------------------------------
    |  A C C E S S O R S / M O D I F I E R S    |
    ============================================*/

    /**
     * Sets the {@link AuthenticationListener AuthenticationListener}s that should be notified during authentication
     * attempts.
     *
     * @param listeners one or more {@code AuthenticationListener}s that should be notified due to an
     *                  authentication attempt.
     */
    @SuppressWarnings({"UnusedDeclaration"})
    public void setAuthenticationListeners(Collection<AuthenticationListener> listeners) {
        if (listeners == null) {
            this.listeners = new ArrayList<AuthenticationListener>();
        } else {
            this.listeners = listeners;
        }
    }

    /**
     * Returns the {@link AuthenticationListener AuthenticationListener}s that should be notified during authentication
     * attempts.
     *
     * @return the {@link AuthenticationListener AuthenticationListener}s that should be notified during authentication
     *         attempts.
     */
    @SuppressWarnings({"UnusedDeclaration"})
    public Collection<AuthenticationListener> getAuthenticationListeners() {
        return this.listeners;
    }

    /*-------------------------------------------
    |               M E T H O D S               |
    ============================================*/

    /**
     * Notifies any registered {@link AuthenticationListener AuthenticationListener}s that
     * authentication was successful for the specified {@code token} which resulted in the specified
     * {@code info}.  This implementation merely iterates over the internal {@code listeners} collection and
     * calls {@link AuthenticationListener#onSuccess(AuthenticationToken, AuthenticationInfo) onSuccess}
     * for each.
     *
     * @param token the submitted {@code AuthenticationToken} that resulted in a successful authentication.
     * @param info  the returned {@code AuthenticationInfo} resulting from the successful authentication.
     */
    protected void notifySuccess(AuthenticationToken token, AuthenticationInfo info) {
        for (AuthenticationListener listener : this.listeners) {
            listener.onSuccess(token, info);
        }
    }

    /**
     * Notifies any registered {@link AuthenticationListener AuthenticationListener}s that
     * authentication failed for the
     * specified {@code token} which resulted in the specified {@code ae} exception.  This implementation merely
     * iterates over the internal {@code listeners} collection and calls
     * {@link AuthenticationListener#onFailure(AuthenticationToken, AuthenticationException) onFailure}
     * for each.
     *
     * @param token the submitted {@code AuthenticationToken} that resulted in a failed authentication.
     * @param ae    the resulting {@code AuthenticationException} that caused the authentication to fail.
     */
    protected void notifyFailure(AuthenticationToken token, AuthenticationException ae) {
        for (AuthenticationListener listener : this.listeners) {
            listener.onFailure(token, ae);
        }
    }

    /**
     * Notifies any registered {@link AuthenticationListener AuthenticationListener}s that a
     * {@code Subject} has logged-out.  This implementation merely
     * iterates over the internal {@code listeners} collection and calls
     * {@link AuthenticationListener#onLogout(org.apache.shiro.subject.PrincipalCollection) onLogout}
     * for each.
     *
     * @param principals the identifying principals of the {@code Subject}/account logging out.
     */
    protected void notifyLogout(PrincipalCollection principals) {
        for (AuthenticationListener listener : this.listeners) {
            listener.onLogout(principals);
        }
    }

    /**
     * This implementation merely calls
     * {@link #notifyLogout(org.apache.shiro.subject.PrincipalCollection) notifyLogout} to allow any registered listeners
     * to react to the logout.
     *
     * @param principals the identifying principals of the {@code Subject}/account logging out.
     */
    public void onLogout(PrincipalCollection principals) {
        notifyLogout(principals);
    }

    /**
     * Implementation of the {@link Authenticator} interface that functions in the following manner:
     * <ol>
     * <li>Calls template {@link #doAuthenticate doAuthenticate} method for subclass execution of the actual
     * authentication behavior.</li>
     * <li>If an {@code AuthenticationException} is thrown during {@code doAuthenticate},
     * {@link #notifyFailure(AuthenticationToken, AuthenticationException) notify} any registered
     * {@link AuthenticationListener AuthenticationListener}s of the exception and then propogate the exception
     * for the caller to handle.</li>
     * <li>If no exception is thrown (indicating a successful login),
     * {@link #notifySuccess(AuthenticationToken, AuthenticationInfo) notify} any registered
     * {@link AuthenticationListener AuthenticationListener}s of the successful attempt.</li>
     * <li>Return the {@code AuthenticationInfo}</li>
     * </ol>
     *
     * @param token the submitted token representing the subject's (user's) login principals and credentials.
     * @return the AuthenticationInfo referencing the authenticated user's account data.
     * @throws AuthenticationException if there is any problem during the authentication process - see the
     *                                 interface's JavaDoc for a more detailed explanation.
     */
    public final AuthenticationInfo authenticate(AuthenticationToken token) throws AuthenticationException {

        if (token == null) {
            throw new IllegalArgumentException("Method argumet (authentication token) cannot be null.");
        }

        log.trace("Authentication attempt received for token [{}]", token);

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
            }
            try {
                notifyFailure(token, ae);
            } catch (Throwable t2) {
                if (log.isWarnEnabled()) {
                    String msg = "Unable to send notification for failed authentication attempt - listener error?.  " +
                            "Please check your AuthenticationListener implementation(s).  Logging sending exception " +
                            "and propagating original AuthenticationException instead...";
                    log.warn(msg, t2);
                }
            }


            throw ae;
        }

        log.debug("Authentication successful for token [{}].  Returned account [{}]", token, info);

        notifySuccess(token, info);

        return info;
    }

    /**
     * Template design pattern hook for subclasses to implement specific authentication behavior.
     * <p/>
     * Common behavior for most authentication attempts is encapsulated in the
     * {@link #authenticate} method and that method invokes this one for custom behavior.
     * <p/>
     * <b>N.B.</b> Subclasses <em>should</em> throw some kind of
     * {@code AuthenticationException} if there is a problem during
     * authentication instead of returning {@code null}.  A {@code null} return value indicates
     * a configuration or programming error, since {@code AuthenticationException}s should
     * indicate any expected problem (such as an unknown account or username, or invalid password, etc).
     *
     * @param token the authentication token encapsulating the user's login information.
     * @return an {@code AuthenticationInfo} object encapsulating the user's account information
     *         important to Shiro.
     * @throws AuthenticationException if there is a problem logging in the user.
     */
    protected abstract AuthenticationInfo doAuthenticate(AuthenticationToken token)
            throws AuthenticationException;


}
