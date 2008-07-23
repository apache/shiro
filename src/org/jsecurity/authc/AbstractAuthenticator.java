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
package org.jsecurity.authc;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.subject.PrincipalCollection;

import java.util.ArrayList;
import java.util.Collection;

/**
 * Superclass for almost all {@link Authenticator} implementations that performs the common work around authentication
 * attempts.
 *
 * <p>This class delegates the actual authentication attempt to subclasses but supports notification for
 * successful and failed logins as well as logouts. Notification is sent to one or more registered
 * {@link org.jsecurity.authc.AuthenticationListener AuthenticationListener}s to allow for custom processing logic
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
    protected transient final Log log = LogFactory.getLog(getClass());

    /*--------------------------------------------
    |    I N S T A N C E   V A R I A B L E S    |
    ============================================*/
    private Collection<AuthenticationListener> listeners = new ArrayList<AuthenticationListener>();

    /*--------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*/
    public AbstractAuthenticator() {
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
    protected void notifySuccess(AuthenticationToken token, AuthenticationInfo info) {
        for (AuthenticationListener listener : this.listeners) {
            listener.onSuccess(token, info);
        }
    }

    protected void notifyFailure(AuthenticationToken token, AuthenticationException ae) {
        for (AuthenticationListener listener : this.listeners) {
            listener.onFailure(token, ae);
        }
    }

    protected void notifyLogout(PrincipalCollection principals) {
        for (AuthenticationListener listener : this.listeners) {
            listener.onLogout(principals);
        }
    }

    public void onLogout(PrincipalCollection principals) {
        notifyLogout(principals);
    }


    /**
     * Implementation of the {@link Authenticator} interface that functions in the following manner:
     *
     * <ol>
     * <li>Calls template {@link #doAuthenticate doAuthenticate} method for subclass execution of the actual
     * authentication behavior.</li>
     * <li>If an <tt>AuthenticationException</tt> is thrown during <tt>doAuthenticate</tt>, create and send a
     * failure <tt>AuthenticationEvent</tt> that represents this failure, and then propogate this exception
     * for the caller to handle.</li>
     * <li>If no exception is thrown (indicating a successful login), send a success <tt>AuthenticationEvent</tt>
     * noting the successful authentication.</li>
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

        if (log.isInfoEnabled()) {
            log.info("Authentication successful for token [" + token + "].  " +
                    "Returned account: [" + info + "]");
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
     *         important to JSecurity.
     * @throws AuthenticationException if there is a problem logging in the user.
     */
    protected abstract AuthenticationInfo doAuthenticate(AuthenticationToken token)
            throws AuthenticationException;


}