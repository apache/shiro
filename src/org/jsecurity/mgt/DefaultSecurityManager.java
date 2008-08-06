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
package org.jsecurity.mgt;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.authc.*;
import org.jsecurity.authz.Authorizer;
import org.jsecurity.crypto.Cipher;
import org.jsecurity.realm.Realm;
import org.jsecurity.session.InvalidSessionException;
import org.jsecurity.session.Session;
import org.jsecurity.subject.*;
import org.jsecurity.util.ThreadContext;

import java.net.InetAddress;
import java.util.Collection;

/**
 * <p>The JSecurity framework's default concrete implementation of the {@link SecurityManager} interface,
 * based around a collection of {@link org.jsecurity.realm.Realm}s.  This implementation delegates its
 * authentication, authorization, and session operations to wrapped {@link Authenticator}, {@link Authorizer}, and
 * {@link org.jsecurity.session.mgt.SessionManager SessionManager} instances respectively via superclass
 * implementation.</p>
 *
 * <p>To greatly reduce and simplify configuration, this implementation (and its superclasses) will
 * create suitable defaults for <em>all</em> of its required dependencies.  Therefore, you only need to override
 * attributes for custom behavior.  But, note the following:</p>
 *
 * <p>Unless you're happy with the default simple {@link org.jsecurity.realm.text.PropertiesRealm properties file}-based realm, which may or
 * may not be flexible enough for enterprise applications, you might want to specify at least one custom
 * <tt>Realm</tt> implementation that 'knows' about your application's data/security model
 * (via {@link #setRealm} or one of the overloaded constructors).  All other attributes in this class hierarchy
 * will have suitable defaults for most enterprise applications.</p>
 *
 * <p><b>RememberMe notice</b>: This class supports the ability to configure a
 * {@link #setRememberMeManager RememberMeManager}
 * for <tt>RememberMe</tt> identity services for login/logout, BUT, a default instance <em>will not</em> be created
 * for this attribute at startup.
 *
 * <p>Because RememberMe services are inherently client tier-specific and
 * therefore aplication-dependent, if you want <tt>RememberMe</tt> services enabled, you will have to specify an
 * instance yourself via the {@link #setRememberMeManager(org.jsecurity.subject.RememberMeManager) setRememberMeManager}
 * mutator.  However if you're reading this JavaDoc with the
 * expectation of operating in a Web environment, take a look at the
 * {@link org.jsecurity.web.DefaultWebSecurityManager DefaultWebSecurityManager} implementation, which
 * <em>does</em> support <tt>RememberMe</tt> services by default at startup.
 *
 * @author Les Hazlewood
 * @author Jeremy Haile
 * @see org.jsecurity.web.DefaultWebSecurityManager
 * @since 0.2
 */
public class DefaultSecurityManager extends SessionsSecurityManager {

    private static final Log log = LogFactory.getLog(DefaultSecurityManager.class);

    protected RememberMeManager rememberMeManager;

    /**
     * Default no-arg constructor.
     */
    public DefaultSecurityManager() {
    }

    /**
     * Supporting constructor for a single-realm application.
     *
     * @param singleRealm the single realm used by this SecurityManager.
     */
    public DefaultSecurityManager(Realm singleRealm) {
        setRealm(singleRealm);
    }

    /**
     * Supporting constructor for multiple {@link #setRealms realms}.
     *
     * @param realms the realm instances backing this SecurityManager.
     */
    public DefaultSecurityManager(Collection<Realm> realms) {
        setRealms(realms);
    }

    public RememberMeManager getRememberMeManager() {
        return rememberMeManager;
    }

    public void setRememberMeManager(RememberMeManager rememberMeManager) {
        this.rememberMeManager = rememberMeManager;
    }

    private AbstractRememberMeManager getRememberMeManagerForCipherAttributes() {
        RememberMeManager rmm = getRememberMeManager();
        if (!(rmm instanceof AbstractRememberMeManager)) {
            String msg = "The convenience passthrough methods for setting remember me cipher attributes " +
                    "are only available when the underlying RememberMeManager implementation is a subclass of " +
                    AbstractRememberMeManager.class.getName() + ".";
            throw new IllegalStateException(msg);
        }
        return (AbstractRememberMeManager) rmm;
    }

    public void setRememberMeCipher(Cipher cipher) {
        getRememberMeManagerForCipherAttributes().setCipher(cipher);
    }

    public void setRememberMeCipherKey(byte[] bytes) {
        getRememberMeManagerForCipherAttributes().setCipherKey(bytes);
    }

    public void setRememberMeCipherKeyHex(String hex) {
        getRememberMeManagerForCipherAttributes().setCipherKeyHex(hex);
    }

    public void setRememberMeCipherKeyBase64(String base64) {
        getRememberMeManagerForCipherAttributes().setCipherKeyBase64(base64);
    }

    public void setRememberMeEncryptionCipherKey(byte[] bytes) {
        getRememberMeManagerForCipherAttributes().setEncryptionCipherKey(bytes);
    }

    public void setRememberMeEncryptionCipherKeyHex(String hex) {
        getRememberMeManagerForCipherAttributes().setEncryptionCipherKeyHex(hex);
    }

    public void setRememberMeEncryptionCipherKeyBase64(String base64) {
        getRememberMeManagerForCipherAttributes().setEncryptionCipherKeyBase64(base64);
    }

    public void setRememberMeDecryptionCipherKey(byte[] bytes) {
        getRememberMeManagerForCipherAttributes().setDecryptionCipherKey(bytes);
    }

    public void setRememberMeDecryptionCipherKeyHex(String hex) {
        getRememberMeManagerForCipherAttributes().setDecryptionCipherKeyHex(hex);
    }

    public void setRememberMeDecryptionCipherKeyBase64(String base64) {
        getRememberMeManagerForCipherAttributes().setDecryptionCipherKeyBase64(base64);
    }

    private void assertPrincipals(AuthenticationInfo info) {
        PrincipalCollection principals = info.getPrincipals();
        if (principals == null || principals.isEmpty()) {
            String msg = "Authentication info returned from Authenticator must have non null and non empty principals.";
            throw new IllegalArgumentException(msg);
        }
    }

    protected Subject createSubject() {
        PrincipalCollection principals = getRememberedIdentity();
        return createSubject(principals);
    }

    protected Subject createSubject(PrincipalCollection subjectPrincipals) {
        return createSubject(subjectPrincipals, null);
    }

    protected Subject createSubject(PrincipalCollection principals, Session existing) {
        return createSubject(principals, existing, false);
    }

    protected Subject createSubject(PrincipalCollection principals, Session existing, boolean authenticated) {
        return createSubject(principals, existing, authenticated, null);
    }

    protected Subject createSubject(PrincipalCollection principals, Session existing,
                                    boolean authenticated, InetAddress inetAddress) {
        return new DelegatingSubject(principals, authenticated, inetAddress, existing, this);
    }

    /**
     * Creates a <tt>Subject</tt> instance for the user represented by the given method arguments.
     *
     * @param token the <tt>AuthenticationToken</tt> submitted for the successful authentication.
     * @param info  the <tt>AuthenticationInfo</tt> of a newly authenticated user.
     * @return the <tt>Subject</tt> instance that represents the user and session data for the newly
     *         authenticated user.
     */
    protected Subject createSubject(AuthenticationToken token, AuthenticationInfo info) {
        assertPrincipals(info);

        //get any existing session that may exist - we don't want to lose it:
        Subject subject = getSubject(false);
        Session session = null;
        if (subject != null) {
            session = subject.getSession(false);
        }

        InetAddress authcSourceIP = null;
        if (token instanceof InetAuthenticationToken) {
            authcSourceIP = ((InetAuthenticationToken) token).getInetAddress();
        }
        if (authcSourceIP == null) {
            //try the thread local:
            authcSourceIP = ThreadContext.getInetAddress();
        }

        return createSubject(info.getPrincipals(), session, true, authcSourceIP);
    }

    /**
     * Binds a <tt>Subject</tt> instance created after authentication to the application for later use.
     *
     * <p>The default implementation merely binds the argument to the thread local via the {@link ThreadContext}.
     * Should be overridden by subclasses for environment-specific binding (e.g. web environment, etc).
     *
     * @param subject the <tt>Subject</tt> instance created after authentication to be bound to the application
     *                for later use.
     */
    protected void bind(Subject subject) {
        if (log.isTraceEnabled()) {
            log.trace("Binding Subject [" + subject + "] to a thread local...");
        }
        ThreadContext.bind(subject);
    }

    private void assertCreation(Subject subject) throws IllegalStateException {
        if (subject == null) {
            String msg = "Programming error - please verify that you have overridden the " +
                    getClass().getName() + ".createSubject( AuthenticationInfo info ) method to return " +
                    "a non-null Subject instance";
            throw new IllegalStateException(msg);
        }
    }

    protected void rememberMeSuccessfulLogin(AuthenticationToken token, AuthenticationInfo info) {
        RememberMeManager rmm = getRememberMeManager();
        if (rmm != null) {
            try {
                rmm.onSuccessfulLogin(token, info);
            } catch (Exception e) {
                if (log.isWarnEnabled()) {
                    String msg = "Delegate RememberMeManager instance of type [" + rmm.getClass().getName() +
                            "] threw an exception during onSuccessfulLogin.  RememberMe services will not be " +
                            "performed for account [" + info + "].";
                    log.warn(msg, e);
                }
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("This " + getClass().getName() + " instance does not have a " +
                        "[" + RememberMeManager.class.getName() + "] instance configured.  RememberMe services " +
                        "will not be performed for account [" + info + "].");
            }
        }
    }

    protected void rememberMeFailedLogin(AuthenticationToken token, AuthenticationException ex) {
        RememberMeManager rmm = getRememberMeManager();
        if (rmm != null) {
            try {
                rmm.onFailedLogin(token, ex);
            } catch (Exception e) {
                if (log.isWarnEnabled()) {
                    String msg = "Delegate RememberMeManager instance of type [" + rmm.getClass().getName() +
                            "] threw an exception during onFailedLogin for AuthenticationToken [" +
                            token + "].";
                    log.warn(msg, e);
                }
            }
        }
    }

    protected void rememberMeLogout(PrincipalCollection subjectPrincipals) {
        RememberMeManager rmm = getRememberMeManager();
        if (rmm != null) {
            try {
                rmm.onLogout(subjectPrincipals);
            } catch (Exception e) {
                if (log.isWarnEnabled()) {
                    String msg = "Delegate RememberMeManager instance of type [" + rmm.getClass().getName() +
                            "] threw an exception during onLogout for subject with principals [" +
                            subjectPrincipals + "]";
                    log.warn(msg, e);
                }
            }
        }
    }

    /**
     * First authenticates the <tt>AuthenticationToken</tt> argument, and if successful, constructs a
     * <tt>Subject</tt> instance representing the authenticated account's identity.
     *
     * <p>Once constructed, the <tt>Subject</tt> instance is then {@link #bind bound} to the application for
     * subsequent access before being returned to the caller.
     *
     * @param token the authenticationToken to process for the login attempt.
     * @return a Subject representing the authenticated user.
     * @throws AuthenticationException if there is a problem authenticating the specified <tt>token</tt>.
     */
    public Subject login(AuthenticationToken token) throws AuthenticationException {
        AuthenticationInfo info;
        try {
            info = authenticate(token);
            onSuccessfulLogin(token, info);
        } catch (AuthenticationException ae) {
            try {
                onFailedLogin(token, ae);
            } catch (Exception e) {
                if (log.isInfoEnabled()) {
                    log.info("onFailedLogin(AuthenticationToken,AuthenticationException) method threw an " +
                            "exception.  Logging and propagating original AuthenticationException.", e);
                }
            }
            throw ae; //propagate
        }
        Subject subject = createSubject(token, info);
        assertCreation(subject);
        bind(subject);
        return subject;
    }

    protected void onSuccessfulLogin(AuthenticationToken token, AuthenticationInfo info) {
        rememberMeSuccessfulLogin(token, info);
    }

    protected void onFailedLogin(AuthenticationToken token, AuthenticationException ae) {
        rememberMeFailedLogin(token, ae);
    }

    protected void beforeLogout(PrincipalCollection subjectIdentifier) {
        rememberMeLogout(subjectIdentifier);
    }

    public void logout(PrincipalCollection principals) {

        if (principals != null) {

            beforeLogout(principals);

            Authenticator authc = getAuthenticator();
            if (authc instanceof LogoutAware) {
                ((LogoutAware) authc).onLogout(principals);
            }
        }

        //Method arg is ignored - get the Subject from the environment if it exists:
        Subject subject = getSubject(false);
        if (subject != null) {
            try {
                stopSession(subject);
            } catch (Exception e) {
                if (log.isDebugEnabled()) {
                    String msg = "Unable to cleanly stop Session for Subject [" + subject.getPrincipal() + "] " +
                            "Ignoring (logging out).";
                    log.debug(msg, e);
                }
            }
            try {
                unbind(subject);
            } catch (Exception e) {
                if (log.isDebugEnabled()) {
                    String msg = "Unable to cleanly unbind Subject.  Ignoring (logging out).";
                    log.debug(msg, e);
                }
            }
        }
    }

    protected void stopSession(Subject subject) {
        Session s = subject.getSession(false);
        if (s != null) {
            try {
                s.stop();
            } catch (InvalidSessionException ise) {
                //ignored - we're invalidating, and have no further need of the session anyway
                //log just in case someone wants to know:
                if (log.isTraceEnabled()) {
                    log.trace("Session has already been invalidated for subject [" +
                            subject.getPrincipal() + "].  Ignoring and continuing logout ...", ise);
                }
            }
        }
    }

    protected void unbind(Subject subject) {
        ThreadContext.unbindSubject();
    }

    protected PrincipalCollection getRememberedIdentity() {
        RememberMeManager rmm = getRememberMeManager();
        if (rmm != null) {
            try {
                return rmm.getRememberedPrincipals();
            } catch (Exception e) {
                if (log.isWarnEnabled()) {
                    String msg = "Delegate RememberMeManager instance of type [" + rmm.getClass().getName() +
                            "] threw an exception during getRememberedPrincipals().";
                    log.warn(msg, e);
                }
            }
        }
        return null;
    }

    protected Subject getSubject(boolean create) {
        Subject subject = ThreadContext.getSubject();
        if (subject == null && create) {
            subject = createSubject();
            bind(subject);
        }
        return subject;
    }

    public Subject getSubject() {
        return getSubject(true);
    }
}