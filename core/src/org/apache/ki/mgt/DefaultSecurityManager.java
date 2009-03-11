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

import java.io.Serializable;
import java.net.InetAddress;
import java.util.Collection;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.apache.ki.authc.AuthenticationException;
import org.apache.ki.authc.AuthenticationInfo;
import org.apache.ki.authc.AuthenticationToken;
import org.apache.ki.authc.Authenticator;
import org.apache.ki.authc.LogoutAware;
import org.apache.ki.authz.AuthorizationException;
import org.apache.ki.authz.Authorizer;
import org.apache.ki.crypto.Cipher;
import org.apache.ki.realm.Realm;
import org.apache.ki.session.InvalidSessionException;
import org.apache.ki.session.Session;
import org.apache.ki.session.mgt.DelegatingSession;
import org.apache.ki.subject.PrincipalCollection;
import org.apache.ki.subject.Subject;
import org.apache.ki.util.ThreadContext;


/**
 * <p>The JSecurity framework's default concrete implementation of the {@link SecurityManager} interface,
 * based around a collection of {@link org.apache.ki.realm.Realm}s.  This implementation delegates its
 * authentication, authorization, and session operations to wrapped {@link Authenticator}, {@link Authorizer}, and
 * {@link org.apache.ki.session.mgt.SessionManager SessionManager} instances respectively via superclass
 * implementation.</p>
 *
 * <p>To greatly reduce and simplify configuration, this implementation (and its superclasses) will
 * create suitable defaults for all of its required dependencies, <em>except</em> the required one or more
 * {@link Realm Realm}s.  Because <code>Realm</code> implementations usually interact with an application's data model,
 * they are almost always application specific;  you will want to specify at least one custom
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
 * instance yourself via the {@link #setRememberMeManager(RememberMeManager) setRememberMeManager}
 * mutator.  However if you're reading this JavaDoc with the
 * expectation of operating in a Web environment, take a look at the
 * {@link org.ki.web.DefaultWebSecurityManager DefaultWebSecurityManager} implementation, which
 * <em>does</em> support <tt>RememberMe</tt> services by default at startup.
 *
 * @author Les Hazlewood
 * @author Jeremy Haile
 * @see org.ki.web.DefaultWebSecurityManager
 * @since 0.2
 */
public class DefaultSecurityManager extends SessionsSecurityManager {

    //TODO - complete JavaDoc

    private static final Log log = LogFactory.getLog(DefaultSecurityManager.class);

    protected RememberMeManager rememberMeManager;

    protected SubjectFactory subjectFactory;

    protected SubjectBinder subjectBinder;

    /**
     * Default no-arg constructor.
     */
    public DefaultSecurityManager() {
        super();
        this.subjectFactory = new DefaultSubjectFactory(this);
        this.subjectBinder = new SessionSubjectBinder();
    }

    /**
     * Supporting constructor for a single-realm application.
     *
     * @param singleRealm the single realm used by this SecurityManager.
     */
    public DefaultSecurityManager(Realm singleRealm) {
        this();
        setRealm(singleRealm);
    }

    /**
     * Supporting constructor for multiple {@link #setRealms realms}.
     *
     * @param realms the realm instances backing this SecurityManager.
     */
    public DefaultSecurityManager(Collection<Realm> realms) {
        this();
        setRealms(realms);
    }

    public SubjectFactory getSubjectFactory() {
        return subjectFactory;
    }

    public void setSubjectFactory(SubjectFactory subjectFactory) {
        this.subjectFactory = subjectFactory;
        if (this.subjectFactory instanceof SecurityManagerAware) {
            ((SecurityManagerAware) this.subjectFactory).setSecurityManager(this);
        }
    }

    public SubjectBinder getSubjectBinder() {
        return subjectBinder;
    }

    public void setSubjectBinder(SubjectBinder subjectBinder) {
        this.subjectBinder = subjectBinder;
    }

    public RememberMeManager getRememberMeManager() {
        return rememberMeManager;
    }

    public void setRememberMeManager(RememberMeManager rememberMeManager) {
        this.rememberMeManager = rememberMeManager;
    }

    private AbstractRememberMeManager getRememberMeManagerForCipherAttributes() {
        if (!(this.rememberMeManager instanceof AbstractRememberMeManager)) {
            String msg = "The convenience passthrough methods for setting remember me cipher attributes " +
                    "are only available when the underlying RememberMeManager implementation is a subclass of " +
                    AbstractRememberMeManager.class.getName() + ".";
            throw new IllegalStateException(msg);
        }
        return (AbstractRememberMeManager) this.rememberMeManager;
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

    protected Subject createSubject() {
        Subject subject = null;

        Serializable sessionId = ThreadContext.getSessionId();
        if (sessionId != null) {
            try {
                subject = getSubjectBySessionId(sessionId);
            } catch (InvalidSessionException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Session id referenced on the current thread [" + sessionId + "] is invalid.  " +
                            "Ignoring and creating a new Subject instance to continue.  This message can be " +
                            "safely ignored.", e);
                }
            } catch (AuthorizationException e) {
                if (log.isWarnEnabled()) {
                    log.warn("Session id referenced on the current thread [" + sessionId + "] is not allowed to be " +
                            "referenced.  Ignoring and creating a Subject instance without a session to continue.", e);
                }
            }
        }

        if (subject == null) {
            PrincipalCollection principals = getRememberedIdentity();
            return getSubjectFactory().createSubject(principals, null, false, null);
        }

        return subject;
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
        return getSubjectFactory().createSubject(token, info, getSubject(false));
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
        getSubjectBinder().bind(subject);
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

    protected Subject getSubject(PrincipalCollection principals) {
        //Method arg is ignored at the moment - retrieve from the environment if it exists:
        return getSubject(false);
    }

    public void logout(PrincipalCollection principals) {

        Subject subject;

        if (principals != null) {
            beforeLogout(principals);
            Authenticator authc = getAuthenticator();
            if (authc instanceof LogoutAware) {
                ((LogoutAware) authc).onLogout(principals);
            }
            subject = getSubject(principals);
        } else {
            subject = getSubject(false);
        }

        try {
            unbind(subject);
        } catch (Exception e) {
            if (log.isDebugEnabled()) {
                String msg = "Unable to cleanly unbind Subject.  Ignoring (logging out).";
                log.debug(msg, e);
            }
        } finally {
            try {
                stopSession(subject);
            } catch (Exception e) {
                if (log.isDebugEnabled()) {
                    String msg = "Unable to cleanly stop Session for Subject [" + subject.getPrincipal() + "] " +
                            "Ignoring (logging out).";
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
        getSubjectBinder().unbind(subject);
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
        Subject subject = getSubjectBinder().getSubject();
        if (subject == null && create) {
            subject = createSubject();
            bind(subject);
        }
        return subject;
    }

    public Subject getSubject() {
        return getSubject(true);
    }

    protected PrincipalCollection getPrincipals(Session session) {
        return (PrincipalCollection) session.getAttribute(SessionSubjectBinder.PRINCIPALS_SESSION_KEY);
    }

    protected boolean isAuthenticated(Session session, PrincipalCollection principals) {
        if (principals != null) {
            Boolean authc = (Boolean) session.getAttribute(SessionSubjectBinder.AUTHENTICATED_SESSION_KEY);
            return authc != null && authc;
        }
        return false;
    }

    /**
     * Acquires the {@link Subject Subject} that owns the {@link Session Session} with the specified {@code sessionId}.
     *
     * <p><b>Although simple in concept, this method provides incredibly powerful functionality:</b>
     *
     * <p>The ability to reference a {@code Subject} and their server-side session
     * <em>across clients of different mediums</em> such as web applications, Java applets,
     * standalone C# clients over XMLRPC and/or SOAP, and many others. This is a <em>huge</em>
     * benefit in heterogeneous enterprise applications.
     *
     * <p>To maintain session integrity across client mediums, the {@code sessionId} <b>must</b> be transmitted
     * to all client mediums securely (e.g. over SSL) to prevent man-in-the-middle attacks.  This
     * is nothing new - all web applications are susceptible to the same problem when transmitting
     * {@code Cookie}s or when using URL rewriting.  As long as the
     * {@code sessionId} is transmitted securely, session integrity can be maintained.
     *
     * @param sessionId the id of the session that backs the desired Subject being acquired.
     * @return the {@code Subject} that owns the {@code Session Session} with the specified {@code sessionId}
     * @throws org.apache.ki.session.InvalidSessionException
     *          if the session identified by <tt>sessionId</tt> has
     *          been stopped, expired, or doesn't exist.
     * @throws org.apache.ki.authz.AuthorizationException
     *          if the executor of this method is not allowed to acquire the owning {@code Subject}.  The reason
     *          for the exception is implementation-specific and could be for any number of reasons.  A common
     *          reason in many systems would be if one host tried to acquire a {@code Subject} based on a
     *          {@code Session} that originated on an entirely different host (although it is not a JSecurity
     *          requirement this scenario is disallowed - its just an example that <em>may</em> throw an Exception in
     *          some systems).
     * @see org.apache.ki.authz.HostUnauthorizedException
     * @since 1.0
     */
    private Subject getSubjectBySessionId(Serializable sessionId) throws InvalidSessionException, AuthorizationException {
        if (!isValid(sessionId)) {
            String msg = "Specified id [" + sessionId + "] does not correspond to a valid Session  It either " +
                    "does not exist or the corresponding session has been stopped or expired.";
            throw new InvalidSessionException(msg, sessionId);
        }

        Session existing = new DelegatingSession(this, sessionId);
        PrincipalCollection principals = getPrincipals(existing);
        boolean authenticated = isAuthenticated(existing, principals);
        InetAddress host = existing.getHostAddress();

        return getSubjectFactory().createSubject(principals, existing, authenticated, host);
    }
}