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
package org.apache.shiro.mgt;

import org.apache.shiro.authc.*;
import org.apache.shiro.authz.Authorizer;
import org.apache.shiro.crypto.Cipher;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.session.InvalidSessionException;
import org.apache.shiro.session.Session;
import org.apache.shiro.session.SessionException;
import org.apache.shiro.session.mgt.DelegatingSession;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Serializable;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

/**
 * The Shiro framework's default concrete implementation of the {@link SecurityManager} interface,
 * based around a collection of {@link org.apache.shiro.realm.Realm}s.  This implementation delegates its
 * authentication, authorization, and session operations to wrapped {@link Authenticator}, {@link Authorizer}, and
 * {@link org.apache.shiro.session.mgt.SessionManager SessionManager} instances respectively via superclass
 * implementation.
 * <p/>
 * To greatly reduce and simplify configuration, this implementation (and its superclasses) will
 * create suitable defaults for all of its required dependencies, <em>except</em> the required one or more
 * {@link Realm Realm}s.  Because {@code Realm} implementations usually interact with an application's data model,
 * they are almost always application specific;  you will want to specify at least one custom
 * {@code Realm} implementation that 'knows' about your application's data/security model
 * (via {@link #setRealm} or one of the overloaded constructors).  All other attributes in this class hierarchy
 * will have suitable defaults for most enterprise applications.
 * <p/>
 * <b>RememberMe notice</b>: This class supports the ability to configure a
 * {@link #setRememberMeManager RememberMeManager}
 * for {@code RememberMe} identity services for login/logout, BUT, a default instance <em>will not</em> be created
 * for this attribute at startup.
 * <p/>
 * Because RememberMe services are inherently client tier-specific and
 * therefore aplication-dependent, if you want {@code RememberMe} services enabled, you will have to specify an
 * instance yourself via the {@link #setRememberMeManager(RememberMeManager) setRememberMeManager}
 * mutator.  However if you're reading this JavaDoc with the
 * expectation of operating in a Web environment, take a look at the
 * {@code org.apache.shiro.web.DefaultWebSecurityManager} implementation, which
 * <em>does</em> support {@code RememberMe} services by default at startup.
 *
 * @author Les Hazlewood
 * @author Jeremy Haile
 * @since 0.2
 */
public class DefaultSecurityManager extends SessionsSecurityManager {

    //TODO - complete JavaDoc

    private static final Logger log = LoggerFactory.getLogger(DefaultSecurityManager.class);

    protected RememberMeManager rememberMeManager;

    protected SubjectFactory subjectFactory;

    protected SubjectBinder subjectBinder;

    /**
     * Default no-arg constructor.
     */
    public DefaultSecurityManager() {
        super();
        this.subjectFactory = new DefaultSubjectFactory();
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

    protected Session getSession(Serializable id) {
        checkValid(id);
        return new DelegatingSession(this, id);
    }

    /**
     * Creates a {@code Subject} instance for the user represented by the given method arguments.
     *
     * @param token    the {@code AuthenticationToken} submitted for the successful authentication.
     * @param info     the {@code AuthenticationInfo} of a newly authenticated user.
     * @param existing the existing {@code Subject} instance that initiated the authentication attempt
     * @return the {@code Subject} instance that represents the context and session data for the newly
     *         authenticated subject.
     */
    protected Subject createSubject(AuthenticationToken token, AuthenticationInfo info, Subject existing) {
        Map<String, Object> context = new HashMap<String, Object>();
        context.put(SubjectFactory.AUTHENTICATED, Boolean.TRUE);
        context.put(SubjectFactory.AUTHENTICATION_TOKEN, token);
        context.put(SubjectFactory.AUTHENTICATION_INFO, info);
        if (existing != null) {
            context.put(SubjectFactory.SUBJECT, existing);
        }
        return createSubject(context);
    }

    /**
     * Binds a {@code Subject} instance created after authentication to the application for later use.
     * <p/>
     * The default implementation simply delegates to the internal {@link #getSubjectBinder() subjectBinder}.
     *
     * @param subject the {@code Subject} instance created after authentication to be bound to the application
     *                for later use.
     */
    protected void bind(Subject subject) {
        getSubjectBinder().bind(subject);
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
            if (log.isTraceEnabled()) {
                log.trace("This " + getClass().getName() + " instance does not have a " +
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
     * First authenticates the {@code AuthenticationToken} argument, and if successful, constructs a
     * {@code Subject} instance representing the authenticated account's identity.
     * <p/>
     * Once constructed, the {@code Subject} instance is then {@link #bind bound} to the application for
     * subsequent access before being returned to the caller.
     *
     * @param token the authenticationToken to process for the login attempt.
     * @return a Subject representing the authenticated user.
     * @throws AuthenticationException if there is a problem authenticating the specified {@code token}.
     */
    public Subject login(Subject subject, AuthenticationToken token) throws AuthenticationException {
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
        Subject replaced = createSubject(token, info, subject);
        //TODO - is binding necessary anymore?  Shouldn't the Builders or Builder callers do this now?
        bind(replaced);
        return replaced;
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

    /**
     * This implementation attempts to resolve any session ID that may exist in the context argument by
     * passing it to the {@link #resolveSession(Map)} method.  The
     * return value from that call is then used to attempt to resolve the subject identity via the
     * {@link #resolvePrincipals(java.util.Map)} method.  The return value from that call is then used to create
     * the {@code Subject} instance by calling
     * <code>{@link #getSubjectFactory() getSubjectFactory()}.{@link SubjectFactory#createSubject(java.util.Map) createSubject}(resolvedContext);</code>
     *
     * @param context any data needed to direct how the Subject should be constructed.
     * @return the {@code Subject} instance reflecting the specified initialization data.
     * @see SubjectFactory#createSubject(java.util.Map)
     * @since 1.0
     */
    public Subject createSubject(Map context) {
        if (context == null) {
            context = new HashMap();
        }

        //ensure that the context map has a SecurityManager instance, and if not, add one:
        Map resolved = ensureSecurityManager(context);

        //Translate a session id if it exists into a Session object before sending to the SubjectFactory
        //The SubjectFactory should not need to know how to acquire sessions as it is often environment
        //specific - better to shield the SF from these details:
        resolved = resolveSession(resolved);

        //Similarly, the SubjectFactory should not have any concept of RememberMe - translate that here first
        //if possible before handing off to the SubjectFactory:
        resolved = resolvePrincipals(resolved);

        return getSubjectFactory().createSubject(resolved);
    }

    /**
     * Determines if there is a {@code SecurityManager} instance in the context map under the
     * {@link SubjectFactory#SECURITY_MANAGER} key, and if not, adds 'this' to the map under that key.  This ensures
     * the SubjectFactory instance will have access to a SecurityManager during Subject construction if necessary.
     *
     * @param context the subject context data that may contain a SecurityManager instance.
     * @return The context Map to use to pass to a {@link SubjectFactory} for subject creation.
     * @since 1.0
     */
    @SuppressWarnings({"unchecked"})
    protected Map ensureSecurityManager(Map context) {
        if (context.containsKey(SubjectFactory.SECURITY_MANAGER)) {
            log.debug("Context already contains a SecurityManager instance.  Returning.");
            return context;
        }
        log.trace("No SecurityManager found in context.  Adding self reference.");
        context.put(SubjectFactory.SECURITY_MANAGER, this);
        return context;
    }

    /**
     * Attempts to resolve any session id in the context to its corresponding {@link Session} and returns a
     * context that represents this resolved {@code Session} to ensure it may be referenced if necessary by the
     * invoked {@link SubjectFactory} that performs actual {@link Subject} construction.
     * <p/>
     * The session id, if it exists in the context map, should be available as a value under the
     * <code>{@link SubjectFactory SubjectFactory}.{@link SubjectFactory#SESSION_ID SESSION_ID}</code> key constant.
     * If a session is resolved, a copy of the original context Map is made to ensure the method argument is not
     * changed, the resolved session is placed into the copy and the copy is returned.
     * <p/>
     * If there is a {@code Session} already in the context because that is what the caller wants to be used for
     * {@code Subject} construction, or if no session is resolved, this method effectively does nothing and immediately
     * returns the Map method argument unaltered.
     *
     * @param context the subject context data that may contain a session id that should be converted to a Session instance.
     * @return The context Map to use to pass to a {@link SubjectFactory} for subject creation.
     * @since 1.0
     */
    @SuppressWarnings({"unchecked"})
    protected Map resolveSession(Map context) {
        if (context.containsKey(SubjectFactory.SESSION)) {
            log.debug("Context already contains a session.  Returning.");
            return context;
        }
        log.trace("No session found in context.  Looking for a session id to resolve in to a session.");
        //otherwise try to resolve a session if a session id exists:
        Serializable sessionId = getSessionId(context);
        if (sessionId != null) {
            try {
                Session session = getSession(sessionId);
                context.put(SubjectFactory.SESSION, session);
            } catch (InvalidSessionException e) {
                onInvalidSessionId(sessionId, e);
                log.debug("Context referenced sessionId is invalid.  Ignoring and creating an anonymous " +
                        "(session-less) Subject instance.", e);
            }
        }
        return context;
    }

    /**
     * Heuristically determines if the specified subject map can resolve a Subject identity ({@link PrincipalCollection})
     * either directly or indirectly by value association.  This implementation returns {@code true} in the following
     * two cases, {@code false} otherwise:
     * <ol>
     * <li>If the context {@link Map#containsKey contains} a key {@link SubjectFactory#PRINCIPALS}, it is assumed
     * the identity has been explicitly provided already.</li>
     * <li>If the context has a {@link Session} under the {@link SubjectFactory#SESSION} key, it attempts to resolve
     * any identity associated with that {@code Session} instance.  If one can be found in the {@code Session}, it is
     * assumed that {@code Session} identity should be used/retained.</li>
     * </ol>
     *
     * @param context the subject context data that may provide (directly or indirectly through one of its values) a
     *                {@link PrincipalCollection} identity.
     * @return {@code true} if an identity can be resolved, {@code false} otherwise.
     * @since 1.0
     */
    protected boolean containsIdentity(Map context) {
        if (context.containsKey(SubjectFactory.PRINCIPALS)) {
            log.trace("Context already contains an explicit identity.");
            return true;
        }
        if (context.containsKey(SubjectFactory.SESSION)) {
            Session session = (Session) context.get(SubjectFactory.SESSION);
            if (session != null) {
                Object principals = session.getAttribute(SessionSubjectBinder.PRINCIPALS_SESSION_KEY);
                if (principals != null) {
                    log.trace("Context already contains an implicit (session-based) identity.");
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Attempts to resolve an identity (a {@link PrincipalCollection}) for the context using heuristics.  The
     * implementation strategy:
     * <ol>
     * <li>Check the context to see if it already {@link #containsIdentity(java.util.Map) contains an identity}.  If
     * so, this method does nothing and returns the method argument unaltered.</li>
     * <li>Check for a RememberMe identity by calling {@link #getRememberedIdentity()}.  If that method returns a
     * non-null value, create a <em>copy</em> of the method argument, and place the remembered {@link PrincipalCollection}
     * in the copied context map under the {@link SubjectFactory#PRINCIPALS} key and return that copied context.</li>
     * </ol>
     *
     * @param context the subject context data that may provide (directly or indirectly through one of its values) a
     *                {@link PrincipalCollection} identity.
     * @return The context Map to use to pass to a {@link SubjectFactory} for subject creation.
     * @since 1.0
     */
    @SuppressWarnings({"unchecked"})
    protected Map resolvePrincipals(Map context) {
        if (!containsIdentity(context)) {
            log.trace("No identity (PrincipalCollection) found in the context.  Looking for a remembered identity.");
            PrincipalCollection principals = getRememberedIdentity();
            if (principals != null) {
                log.debug("Found remembered PrincipalCollection.  Adding to the context to be used " +
                        "for subject construction by the SubjectFactory.");
                context.put(SubjectFactory.PRINCIPALS, principals);
            } else {
                log.trace("No remembered identity found.  Returning original context.");
            }
        }

        return context;
    }

    /**
     * Allows subclasses to react to the fact that a specified/referenced session id was invalid.  Default
     * implementation does nothing (no-op).
     *
     * @param sessionId the session id that was discovered to be invalid (no session, expired, etc).
     * @param e         the exception thrown upon encountering the invalid session id
     * @since 1.0
     */
    protected void onInvalidSessionId(Serializable sessionId, InvalidSessionException e) {
    }

    /**
     * Utility method to retrieve the session id from the given subject context Map which will be used to resolve
     * to a {@link Session} or {@code null} if there is no session id in the map.  If the session id exists, it is
     * expected to be available in the map under the
     * <code>{@link SubjectFactory SubjectFactory}.{@link SubjectFactory#SESSION_ID SESSION_ID}</code> constant.
     *
     * @param subjectContext the context map with data that will be used to construct a {@link Subject} instance via
     *                       a {@link SubjectFactory}
     * @return a session id to resolve to a {@link Session} instance or {@code null} if a session id could not be found.
     * @see #createSubject(java.util.Map)
     * @see SubjectFactory#createSubject(java.util.Map)
     */
    protected Serializable getSessionId(Map subjectContext) {
        return (Serializable) subjectContext.get(SubjectFactory.SESSION_ID);
    }

    public void logout(Subject subject) {

        if (subject == null) {
            throw new IllegalArgumentException("Subject method argument cannot be null.");
        }

        PrincipalCollection principals = subject.getPrincipals();

        if (principals != null && !principals.isEmpty()) {
            if (log.isDebugEnabled()) {
                log.debug("Logging out subject with primary principal {}" + principals.getPrimaryPrincipal());
            }
            beforeLogout(principals);
            Authenticator authc = getAuthenticator();
            if (authc instanceof LogoutAware) {
                ((LogoutAware) authc).onLogout(principals);
            }
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
            //react to the id and not the session itself - the Session instance could be a proxy/delegate Session
            //in which case the ID might be the only thing accessible.  Better to pass off the ID to the underlying
            //SessionManager since this will successfully handle all cases.
            Serializable sessionId = s.getId();
            if (sessionId != null) {
                try {
                    stop(sessionId);
                } catch (SessionException e) {
                    //ignored - we're invalidating, and have no further need of the session anyway
                    //log just in case someone wants to know:
                    if (log.isDebugEnabled()) {
                        String msg = "Session for Subject [" + (subject != null ? subject.getPrincipal() : null) +
                                "] has already been invalidated.  Logging exception since session exceptions are " +
                                "irrelevant when the owning Subject has logged out.";
                        log.debug(msg, e);
                    }
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

    public Subject getSubject() {
        Subject subject = getSubjectBinder().getSubject();
        if (subject == null) {
            subject = createSubject(new HashMap());
            bind(subject);
        }
        return subject;
    }
}
