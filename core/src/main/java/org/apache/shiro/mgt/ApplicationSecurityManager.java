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

import org.apache.shiro.account.Account;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.Authenticator;
import org.apache.shiro.authc.DefaultAuthenticator;
import org.apache.shiro.authc.LogoutAware;
import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.authz.Authorizer;
import org.apache.shiro.authz.ModularRealmAuthorizer;
import org.apache.shiro.authz.Permission;
import org.apache.shiro.cache.CacheManager;
import org.apache.shiro.cache.CacheManagerAware;
import org.apache.shiro.cache.DisabledCacheManager;
import org.apache.shiro.event.EventBus;
import org.apache.shiro.event.EventBusAware;
import org.apache.shiro.event.support.DefaultEventBus;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.session.InvalidSessionException;
import org.apache.shiro.session.Session;
import org.apache.shiro.session.SessionException;
import org.apache.shiro.session.mgt.DefaultSessionContext;
import org.apache.shiro.session.mgt.DefaultSessionKey;
import org.apache.shiro.session.mgt.SessionContext;
import org.apache.shiro.session.mgt.SessionKey;
import org.apache.shiro.session.mgt.SessionManager;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.subject.SubjectContext;
import org.apache.shiro.subject.support.DefaultSubjectContext;
import org.apache.shiro.util.Assert;
import org.apache.shiro.util.CollectionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Serializable;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Set;

/** @since 2.0 */
public class ApplicationSecurityManager implements SecurityManager, EventBusAware, CacheManagerAware {

    private static final Logger log = LoggerFactory.getLogger(ApplicationSecurityManager.class);

    /** The EventBus to use to use to publish and receive events of interest during Shiro's operation.  Never null. */
    private EventBus eventBus;

    /**
     * The CacheManager to use to perform caching operations to enhance performance.
     * Cannot be null - to disable caching, a DisabledCacheManager should be configured (the default).
     */
    private CacheManager cacheManager;

    private Collection<Realm> realms;

    private Authenticator  authenticator;
    private Authorizer     authorizer;
    private SessionManager sessionManager;

    private RememberMeManager rememberMeManager;
    private SubjectDAO        subjectDAO;
    private SubjectFactory    subjectFactory;

    public ApplicationSecurityManager() {
        this.eventBus = new DefaultEventBus();
        setCacheManager(new DisabledCacheManager());

        // ===== Authenticator =====
        DefaultAuthenticator authenticator = new DefaultAuthenticator();
        authenticator.setEventBus(this.eventBus);
        setAuthenticator(authenticator);

        // ===== Authorizer =====
        setAuthorizer(new ModularRealmAuthorizer());
    }

    /* ===================================================================== *
     * Getters and Setters                                                   *
     * ===================================================================== */

    private Set<Object> getDependenciesForInjection(Object ignore) {
        Set<Object> deps = CollectionUtils.asSet(
            eventBus, cacheManager, realms, authenticator, authorizer, sessionManager,
            rememberMeManager, subjectDAO, subjectFactory
        );
        if (ignore != null) {
            deps.remove(ignore);
        }
        return deps;
    }

    public Collection<Realm> getRealms() {
        return realms;
    }

    public void setRealms(Collection<Realm> realms) {
        Assert.notEmpty(realms, "Realms argument cannot be empty.");
        Collection<Realm> immutableRealmsCollection = Collections.unmodifiableCollection(realms);
        this.realms = immutableRealmsCollection;
        applyEventBus(this.realms);
        applyCacheManager(this.realms);
        Authenticator authc = this.authenticator;
        if (authc instanceof DefaultAuthenticator) {
            ((DefaultAuthenticator) authc).setRealms(immutableRealmsCollection);
        }
        Authorizer authz = this.authorizer;
        if (authz instanceof ModularRealmAuthorizer) {
            ((ModularRealmAuthorizer) authz).setRealms(immutableRealmsCollection);
        }
    }

    public EventBus getEventBus() {
        return eventBus;
    }

    public void setEventBus(EventBus eventBus) {
        Assert.notNull(eventBus, "EventBus argument cannot be null.");
        this.eventBus = eventBus;
        applyEventBus(getDependenciesForInjection(this.eventBus));
    }

    private void applyEventBus(Object target) {
        if (target instanceof Collection) {
            Collection c = (Collection) target;
            for (Object o : c) {
                applyEventBus(o);
            }
        }
        if (target instanceof EventBusAware) {
            ((EventBusAware) target).setEventBus(this.eventBus);
        }
    }

    public CacheManager getCacheManager() {
        return cacheManager;
    }

    public void setCacheManager(CacheManager cacheManager) {
        Assert.notNull(cacheManager, "CacheManager cannot be null.  If you want to disable caching, configure a " +
                                     DisabledCacheManager.class.getName() + " instance.");
        this.cacheManager = cacheManager;
        applyCacheManager(getDependenciesForInjection(this.cacheManager));
    }

    private void applyCacheManager(Object target) {
        if (target instanceof Collection) {
            Collection c = (Collection) target;
            for (Object o : c) {
                applyCacheManager(o);
            }
        }
        if (target instanceof CacheManagerAware) {
            ((CacheManagerAware) target).setCacheManager(this.cacheManager);
        }
    }

    public Authenticator getAuthenticator() {
        return authenticator;
    }

    public void setAuthenticator(Authenticator authenticator) {
        Assert.notNull(authenticator, "Authenticator argument cannot be null.");
        this.authenticator = authenticator;
        if (this.authenticator instanceof DefaultAuthenticator) {
            ((DefaultAuthenticator) this.authenticator).setRealms(this.realms);
        }
        applyEventBus(this.authenticator);
        applyCacheManager(this.authenticator);
    }

    public Authorizer getAuthorizer() {
        return authorizer;
    }

    public void setAuthorizer(Authorizer authorizer) {
        Assert.notNull(authorizer, "Authorizer argument cannot be null.");
        this.authorizer = authorizer;
        applyEventBus(this.authorizer);
        applyCacheManager(this.authorizer);
    }

    public SessionManager getSessionManager() {
        return sessionManager;
    }

    public void setSessionManager(SessionManager sessionManager) {
        this.sessionManager = sessionManager;
    }

    /**
     * Returns the {@code SubjectFactory} responsible for creating {@link Subject} instances exposed to the
     * application.
     *
     * @return the {@code SubjectFactory} responsible for creating {@link Subject} instances exposed to the
     *         application.
     */
    public SubjectFactory getSubjectFactory() {
        return subjectFactory;
    }

    /**
     * Sets the {@code SubjectFactory} responsible for creating {@link Subject} instances exposed to the application.
     *
     * @param subjectFactory the {@code SubjectFactory} responsible for creating {@link Subject} instances exposed to
     *                       the application.
     */
    public void setSubjectFactory(SubjectFactory subjectFactory) {
        this.subjectFactory = subjectFactory;
    }

    /**
     * Returns the {@code SubjectDAO} responsible for persisting Subject state, typically used after login or when an
     * Subject identity is discovered (eg after RememberMe services).  Unless configured otherwise, the default
     * implementation is a {@link DefaultSubjectDAO}.
     *
     * @return the {@code SubjectDAO} responsible for persisting Subject state, typically used after login or when an
     *         Subject identity is discovered (eg after RememberMe services).
     * @see DefaultSubjectDAO
     */
    public SubjectDAO getSubjectDAO() {
        return subjectDAO;
    }

    /**
     * Sets the {@code SubjectDAO} responsible for persisting Subject state, typically used after login or when an
     * Subject identity is discovered (eg after RememberMe services). Unless configured otherwise, the default
     * implementation is a {@link DefaultSubjectDAO}.
     *
     * @param subjectDAO the {@code SubjectDAO} responsible for persisting Subject state, typically used after login or
     *                   when an
     *                   Subject identity is discovered (eg after RememberMe services).
     * @see DefaultSubjectDAO
     */
    public void setSubjectDAO(SubjectDAO subjectDAO) {
        this.subjectDAO = subjectDAO;
    }

    public RememberMeManager getRememberMeManager() {
        return rememberMeManager;
    }

    public void setRememberMeManager(RememberMeManager rememberMeManager) {
        this.rememberMeManager = rememberMeManager;
    }

    /* ===================================================================== *
     * Authenticator Methods                                                 *
     * ===================================================================== */

    public AuthenticationInfo authenticate(AuthenticationToken authenticationToken) throws AuthenticationException {
        return this.authenticator.authenticate(authenticationToken);
    }

    public Account authenticateAccount(AuthenticationToken authenticationToken) throws AuthenticationException {
        return this.authenticator.authenticateAccount(authenticationToken);
    }

    /* ===================================================================== *
     * Authorizer Methods                                                    *
     * ===================================================================== */

    public boolean isPermitted(PrincipalCollection principals, String permission) {
        return this.authorizer.isPermitted(principals, permission);
    }

    public boolean isPermitted(PrincipalCollection principals, Permission permission) {
        return this.authorizer.isPermitted(principals, permission);
    }

    public boolean[] isPermitted(PrincipalCollection principals, String... permissions) {
        return this.authorizer.isPermitted(principals, permissions);
    }

    public boolean[] isPermitted(PrincipalCollection principals, List<Permission> permissions) {
        return this.authorizer.isPermitted(principals, permissions);
    }

    public boolean isPermittedAll(PrincipalCollection principals, String... permissions) {
        return this.authorizer.isPermittedAll(principals, permissions);
    }

    public boolean isPermittedAll(PrincipalCollection principals, Collection<Permission> permissions) {
        return this.authorizer.isPermittedAll(principals, permissions);
    }

    public void checkPermission(PrincipalCollection principals, String permission) throws AuthorizationException {
        this.authorizer.checkPermission(principals, permission);
    }

    public void checkPermission(PrincipalCollection principals, Permission permission) throws AuthorizationException {
        this.authorizer.checkPermission(principals, permission);
    }

    public void checkPermissions(PrincipalCollection principals, String... permissions) throws AuthorizationException {
        this.authorizer.checkPermissions(principals, permissions);
    }

    public void checkPermissions(PrincipalCollection principals, Collection<Permission> permissions)
        throws AuthorizationException {
        this.authorizer.checkPermissions(principals, permissions);
    }

    public boolean hasRole(PrincipalCollection principals, String roleIdentifier) {
        return this.authorizer.hasRole(principals, roleIdentifier);
    }

    public boolean[] hasRoles(PrincipalCollection principals, List<String> roleIdentifiers) {
        return this.authorizer.hasRoles(principals, roleIdentifiers);
    }

    public boolean hasAllRoles(PrincipalCollection principals, Collection<String> roleIdentifiers) {
        return this.authorizer.hasAllRoles(principals, roleIdentifiers);
    }

    public void checkRole(PrincipalCollection principals, String roleIdentifier) throws AuthorizationException {
        this.authorizer.checkRole(principals, roleIdentifier);
    }

    public void checkRoles(PrincipalCollection principals, Collection<String> roleIdentifiers)
        throws AuthorizationException {
        this.authorizer.checkRoles(principals, roleIdentifiers);
    }

    public void checkRoles(PrincipalCollection principals, String... roleIdentifiers)
        throws AuthorizationException {
        this.authorizer.checkRoles(principals, roleIdentifiers);
    }

    /* ===================================================================== *
     * SessionManager Methods                                                *
     * ===================================================================== */

    public Session start(SessionContext context) {
        return this.sessionManager.start(context);
    }

    public Session getSession(SessionKey key) throws SessionException {
        return this.sessionManager.getSession(key);
    }

    /* ===================================================================== *
     * SecurityManager Methods                                               *
     * ===================================================================== */

    protected SubjectContext createSubjectContext() {
        return new DefaultSubjectContext();
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
        SubjectContext context = createSubjectContext();
        context.setAuthenticated(true);
        context.setAuthenticationToken(token);
        context.setAuthenticationInfo(info);
        if (existing != null) {
            context.setSubject(existing);
        }
        return createSubject(context);
    }

    /**
     * Binds a {@code Subject} instance created after authentication to the application for later use.
     * <p/>
     * As of Shiro 1.2, this method has been deprecated in favor of {@link #save(org.apache.shiro.subject.Subject)},
     * which this implementation now calls.
     *
     * @param subject the {@code Subject} instance created after authentication to be bound to the application
     *                for later use.
     * @see #save(org.apache.shiro.subject.Subject)
     * @deprecated in favor of {@link #save(org.apache.shiro.subject.Subject) save(subject)}.
     */
    @Deprecated
    protected void bind(Subject subject) {
        save(subject);
    }

    protected void rememberMeSuccessfulLogin(AuthenticationToken token, AuthenticationInfo info, Subject subject) {
        RememberMeManager rmm = getRememberMeManager();
        if (rmm != null) {
            try {
                rmm.onSuccessfulLogin(subject, token, info);
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

    protected void rememberMeFailedLogin(AuthenticationToken token, AuthenticationException ex, Subject subject) {
        RememberMeManager rmm = getRememberMeManager();
        if (rmm != null) {
            try {
                rmm.onFailedLogin(subject, token, ex);
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

    protected void rememberMeLogout(Subject subject) {
        RememberMeManager rmm = getRememberMeManager();
        if (rmm != null) {
            try {
                rmm.onLogout(subject);
            } catch (Exception e) {
                if (log.isWarnEnabled()) {
                    String msg = "Delegate RememberMeManager instance of type [" + rmm.getClass().getName() +
                                 "] threw an exception during onLogout for subject with principals [" +
                                 (subject != null ? subject.getPrincipals() : null) + "]";
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
        } catch (AuthenticationException ae) {
            try {
                onFailedLogin(token, ae, subject);
            } catch (Exception e) {
                if (log.isInfoEnabled()) {
                    log.info("onFailedLogin method threw an " +
                             "exception.  Logging and propagating original AuthenticationException.", e);
                }
            }
            throw ae; //propagate
        }

        Subject loggedIn = createSubject(token, info, subject);

        onSuccessfulLogin(token, info, loggedIn);

        return loggedIn;
    }

    protected void onSuccessfulLogin(AuthenticationToken token, AuthenticationInfo info, Subject subject) {
        rememberMeSuccessfulLogin(token, info, subject);
    }

    protected void onFailedLogin(AuthenticationToken token, AuthenticationException ae, Subject subject) {
        rememberMeFailedLogin(token, ae, subject);
    }

    protected void beforeLogout(Subject subject) {
        rememberMeLogout(subject);
    }

    protected SubjectContext copy(SubjectContext subjectContext) {
        return new DefaultSubjectContext(subjectContext);
    }

    /**
     * This implementation functions as follows:
     * <p/>
     * <ol>
     * <li>Ensures the {@code SubjectContext} is as populated as it can be, using heuristics to acquire
     * data that may not have already been available to it (such as a referenced session or remembered
     * principals).</li>
     * <li>Calls {@link #doCreateSubject(org.apache.shiro.subject.SubjectContext)} to actually perform the
     * {@code Subject} instance creation.</li>
     * <li>calls {@link #save(org.apache.shiro.subject.Subject) save(subject)} to ensure the constructed
     * {@code Subject}'s state is accessible for future requests/invocations if necessary.</li>
     * <li>returns the constructed {@code Subject} instance.</li>
     * </ol>
     *
     * @param subjectContext any data needed to direct how the Subject should be constructed.
     * @return the {@code Subject} instance reflecting the specified contextual data.
     * @see #ensureSecurityManager(org.apache.shiro.subject.SubjectContext)
     * @see #resolveSession(org.apache.shiro.subject.SubjectContext)
     * @see #resolvePrincipals(org.apache.shiro.subject.SubjectContext)
     * @see #doCreateSubject(org.apache.shiro.subject.SubjectContext)
     * @see #save(org.apache.shiro.subject.Subject)
     * @since 1.0
     */
    public Subject createSubject(SubjectContext subjectContext) {
        //create a copy so we don't modify the argument's backing map:
        SubjectContext context = copy(subjectContext);

        //ensure that the context has a SecurityManager instance, and if not, add one:
        context = ensureSecurityManager(context);

        //Resolve an associated Session (usually based on a referenced session ID), and place it in the context before
        //sending to the SubjectFactory.  The SubjectFactory should not need to know how to acquire sessions as the
        //process is often environment specific - better to shield the SF from these details:
        context = resolveSession(context);

        //Similarly, the SubjectFactory should not require any concept of RememberMe - translate that here first
        //if possible before handing off to the SubjectFactory:
        context = resolvePrincipals(context);

        Subject subject = doCreateSubject(context);

        //save this subject for future reference if necessary:
        //(this is needed here in case rememberMe principals were resolved and they need to be stored in the
        //session, so we don't constantly rehydrate the rememberMe PrincipalCollection on every operation).
        //Added in 1.2:
        save(subject);

        return subject;
    }

    /**
     * Actually creates a {@code Subject} instance by delegating to the internal
     * {@link #getSubjectFactory() subjectFactory}.  By the time this method is invoked, all possible
     * {@code SubjectContext} data (session, principals, et. al.) has been made accessible using all known heuristics
     * and will be accessible to the {@code subjectFactory} via the {@code subjectContext.resolve*} methods.
     *
     * @param context the populated context (data map) to be used by the {@code SubjectFactory} when creating a
     *                {@code Subject} instance.
     * @return a {@code Subject} instance reflecting the data in the specified {@code SubjectContext} data map.
     * @see #getSubjectFactory()
     * @see SubjectFactory#createSubject(org.apache.shiro.subject.SubjectContext)
     * @since 1.2
     */
    protected Subject doCreateSubject(SubjectContext context) {
        return getSubjectFactory().createSubject(context);
    }

    /**
     * Saves the subject's state to a persistent location for future reference if necessary.
     * <p/>
     * This implementation merely delegates to the internal {@link #setSubjectDAO(SubjectDAO) subjectDAO} and calls
     * {@link SubjectDAO#save(org.apache.shiro.subject.Subject) subjectDAO.save(subject)}.
     *
     * @param subject the subject for which state will potentially be persisted
     * @see SubjectDAO#save(org.apache.shiro.subject.Subject)
     * @since 1.2
     */
    protected void save(Subject subject) {
        this.subjectDAO.save(subject);
    }

    /**
     * Removes (or 'unbinds') the Subject's state from the application, typically called during {@link #logout}..
     * <p/>
     * This implementation merely delegates to the internal {@link #setSubjectDAO(SubjectDAO) subjectDAO} and calls
     * {@link SubjectDAO#delete(org.apache.shiro.subject.Subject) delete(subject)}.
     *
     * @param subject the subject for which state will be removed
     * @see SubjectDAO#delete(org.apache.shiro.subject.Subject)
     * @since 1.2
     */
    protected void delete(Subject subject) {
        this.subjectDAO.delete(subject);
    }

    /**
     * Determines if there is a {@code SecurityManager} instance in the context, and if not, adds 'this' to the
     * context.  This ensures the SubjectFactory instance will have access to a SecurityManager during Subject
     * construction if necessary.
     *
     * @param context the subject context data that may contain a SecurityManager instance.
     * @return The SubjectContext to use to pass to a {@link SubjectFactory} for subject creation.
     * @since 1.0
     */
    @SuppressWarnings({"unchecked"})
    protected SubjectContext ensureSecurityManager(SubjectContext context) {
        if (context.resolveSecurityManager() != null) {
            log.trace("Context already contains a SecurityManager instance.  Returning.");
            return context;
        }
        log.trace("No SecurityManager found in context.  Adding self reference.");
        context.setSecurityManager(this);
        return context;
    }

    /**
     * Attempts to resolve any associated session based on the context and returns a
     * context that represents this resolved {@code Session} to ensure it may be referenced if necessary by the
     * invoked {@link SubjectFactory} that performs actual {@link Subject} construction.
     * <p/>
     * If there is a {@code Session} already in the context because that is what the caller wants to be used for
     * {@code Subject} construction, or if no session is resolved, this method effectively does nothing
     * returns the context method argument unaltered.
     *
     * @param context the subject context data that may resolve a Session instance.
     * @return The context to use to pass to a {@link SubjectFactory} for subject creation.
     * @since 1.0
     */
    @SuppressWarnings({"unchecked"})
    protected SubjectContext resolveSession(SubjectContext context) {
        if (context.resolveSession() != null) {
            log.debug("Context already contains a session.  Returning.");
            return context;
        }
        try {
            //Context couldn't resolve it directly, let's see if we can since we have direct access to
            //the session manager:
            Session session = resolveContextSession(context);
            if (session != null) {
                context.setSession(session);
            }
        } catch (InvalidSessionException e) {
            log.debug("Resolved SubjectContext context session is invalid.  Ignoring and creating an anonymous " +
                      "(session-less) Subject instance.", e);
        }
        return context;
    }

    protected Session resolveContextSession(SubjectContext context) throws InvalidSessionException {
        SessionKey key = getSessionKey(context);
        if (key != null) {
            return getSession(key);
        }
        return null;
    }

    protected SessionKey getSessionKey(SubjectContext context) {
        Serializable sessionId = context.getSessionId();
        if (sessionId != null) {
            return new DefaultSessionKey(sessionId);
        }
        return null;
    }

    private static boolean isEmpty(PrincipalCollection pc) {
        return pc == null || pc.isEmpty();
    }

    /**
     * Attempts to resolve an identity (a {@link PrincipalCollection}) for the context using heuristics.  This
     * implementation functions as follows:
     * <ol>
     * <li>Check the context to see if it can already {@link SubjectContext#resolvePrincipals resolve an identity}.  If
     * so, this method does nothing and returns the method argument unaltered.</li>
     * <li>Check for a RememberMe identity by calling {@link #getRememberedIdentity}.  If that method returns a
     * non-null value, place the remembered {@link PrincipalCollection} in the context.</li>
     * </ol>
     *
     * @param context the subject context data that may provide (directly or indirectly through one of its values) a
     *                {@link PrincipalCollection} identity.
     * @return The Subject context to use to pass to a {@link SubjectFactory} for subject creation.
     * @since 1.0
     */
    @SuppressWarnings({"unchecked"})
    protected SubjectContext resolvePrincipals(SubjectContext context) {

        PrincipalCollection principals = context.resolvePrincipals();

        if (isEmpty(principals)) {
            log.trace("No identity (PrincipalCollection) found in the context.  Looking for a remembered identity.");

            principals = getRememberedIdentity(context);

            if (!isEmpty(principals)) {
                log.debug("Found remembered PrincipalCollection.  Adding to the context to be used " +
                          "for subject construction by the SubjectFactory.");

                context.setPrincipals(principals);

                // The following call was removed (commented out) in Shiro 1.2 because it uses the session as an
                // implementation strategy.  Session use for Shiro's own needs should be controlled in a single place
                // to be more manageable for end-users: there are a number of stateless (e.g. REST) applications that
                // use Shiro that need to ensure that sessions are only used when desirable.  If Shiro's internal
                // implementations used Subject sessions (setting attributes) whenever we wanted, it would be much
                // harder for end-users to control when/where that occurs.
                //
                // Because of this, the SubjectDAO was created as the single point of control, and session state logic
                // has been moved to the DefaultSubjectDAO implementation.

                // Removed in Shiro 1.2.  SHIRO-157 is still satisfied by the new DefaultSubjectDAO implementation
                // introduced in 1.2
                // Satisfies SHIRO-157:
                // bindPrincipalsToSession(principals, context);

            } else {
                log.trace("No remembered identity found.  Returning original context.");
            }
        }

        return context;
    }

    protected SessionContext createSessionContext(SubjectContext subjectContext) {
        DefaultSessionContext sessionContext = new DefaultSessionContext();
        if (!CollectionUtils.isEmpty(subjectContext)) {
            sessionContext.putAll(subjectContext);
        }
        Serializable sessionId = subjectContext.getSessionId();
        if (sessionId != null) {
            sessionContext.setSessionId(sessionId);
        }
        String host = subjectContext.resolveHost();
        if (host != null) {
            sessionContext.setHost(host);
        }
        return sessionContext;
    }

    public void logout(Subject subject) {

        if (subject == null) {
            throw new IllegalArgumentException("Subject method argument cannot be null.");
        }

        beforeLogout(subject);

        PrincipalCollection principals = subject.getPrincipals();
        if (principals != null && !principals.isEmpty()) {
            if (log.isDebugEnabled()) {
                log.debug("Logging out subject with primary principal {}", principals.getPrimaryPrincipal());
            }
            Authenticator authc = getAuthenticator();
            if (authc instanceof LogoutAware) {
                ((LogoutAware) authc).onLogout(principals);
            }
        }

        try {
            delete(subject);
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
            s.stop();
        }
    }

    protected PrincipalCollection getRememberedIdentity(SubjectContext subjectContext) {
        RememberMeManager rmm = getRememberMeManager();
        if (rmm != null) {
            try {
                return rmm.getRememberedPrincipals(subjectContext);
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
}
