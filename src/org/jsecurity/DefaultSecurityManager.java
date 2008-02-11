/*
 * Copyright (C) 2005-2008 Les Hazlewood, Jeremy Haile
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
package org.jsecurity;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.authc.*;
import org.jsecurity.authc.support.ModularRealmAuthenticator;
import org.jsecurity.authz.AuthorizationException;
import org.jsecurity.authz.Authorizer;
import org.jsecurity.authz.HostUnauthorizedException;
import org.jsecurity.authz.Permission;
import org.jsecurity.authz.support.ModularRealmAuthorizer;
import org.jsecurity.cache.CacheProvider;
import org.jsecurity.cache.CacheProviderAware;
import org.jsecurity.cache.ehcache.EhCacheProvider;
import org.jsecurity.cache.support.HashtableCacheProvider;
import org.jsecurity.context.SecurityContext;
import org.jsecurity.context.support.DelegatingSecurityContext;
import org.jsecurity.context.support.RememberMeManager;
import org.jsecurity.realm.Realm;
import org.jsecurity.realm.support.file.PropertiesRealm;
import org.jsecurity.session.InvalidSessionException;
import org.jsecurity.session.Session;
import org.jsecurity.session.SessionFactory;
import org.jsecurity.session.event.SessionEventListener;
import org.jsecurity.session.event.SessionEventListenerRegistrar;
import org.jsecurity.session.support.DefaultSessionFactory;
import org.jsecurity.util.*;

import java.io.Serializable;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * <p>The JSecurity framework's default implementation of the {@link org.jsecurity.SecurityManager} interface,
 * based around a collection of security {@link org.jsecurity.realm.Realm}s.  This implementation delegates its
 * authentication, authorization, and session operations to wrapped {@link Authenticator}, {@link Authorizer}, and
 * {@link SessionFactory SessionFactory} instances respectively. It also provides sensible defaults to simplify
 * configuration.</p>
 *
 * <p>This implementation is primarily a convenience mechanism that wraps these three instances to consolidate
 * all behaviors into a single point of reference.  For most JSecurity users, this simplifies configuration and
 * tends to be a more convenient approach than referencing <code>Authenticator</code>, <code>Authorizer</code>, and
 * <tt>SessionFactory</tt> instances seperately in their application code;  instead they only need to interact with a
 * single <tt>SecurityManager</tt> instance.</p>
 *
 * <p>To further reduce and simplify configuration, this implementation will create defaults for <em>all</em> of its
 * dependencies.  Therefore, you only need to override the attributes suitable for your application, but please
 * note the following:</p>
 *
 * <p>Unless you're happy with the default simple {@link PropertiesRealm properties file}-based realm, which may or
 * may not be flexible enough for enterprise applications, you might want to specify at least one custom
 * <tt>Realm</tt> implementation (via {@link #setRealm}) that 'knows' about your application's data/security model.
 * All other attributes have suitable defaults for most enterprise applications.</p>
 *
 * <p>Finally, the only absolute requirement for a <tt>DefaultSecurityManager</tt> instance to function properly is
 * that its {@link #init() init()} method must be called before it is used.  Even this is called automatically if
 * you use one of the constructors with one or more arguments.</p>
 *
 * @author Les Hazlewood
 * @author Jeremy Haile
 * @since 0.2
 */
public class DefaultSecurityManager implements SecurityManager, SessionEventListenerRegistrar, CacheProviderAware, Initializable, Destroyable {

    /*--------------------------------------------
    |             C O N S T A N T S             |
    ============================================*/
    protected transient final Log log = LogFactory.getLog(getClass());

    /*--------------------------------------------
    |    I N S T A N C E   V A R I A B L E S    |
    ============================================*/
    protected CacheProvider cacheProvider = null;
    private boolean cacheProviderImplicitlyCreated = false;

    protected Authenticator authenticator;
    private boolean authenticatorImplicitlyCreated = false;

    protected Authorizer authorizer = null;
    private boolean authorizerImplicitlyCreated = false;

    protected SessionFactory sessionFactory;
    private boolean sessionFactoryImplicitlyCreated = false;
    private boolean lazySessions = true;

    protected RememberMeManager rememberMeManager = null;

    private Collection<Realm> realms = null;
    private boolean realmImplicitlyCreated = false;

    /*--------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*/
    /**
     * Default no-arg constructor - used in IoC environments or when the programmer wishes to explicitly call
     * {@link #init()} after the necessary properties have been set.
     */
    public DefaultSecurityManager() {
    }

    /**
     * Supporting constructor for a single-realm application (automatically calls {@link #init()} before returning).
     *
     * @param singleRealm the single realm used by this SecurityManager.
     */
    public DefaultSecurityManager(Realm singleRealm) {
        setRealm(singleRealm);
        init();
    }

    /**
     * Supporting constructor that sets the required realms property and then automatically calls {@link #init()}.
     *
     * @param realms the realm instances backing this SecurityManager.
     */
    public DefaultSecurityManager(List<Realm> realms) {
        setRealms(realms);
        init();
    }

    /*--------------------------------------------
    |  A C C E S S O R S / M O D I F I E R S    |
    ============================================*/
    public void setAuthenticator(Authenticator authenticator) {
        this.authenticator = authenticator;
    }

    protected Authenticator getRequiredAuthenticator() {
        if (this.authenticator == null) {
            String msg = "No authenticator attribute configured for this SecurityManager instance.  Please ensure " +
                "the init() method is called prior to using this instance and a default one will be created.";
            throw new IllegalStateException(msg);
        }
        return this.authenticator;
    }

    public void setAuthorizer(Authorizer authorizer) {
        this.authorizer = authorizer;
    }

    protected Authorizer getRequiredAuthorizer() {
        if (this.authorizer == null) {
            String msg = "No authorizer attribute configured for this SecurityManager instance.  Please ensure " +
                "the init() method is called prior to using this instance and a default one will be created.";
            throw new IllegalStateException(msg);
        }
        return this.authorizer;
    }

    /**
     * Sets the underlying delegate {@link SessionFactory} instance that will be used to support calls to this
     * manager's {@link #start} and {@link #getSession} calls.
     * <p/>
     * <p>This <tt>SecurityManager</tt> implementation does not provide logic to support the inherited
     * <tt>SessionFactory</tt> interface, but instead delegates these calls to an internal
     * <tt>SessionFactory</tt> instance.
     * <p/>
     * <p>If a <tt>SessionFactory</tt> instance is not set, a default one will be automatically created and
     * initialized based on the {@link #isLazySessions() lazySessions} property.
     *
     * @param sessionFactory delegate instance to use to support this manager's {@link #start} and {@link #getSession}
     *                       implementations.
     */
    public void setSessionFactory(SessionFactory sessionFactory) {
        this.sessionFactory = sessionFactory;
    }

    public SessionFactory getSessionFactory() {
        return this.sessionFactory;
    }

    protected SessionFactory getRequiredSessionFactory() {
        if (this.sessionFactory == null) {
            ensureSessionFactory();
        }
        return this.sessionFactory;
    }

    public void add(SessionEventListener listener) {
        ensureSessionFactory();
        assertSessionFactoryEventListenerSupport(this.sessionFactory);
        ((SessionEventListenerRegistrar) this.sessionFactory).add(listener);
    }

    public boolean remove(SessionEventListener listener) {
        return (this.sessionFactory instanceof SessionEventListenerRegistrar) &&
            ((SessionEventListenerRegistrar) this.sessionFactory).remove(listener);
    }

    /**
     * Convenience method for applications with a single realm that merely wraps the realm in a list and then invokes
     * the {@link #setRealms} method.
     *
     * @param realm the realm to set for a single-realm application.
     * @since 0.2
     */
    public void setRealm(Realm realm) {
        if (realm == null) {
            throw new IllegalArgumentException("Realm argument cannot be null");
        }
        List<Realm> realms = new ArrayList<Realm>(1);
        realms.add(realm);
        setRealms(realms);
    }

    /**
     * Sets the realms managed by this <tt>SecurityManager</tt> instance.
     *
     * @param realms the realms managed by this <tt>SecurityManager</tt> instance.
     */
    public void setRealms(Collection<Realm> realms) {
        if (realms == null) {
            throw new IllegalArgumentException("Realms collection argument cannot be null.");
        }
        if (realms.isEmpty()) {
            throw new IllegalArgumentException("Realms collection argument cannot be empty.");
        }
        this.realms = realms;
    }

    /**
     * Returns the default CacheProvider used by this SecurityManager and any of the caching-aware children components
     * implicitly created
     *
     * @return the cacheProvider used by this SecurityManager and any of its caching-aware implicitly created children components.
     */
    public CacheProvider getCacheProvider() {
        return cacheProvider;
    }

    public void setCacheProvider(CacheProvider cacheProvider) {
        this.cacheProvider = cacheProvider;
    }

    /**
     * Returns whether or not the SessionFactory infrastructure will be lazily initialized upon the first session
     * request.  If this returns <tt>true</tt>, the SessionFactory infrastructure will not be initialized until the
     * first request for a session occurs.  If <tt>false</tt>, the SessionFactory infrastructure will be
     * eagerly initialized when this SecurityManager instance is initialized.
     * <p/>
     * <p>The default value is <strong><tt>true</tt></strong> to slightly increase application startup times and
     * reduce overhead when not using Sessions.  If you require JSecurity Sessions in your app (as would be the
     * case when not a pure web-app or Session state must be accessible by many clients) it is usually better to set
     * this value to <tt>false</tt> to eagerly initialize, ensuring initial session access will be fast and any
     * configuration settings will be verified on application startup instead of being discovered at a later point.
     *
     * @return <tt>true</tt> if the SessionFactory infrastructure will be lazily initialized based on the first
     *         request for a session, <tt>false</tt> if it will be eagerly initialized at the same time as this SecurityManager.
     */
    public boolean isLazySessions() {
        return lazySessions;
    }

    /**
     * Sets whether or not the SessionFactory infrastructure will be lazily initialized upon the first session
     * request.  If this value is <tt>true</tt>, the SessionFactory infrastructure will not be initialized until the
     * first request for a session occurs.  If <tt>false</tt>, the SessionFactory infrastructure will be
     * eagerly initialized when this SecurityManager instance is initialized.
     * <p/>
     * <p>The default value is <strong><tt>true</tt></strong> to slightly increase application startup times and
     * reduce overhead when not using Sessions.  If you require JSecurity Sessions in your app (as would be the
     * case when not a pure web-app or Session state must be accessible by many clients) it is usually better to set
     * this value to <tt>false</tt> to eagerly initialize, ensuring initial session access will be fast and any
     * configuration settings will be verified on application startup instead of being discovered at a later point.
     *
     * @param lazySessions value indicating if the SessionFactory infrastructure will be lazily initialized
     *                     (value of true) or eagerly initialized (value of false)
     */
    public void setLazySessions(boolean lazySessions) {
        this.lazySessions = lazySessions;
    }

    public RememberMeManager getRememberMeManager() {
        return rememberMeManager;
    }

    public void setRememberMeManager(RememberMeManager rememberMeManager) {
        this.rememberMeManager = rememberMeManager;
    }

   /*--------------------------------------------
    |               M E T H O D S               |
    ============================================*/
    protected CacheProvider createCacheProvider() {
        CacheProvider provider;

        if (JavaEnvironment.isEhcacheAvailable()) {
            if (log.isDebugEnabled()) {
                String msg = "Initializing default CacheProvider using EhCache.";
                log.debug(msg);
            }
            EhCacheProvider ehCacheProvider = new EhCacheProvider();
            ehCacheProvider.init();
            provider = ehCacheProvider;
        } else {
            if (log.isWarnEnabled()) {
                String msg = "Instantiating default CacheProvider which will create in-memory HashTable caches.  " +
                    "This is NOT RECOMMENDED for production environments.  Please ensure ehcache.jar is in the " +
                    "classpath and JSecurity will automatically use a production-quality CacheProvider " +
                    "implementation, or you may alternatively provide your own via the #setCacheProvider method.";
                log.warn(msg);
            }
            provider = new HashtableCacheProvider();
        }

        return provider;
    }


    protected synchronized void ensureCacheProvider() {
        //only create one if one hasn't been explicitly set by the instantiator
        CacheProvider cacheProvider = getCacheProvider();
        if (cacheProvider == null) {
            cacheProvider = createCacheProvider();
            cacheProviderImplicitlyCreated = true;
            setCacheProvider(cacheProvider);
        }
    }

    protected Realm createDefaultRealm() {
        PropertiesRealm propsRealm = new PropertiesRealm();
        propsRealm.setCacheProvider(getCacheProvider());
        propsRealm.init();
        return propsRealm;
    }

    protected void ensureRealms() {
        if (realms == null || realms.isEmpty()) {
            if (log.isInfoEnabled()) {
                log.info("No realms set - creating default PropertiesRealm.");
            }
            Realm realm = createDefaultRealm();
            this.realmImplicitlyCreated = true;
            setRealm(realm);
        }
    }

    protected Authenticator createAuthenticator() {
        ModularRealmAuthenticator mra = new ModularRealmAuthenticator();
        mra.setRealms(this.realms);
        mra.init();
        authenticatorImplicitlyCreated = true;
        return mra;
    }

    protected void ensureAuthenticator() {
        if (this.authenticator == null) {
            Authenticator authc = createAuthenticator();
            setAuthenticator(authc);
        }
    }

    protected Authorizer createAuthorizer() {
        ModularRealmAuthorizer mra = new ModularRealmAuthorizer();
        mra.setRealms(this.realms);
        mra.init();
        authorizerImplicitlyCreated = true;
        return mra;
    }

    protected void ensureAuthorizer() {
        if (authorizer == null) {
            Authorizer authz = createAuthorizer();
            setAuthorizer(authz);
        }
    }

    private void assertSessionFactoryEventListenerSupport(SessionFactory factory) {
        if (!(factory instanceof SessionEventListenerRegistrar)) {
            String msg = "SessionEventListener registration failed:  The underlying SessionFactory instance of " +
                "type [" + factory.getClass().getName() + "] does not implement the " +
                SessionEventListenerRegistrar.class.getName() + " interface and therefore cannot support " +
                "runtime SessionEvent propagation.";
            throw new IllegalStateException(msg);
        }
    }

    protected SessionFactory createSessionFactory() {
        DefaultSessionFactory sessionFactory = new DefaultSessionFactory();
        sessionFactory.setCacheProvider(getCacheProvider());
        sessionFactory.init();
        return sessionFactory;
    }

    protected void ensureSessionFactory() {
        if (this.sessionFactory == null) {
            if (log.isInfoEnabled()) {
                log.info("No delegate SessionFactory instance has been set as a property of this class.  Creating a " +
                    "default SessionFactory implementation...");
            }
            SessionFactory sessionFactory = createSessionFactory();
            sessionFactoryImplicitlyCreated = true;
            setSessionFactory(sessionFactory);
        }
    }

    public void init() {
        ensureCacheProvider();
        ensureRealms();
        ensureAuthenticator();
        ensureAuthorizer();
        if (!isLazySessions()) {
            //start SessionFactory infrastructure now
            ensureSessionFactory();
        }
        //TODO - remove before 1.0 final
        SecurityUtils.setSecurityManager( this );
    }

    public void destroy() {
        if (sessionFactoryImplicitlyCreated) {
            LifecycleUtils.destroy(sessionFactory);
            sessionFactory = null;
            sessionFactoryImplicitlyCreated = false;
        }
        if (authorizerImplicitlyCreated) {
            LifecycleUtils.destroy(authorizer);
            authorizer = null;
            authorizerImplicitlyCreated = false;
        }
        if (authenticatorImplicitlyCreated) {
            LifecycleUtils.destroy(authenticator);
            authenticator = null;
            authenticatorImplicitlyCreated = false;
        }
        if (realmImplicitlyCreated) {
            if (realms != null && !realms.isEmpty()) {
                LifecycleUtils.destroy(realms.iterator().next());
            }
            realmImplicitlyCreated = false;
            realms = null;
        }
        if (cacheProviderImplicitlyCreated) {
            LifecycleUtils.destroy(cacheProvider);
            cacheProvider = null;
            cacheProviderImplicitlyCreated = false;
        }
        //TODO - remove before 1.0 final:
        SecurityUtils.setSecurityManager( null );
    }

    /** Delegates to the authenticator for authentication. */
    public Account authenticate(AuthenticationToken token) throws AuthenticationException {
        return getRequiredAuthenticator().authenticate(token);
    }

    public boolean hasRole(Object subjectIdentifier, String roleIdentifier) {
        return getRequiredAuthorizer().hasRole(subjectIdentifier, roleIdentifier);
    }

    public boolean[] hasRoles(Object subjectIdentifier, List<String> roleIdentifiers) {
        return getRequiredAuthorizer().hasRoles(subjectIdentifier, roleIdentifiers);
    }

    public boolean hasAllRoles(Object subjectIdentifier, Collection<String> roleIdentifiers) {
        return getRequiredAuthorizer().hasAllRoles(subjectIdentifier, roleIdentifiers);
    }

    public boolean isPermitted(Object subjectIdentifier, Permission permission) {
        return getRequiredAuthorizer().isPermitted(subjectIdentifier, permission);
    }

    public boolean[] isPermitted(Object subjectIdentifier, List<Permission> permissions) {
        return getRequiredAuthorizer().isPermitted(subjectIdentifier, permissions);
    }

    public boolean isPermittedAll(Object subjectIdentifier, Collection<Permission> permissions) {
        return getRequiredAuthorizer().isPermittedAll(subjectIdentifier, permissions);
    }

    public void checkPermission(Object subjectIdentifier, Permission permission) throws AuthorizationException {
        getRequiredAuthorizer().checkPermission(subjectIdentifier, permission);
    }

    public void checkPermissions(Object subjectIdentifier, Collection<Permission> permissions) throws AuthorizationException {
        getRequiredAuthorizer().checkPermissions(subjectIdentifier, permissions);
    }

    public void checkRole(Object subjectIdentifier, String role) throws AuthorizationException {
        getRequiredAuthorizer().checkRole(subjectIdentifier, role);
    }

    public void checkRoles(Object subjectIdentifier, Collection<String> roles) throws AuthorizationException {
        getRequiredAuthorizer().checkRoles(subjectIdentifier, roles);
    }

    public Session start(InetAddress hostAddress) throws HostUnauthorizedException, IllegalArgumentException {
        return getRequiredSessionFactory().start(hostAddress);
    }

    public Session getSession(Serializable sessionId) throws InvalidSessionException, AuthorizationException {
        return getRequiredSessionFactory().getSession(sessionId);
    }

    private void assertPrincipals(Account account) {
        Collection principals = account.getPrincipals();
        if (principals == null || principals.size() < 1) {
            String msg = "Account returned from Authenticator must return at least one non-null principal.";
            throw new IllegalArgumentException(msg);
        }
    }

    protected SecurityContext createSecurityContext() {
        Object principals = getRememberedIdentity();
        return createSecurityContext( principals );
    }

    protected SecurityContext createSecurityContext( Object subjectPrincipals ) {
        return createSecurityContext( subjectPrincipals, null );
    }

    protected SecurityContext createSecurityContext( Object principals, Session existing ) {
        return createSecurityContext( principals, existing, false );
    }

    protected SecurityContext createSecurityContext( Object principals, Session existing, boolean authenticated ) {
        return createSecurityContext( principals, existing, authenticated, getLocalHost() );
    }

    protected SecurityContext createSecurityContext( Object principals, Session existing,
                                                     boolean authenticated, InetAddress inetAddress ) {
        return new DelegatingSecurityContext( principals, authenticated, inetAddress, existing, this );
    }

    /**
     * Creates a <tt>SecurityContext</tt> instance for the user represented by the given method argument.
     *
     * @param token   the submitted <tt>AuthenticationToken</tt> submitted for the successful authentication.
     * @param account the <tt>Account</tt> of a newly authenticated subject/user.
     * @return the <tt>SecurityContext</tt> that represents the identity and session data for the newly
     *         authenticated subject/user.
     */
    protected SecurityContext createSecurityContext(AuthenticationToken token, Account account) {
        assertPrincipals(account);

        //get any existing session that may exist - we don't want to lose it:
        SecurityContext securityContext = ThreadContext.getSecurityContext();
        Session session = null;
        if (securityContext != null) {
            session = securityContext.getSession(false);
        }

        InetAddress authcSourceIP = null;
        if (token instanceof InetAuthenticationToken) {
            authcSourceIP = ((InetAuthenticationToken) token).getInetAddress();
        }
        if (authcSourceIP == null) {
            //try the thread local:
            authcSourceIP = ThreadContext.getInetAddress();
        } else {
            //revert to localhost:
            authcSourceIP = getLocalHost();
        }

        return createSecurityContext( account.getPrincipals(), session,  true, authcSourceIP );
    }

    /**
     * Binds a <tt>SecurityContext</tt> instance created after authentication to the application for later use.
     *
     * <p>The default implementation merely binds the argument to the thread local via the {@link ThreadContext}.
     * Should be overridden by subclasses for environment-specific binding (e.g. web environment, etc).
     *
     * @param secCtx the <tt>SecurityContext</tt> instance created after authentication to be bound to the application
     *               for later use.
     */
    protected void bind(SecurityContext secCtx) {
        if (log.isDebugEnabled()) {
            log.debug("Binding SecurityContext [" + secCtx + "] to a thread local...");
        }
        ThreadContext.bind(secCtx);
    }

    private void assertCreation(SecurityContext secCtx) throws IllegalStateException {
        if (secCtx == null) {
            String msg = "Programming error - please verify that you have overridden the " +
                getClass().getName() + ".createSecurityContext( Account account ) method to return " +
                "a non-null SecurityContext instance";
            throw new IllegalStateException(msg);
        }
    }

    protected void rememberMeSuccessfulLogin( AuthenticationToken token, Account account ) {
        RememberMeManager rmm = getRememberMeManager();
        if ( rmm != null ) {
            try {
                rmm.onSuccessfulLogin( token, account );
            } catch (Exception e) {
                if ( log.isWarnEnabled() ) {
                    String msg = "Delegate RememberMeManager instance of type [" + rmm.getClass().getName() +
                        "] threw an exception during onSuccessfulLogin.  RememberMe services will not be " +
                        "performed for Account [" + account + "].";
                    log.warn( msg, e );
                }
            }
        } else {
            if ( log.isDebugEnabled() ) {
                log.debug( "This " + getClass().getName() + " instance does not have a " +
                    "[" + RememberMeManager.class.getName() + "] instance configured.  RememberMe services " +
                    "will not be performed for account [" + account + "]." );
            }
        }
    }

    protected void rememberMeFailedLogin( AuthenticationToken token, AuthenticationException ex ) {
        RememberMeManager rmm = getRememberMeManager();
        if ( rmm != null ) {
            try {
                rmm.onFailedLogin( token, ex );
            } catch (Exception e) {
                if ( log.isWarnEnabled() ) {
                    String msg = "Delegate RememberMeManager instance of type [" + rmm.getClass().getName() +
                        "] threw an exception during onFailedLogin for AuthenticationToken [" +
                    token + "].";
                    log.warn( msg, e );
                }
            }
        }
    }

    protected void rememberMeLogout( Object subjectPrincipals ) {
        RememberMeManager rmm = getRememberMeManager();
        if ( rmm != null ) {
            try {
                rmm.onLogout( subjectPrincipals );
            } catch (Exception e) {
                if ( log.isWarnEnabled() ) {
                    String msg = "Delegate RememberMeManager instance of type [" + rmm.getClass().getName() +
                        "] threw an exception during onLogout for subject with principals [" +
                    subjectPrincipals + "]";
                    log.warn( msg, e );
                }
            }
        }
    }

    /**
     * First authenticates the <tt>AuthenticationToken</tt> argument, and if successful, constructs a
     * <tt>SecurityContext</tt> instance representing the authenticated account's identity.
     *
     * <p>Once constructed, the <tt>SecurityContext</tt> instance is then {@link #bind bound} to the application for
     * subsequent access before being returned to the caller.
     *
     * @param token the authenticationToken to process for the login attempt.
     * @return a SecurityContext representing the authenticated account.
     * @throws AuthenticationException if there is a problem authenticating the specified <tt>token</tt>.
     */
    public SecurityContext login(AuthenticationToken token) throws AuthenticationException {
        Account account;
        try {
            account = authenticate(token);
            rememberMeSuccessfulLogin( token, account );
        } catch (AuthenticationException ae) {
            rememberMeFailedLogin( token, ae );
            throw ae; //propagate
        }
        SecurityContext secCtx = createSecurityContext(token, account);
        assertCreation(secCtx);
        bind(secCtx);
        return secCtx;
    }

    public void logout(Object subjectIdentifier) {
        rememberMeLogout( subjectIdentifier );
        //Method arg is ignored - get the SecurityContext from the environment if it exists:
        SecurityContext sc = getSecurityContext(false);
        if (sc != null) {
            try {
                unbind(sc);
            } catch (Exception e) {
                String msg = "Unable to cleanly unbind SecurityContext.  Ignoring.";
                if (log.isDebugEnabled()) {
                    log.debug(msg, e);
                }
            }
        }
    }

    protected void unbind(SecurityContext sc) {
        ThreadContext.unbindSecurityContext();
    }

    protected static InetAddress getLocalHost() {
        try {
            return InetAddress.getLocalHost();
        } catch (UnknownHostException e) {
            return null;
        }
    }

    protected Object getRememberedIdentity() {
        RememberMeManager rmm = getRememberMeManager();
        if ( rmm != null ) {
            try {
                return rmm.getRememberedIdentity();
            } catch (Exception e) {
                if ( log.isWarnEnabled() ) {
                    String msg = "Delegate RememberMeManager instance of type [" + rmm.getClass().getName() +
                        "] threw an exception during getRememberedIdentity().";
                    log.warn( msg, e );
                }
            }
        }
        return null;
    }

    protected SecurityContext getSecurityContext(boolean create) {
        SecurityContext sc = ThreadContext.getSecurityContext();
        if (sc == null && create) {
            sc = createSecurityContext();
            bind(sc);
        }
        return sc;
    }

    public SecurityContext getSecurityContext() {
        return getSecurityContext(true);
    }
}