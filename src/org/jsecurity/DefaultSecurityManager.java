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

import org.jsecurity.authc.*;
import org.jsecurity.authz.Authorizer;
import org.jsecurity.realm.PropertiesRealm;
import org.jsecurity.realm.Realm;
import org.jsecurity.session.Session;
import org.jsecurity.session.SessionFactory;
import org.jsecurity.subject.DelegatingSubject;
import org.jsecurity.subject.RememberMeManager;
import org.jsecurity.subject.Subject;
import org.jsecurity.util.ThreadContext;

import java.net.InetAddress;
import java.util.Collection;

/**
 * <p>The JSecurity framework's default concrete implementation of the {@link org.jsecurity.SecurityManager} interface,
 * based around a collection of {@link org.jsecurity.realm.Realm}s.  This implementation delegates its
 * authentication, authorization, and session operations to wrapped {@link Authenticator}, {@link Authorizer}, and
 * {@link SessionFactory SessionFactory} instances respectively via superclass implementation.</p>
 *
 * <p>To greatly reduce and simplify configuration, this implementation (and its superclasses) will
 * create suitable defaults for <em>all</em> of its required dependencies.  Therefore, you only need to override
 * attributes for custom behavior.  But, note the following:</p>
 *
 * <p>Unless you're happy with the default simple {@link PropertiesRealm properties file}-based realm, which may or
 * may not be flexible enough for enterprise applications, you might want to specify at least one custom
 * <tt>Realm</tt> implementation (via {@link #setRealm}) that 'knows' about your application's data/security model.
 * All other attributes have suitable defaults for most enterprise applications.</p>
 *
 * <p><b>RememberMe notice</b>: This class supports the ability to configure a
 * {@link #setRememberMeManager RememberMeManager}
 * for <tt>RememberMe</tt> identity services for login/logout, BUT, a default instance <em>will not</em> be created
 * for this attribute at startup.
 *
 * <p>Because RememberMe services are inherently client tier-specific and
 * therefore aplication-dependent, if you want <tt>RememberMe</tt> services enabled, you will have to specify an
 * instance yourself before calling {@link #init() init()}.  However if you're reading this JavaDoc with the
 * expectation of operating in a Web environment, take a look at the
 * {@link org.jsecurity.web.support.WebSecurityManager DefaultWebSecurityManager} implementation, which
 * <em>does</em> support <tt>RememberMe</tt> services by default at startup.
 *
 * <p>Finally, the only absolute requirement for a <tt>DefaultSecurityManager</tt> instance to function properly is
 * that its {@link #init() init()} method must be called before it is used.  Even this is called automatically if
 * you use one of the overloaded constructors with one or more arguments.</p>
 *
 * @see org.jsecurity.web.support.WebSecurityManager DefaultWebSecurityManager
 *
 * @author Les Hazlewood
 * @author Jeremy Haile
 * @since 0.2
 */
public class DefaultSecurityManager extends SessionsSecurityManager {

    protected RememberMeManager rememberMeManager = null;

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
        super(singleRealm);
    }

    /**
     * Supporting constructor that sets the {@link #setRealms realms} property and then automatically calls {@link #init()}.
     *
     * @param realms the realm instances backing this SecurityManager.
     */
    public DefaultSecurityManager(Collection<Realm> realms) {
        super(realms);
    }

    public RememberMeManager getRememberMeManager() {
        return rememberMeManager;
    }

    public void setRememberMeManager(RememberMeManager rememberMeManager) {
        this.rememberMeManager = rememberMeManager;
    }

    private void assertPrincipals(Account account) {
        Object principal = account.getPrincipal();
        if (principal == null ) {
            String msg = "Account returned from Authenticator must have an associated principal.";
            throw new IllegalArgumentException(msg);
        }
    }

    protected Subject createSubject() {
        Object principals = getRememberedIdentity();
        return createSubject(principals);
    }

    protected Subject createSubject(Object subjectPrincipals) {
        return createSubject(subjectPrincipals, null);
    }

    protected Subject createSubject(Object principals, Session existing) {
        return createSubject(principals, existing, false);
    }

    protected Subject createSubject(Object principals, Session existing, boolean authenticated) {
        return createSubject(principals, existing, authenticated, null);
    }

    protected Subject createSubject(Object principals, Session existing,
                                    boolean authenticated, InetAddress inetAddress) {
        return new DelegatingSubject(principals, authenticated, inetAddress, existing, this);
    }

    /**
     * Creates a <tt>Subject</tt> instance for the user represented by the given method arguments.
     *
     * @param token   the <tt>AuthenticationToken</tt> submitted for the successful authentication.
     * @param account the <tt>Account</tt> of a newly authenticated user.
     * @return the <tt>Subject</tt> instance that represents the account and session data for the newly
     *         authenticated user.
     */
    protected Subject createSubject(AuthenticationToken token, Account account) {
        assertPrincipals(account);

        //get any existing session that may exist - we don't want to lose it:
        Subject subject = ThreadContext.getSubject();
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

        return createSubject(account.getPrincipal(), session, true, authcSourceIP);
    }

    /**
     * Binds a <tt>Subject</tt> instance created after authentication to the application for later use.
     *
     * <p>The default implementation merely binds the argument to the thread local via the {@link ThreadContext}.
     * Should be overridden by subclasses for environment-specific binding (e.g. web environment, etc).
     *
     * @param subject the <tt>Subject</tt> instance created after authentication to be bound to the application
     *               for later use.
     */
    protected void bind(Subject subject) {
        if (log.isDebugEnabled()) {
            log.debug("Binding Subject [" + subject + "] to a thread local...");
        }
        ThreadContext.bind(subject);
    }

    private void assertCreation(Subject subject) throws IllegalStateException {
        if (subject == null) {
            String msg = "Programming error - please verify that you have overridden the " +
                getClass().getName() + ".createSubject( Account account ) method to return " +
                "a non-null Subject instance";
            throw new IllegalStateException(msg);
        }
    }

    protected void rememberMeSuccessfulLogin(AuthenticationToken token, Account account) {
        RememberMeManager rmm = getRememberMeManager();
        if (rmm != null) {
            try {
                rmm.onSuccessfulLogin(token, account);
            } catch (Exception e) {
                if (log.isWarnEnabled()) {
                    String msg = "Delegate RememberMeManager instance of type [" + rmm.getClass().getName() +
                        "] threw an exception during onSuccessfulLogin.  RememberMe services will not be " +
                        "performed for Account [" + account + "].";
                    log.warn(msg, e);
                }
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("This " + getClass().getName() + " instance does not have a " +
                    "[" + RememberMeManager.class.getName() + "] instance configured.  RememberMe services " +
                    "will not be performed for account [" + account + "].");
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

    protected void rememberMeLogout(Object subjectPrincipals) {
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
     * @return a Subject representing the authenticated account.
     * @throws AuthenticationException if there is a problem authenticating the specified <tt>token</tt>.
     */
    public Subject login(AuthenticationToken token) throws AuthenticationException {
        Account account;
        try {
            account = authenticate(token);
            rememberMeSuccessfulLogin(token, account);
        } catch (AuthenticationException ae) {
            rememberMeFailedLogin(token, ae);
            throw ae; //propagate
        }
        Subject subject = createSubject(token, account);
        assertCreation(subject);
        bind(subject);
        return subject;
    }

    public void logout(Object subjectIdentifier) {
        rememberMeLogout(subjectIdentifier);

        Authenticator authc = getAuthenticator();
        if ( authc instanceof LogoutAware ) {
            ((LogoutAware)authc).onLogout( subjectIdentifier );
        }

        //Method arg is ignored - get the Subject from the environment if it exists:
        Subject sc = getSubject(false);
        if (sc != null) {
            try {
                unbind(sc);
            } catch (Exception e) {
                String msg = "Unable to cleanly unbind Subject.  Ignoring.";
                if (log.isDebugEnabled()) {
                    log.debug(msg, e);
                }
            }
        }
    }

    protected void unbind(Subject sc) {
        ThreadContext.unbindSubject();
    }

    protected Object getRememberedIdentity() {
        RememberMeManager rmm = getRememberMeManager();
        if (rmm != null) {
            try {
                return rmm.getRememberedIdentity();
            } catch (Exception e) {
                if (log.isWarnEnabled()) {
                    String msg = "Delegate RememberMeManager instance of type [" + rmm.getClass().getName() +
                        "] threw an exception during getRememberedIdentity().";
                    log.warn(msg, e);
                }
            }
        }
        return null;
    }

    protected Subject getSubject(boolean create) {
        Subject sc = ThreadContext.getSubject();
        if (sc == null && create) {
            sc = createSubject();
            bind(sc);
        }
        return sc;
    }

    public Subject getSubject() {
        return getSubject(true);
    }
}