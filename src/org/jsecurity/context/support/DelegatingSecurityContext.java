/*
 * Copyright (C) 2005-2007 Les Hazlewood, Jeremy Haile
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
import org.jsecurity.SecurityManager;
import org.jsecurity.authc.AuthenticationException;
import org.jsecurity.authc.AuthenticationToken;
import org.jsecurity.authc.InetAuthenticationToken;
import org.jsecurity.authz.AuthorizationException;
import org.jsecurity.authz.Permission;
import org.jsecurity.authz.UnauthenticatedException;
import org.jsecurity.context.SecurityContext;
import org.jsecurity.session.InvalidSessionException;
import org.jsecurity.session.Session;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

/**
 * <p>Simple implementation of the <tt>SecurityContext</tt> interface that delegates
 * method calls to an underlying {@link org.jsecurity.SecurityManager SecurityManager} instance for security checks.
 * It is essentially a <tt>SecurityManager</tt> proxy.</p>
 *
 * <p>This implementation does not maintain state such as roles and permissions (only a subject
 * identifier, such as a user primary key or username) for better performance in a stateless
 * architecture.  It instead asks the underlying <tt>SecurityManager</tt> every time to perform
 * the authorization check.</p>
 *
 * <p>A common misconception in using this implementation is that an EIS resource (RDBMS, etc) would
 * be &quot;hit&quot; every time a method is called.  This is not necessarily the case and is
 * up to the implementation of the underlying <tt>SecurityManager</tt> instance.  If caching of authorization
 * context data is desired (to eliminate EIS round trips and therefore improve database performance), it is considered
 * much more elegant to let the underlying <tt>SecurityManager</tt> implementation manage caching, not this class.  A
 * <tt>SecurityManager</tt> is considered a business-tier component, where caching strategies are better suited.</p>
 *
 * <p>Applications from large and clustered to simple and vm local all benefit from
 * stateless architectures.  This implementation plays a part in the stateless programming
 * paradigm and should be used whenever possible.</p>
 *
 * @author Les Hazlewood
 * @author Jeremy Haile
 * @since 0.1
 */
public class DelegatingSecurityContext implements SecurityContext {

    protected transient final Log log = LogFactory.getLog(getClass());

    protected Object principals = null;
    protected boolean authenticated = false;
    protected InetAddress inetAddress = null;
    protected Session session = null;
    protected boolean invalidated = false;

    protected SecurityManager securityManager;    

    protected static InetAddress getLocalHost() {
        try {
            return InetAddress.getLocalHost();
        } catch (UnknownHostException e) {
            return null;
        }
    }

    public DelegatingSecurityContext(SecurityManager securityManager) {
        this(false, getLocalHost(), null, securityManager);
    }

    public DelegatingSecurityContext(boolean authenticated, InetAddress inetAddress, Session session, SecurityManager securityManager) {
        this(null, authenticated, inetAddress, session, securityManager);
    }

    public DelegatingSecurityContext( List principals, boolean authenticated, InetAddress inetAddress,
                                      Session session, SecurityManager securityManager ) {
        this( (Object)principals, authenticated, inetAddress, session, securityManager );
    }


    public DelegatingSecurityContext( Object principals, boolean authenticated, InetAddress inetAddress,
                                     Session session, SecurityManager securityManager) {
        if (securityManager == null) {
            throw new IllegalArgumentException("SecurityManager cannot be null.");
        }

        if ( principals instanceof Collection ) {
            //noinspection unchecked
            this.principals = Collections.unmodifiableCollection( (Collection)principals );
        } else {
            this.principals = principals;
        }

        this.authenticated = authenticated;

        if ( inetAddress != null ) {
            this.inetAddress = inetAddress;
        } else {
            this.inetAddress = getLocalHost();
        }
        this.session = session;
        this.securityManager = securityManager;
    }

    protected void assertValid() throws InvalidSecurityContextException {
        if (isInvalidated()) {
            String msg = "The SecurityContext has been invalidated.  It can no longer be used.";
            throw new InvalidSecurityContextException(msg);
        }
    }

    protected boolean isInvalidated() {
        return invalidated;
    }

    protected void setInvalidated(boolean invalidated) {
        this.invalidated = invalidated;
    }

    public SecurityManager getSecurityManager() {
        return securityManager;
    }

    protected boolean hasPrincipal() {
        return getPrincipal() != null;
    }

    /**
     * Returns the InetAddress associated with the client who created/is interacting with this SecurityContext.
     *
     * @return the InetAddress associated with the client who created/is interacting with this SecurityContext.
     */
    public InetAddress getInetAddress() {
        assertValid();
        return this.inetAddress;
    }

    /**
     * If multiple principals are defined, this method will return the first
     * principal in the list of principals.
     *
     * @see org.jsecurity.context.SecurityContext#getPrincipal()
     */
    public Object getPrincipal() {
        assertValid();
        if ( this.principals instanceof Collection ) {
            Collection c = (Collection)this.principals;
            if ( !c.isEmpty() ) {
                return c.iterator().next();
            }
        }
        return this.principals;
    }

    /** @see org.jsecurity.context.SecurityContext#getAllPrincipals() */
    public List getAllPrincipals() {
        assertValid();
        List list;
        if ( this.principals instanceof Collection ) {
            if ( this.principals instanceof List ) {
                list = (List)this.principals;
            } else {
                //noinspection unchecked
                list = new ArrayList( (Collection)this.principals );
            }
        } else {
            list = new ArrayList();
            if ( this.principals != null ) {
                //noinspection unchecked
                list.add( this.principals );
            }
        }

        return list;
    }

    /** @see org.jsecurity.context.SecurityContext#getPrincipalByType(Class) () */
    public <T> T getPrincipalByType(Class<T> principalType) {
        assertValid();
        if ( this.principals instanceof Collection ) {
            Collection c = (Collection)this.principals;
            for( Object o : c ) {
                if ( principalType.isAssignableFrom( o.getClass() ) ) {
                    //noinspection unchecked
                    return (T)o;
                }
            }
        } else {
            if ( principalType.isAssignableFrom(this.principals.getClass())) {
                //noinspection unchecked
                return (T)this.principals;
            }
        }
        return null;
    }

    /** @see org.jsecurity.context.SecurityContext#getAllPrincipalsByType(Class)() */
    public <T> List<T> getAllPrincipalsByType(Class<T> principalType) {
        assertValid();
        List<T> principalsOfType = new ArrayList<T>();

        if (principals != null) {
            if ( principals instanceof Collection ) {
                Collection c = (Collection)principals;
                if ( !c.isEmpty() ) {
                    for( Object o : c ) {
                        if ( principalType.isAssignableFrom( o.getClass() ) ) {
                            //noinspection unchecked
                            principalsOfType.add( (T)o );
                        }
                    }
                }
            } else {
                if ( principalType.isAssignableFrom( principals.getClass() ) ) {
                    //noinspection unchecked
                    principalsOfType.add( (T)principals );
                }
            }
        }
        return principalsOfType;
    }

    public boolean hasRole(String roleIdentifier) {
        assertValid();
        return hasPrincipal() && securityManager.hasRole(getPrincipal(), roleIdentifier);
    }

    public boolean[] hasRoles(List<String> roleIdentifiers) {
        assertValid();
        if (hasPrincipal()) {
            return securityManager.hasRoles(getPrincipal(), roleIdentifiers);
        } else {
            return new boolean[roleIdentifiers.size()];
        }
    }

    public boolean hasAllRoles(Collection<String> roleIdentifiers) {
        assertValid();
        return hasPrincipal() && securityManager.hasAllRoles(getPrincipal(), roleIdentifiers);
    }

    public boolean isPermitted(Permission permission) {
        assertValid();
        return hasPrincipal() && securityManager.isPermitted(getPrincipal(), permission);
    }

    public boolean[] isPermitted(List<Permission> permissions) {
        assertValid();
        if (hasPrincipal()) {
            return securityManager.isPermitted(getPrincipal(), permissions);
        } else {
            return new boolean[permissions.size()];
        }
    }

    public boolean isPermittedAll(Collection<Permission> permissions) {
        assertValid();
        return hasPrincipal() && securityManager.isPermittedAll(getPrincipal(), permissions);
    }

    protected void assertAuthzCheckPossible() throws AuthorizationException {
        if (!hasPrincipal()) {
            String msg = "Subject/User data has not yet been associated with this SecurityContext " +
                "(this can be done by executing " + SecurityContext.class.getName() + ".login(AuthenticationToken) )." +
                "Therefore, authorization operations are not possible (a Subject/User identity is required first).  " +
                "Denying authorization.";
            throw new UnauthenticatedException(msg);
        }
    }

    public void checkPermission(Permission permission) throws AuthorizationException {
        assertValid();
        assertAuthzCheckPossible();
        securityManager.checkPermission(getPrincipal(), permission);
    }

    public void checkPermissions(Collection<Permission> permissions)
        throws AuthorizationException {
        assertValid();
        assertAuthzCheckPossible();
        securityManager.checkPermissions(getPrincipal(), permissions);
    }

    public void checkRole(String role) throws AuthorizationException {
        assertValid();
        assertAuthzCheckPossible();
        securityManager.checkRole(getPrincipal(), role);
    }

    public void checkRoles(Collection<String> roles) throws AuthorizationException {
        assertValid();
        assertAuthzCheckPossible();
        securityManager.checkRoles(getPrincipal(), roles);
    }

    public void login(AuthenticationToken token) throws AuthenticationException {
        assertValid();
        SecurityContext authcSecCtx = securityManager.login(token);
        List principals = authcSecCtx.getAllPrincipals();
        if (principals == null || principals.isEmpty()) {
            String msg = "Principals collection returned from securityManager.login( token ) returned " +
                "is null or empty.  This collection must be populated - please check the SecurityManager " +
                "implementation to ensure this happens after a successful login attempt.";
            throw new IllegalStateException(msg);
        }
        this.principals = principals;
        this.authenticated = true;
        if (token instanceof InetAuthenticationToken) {
            InetAddress addy = ((InetAuthenticationToken) token).getInetAddress();
            if (addy != null) {
                this.inetAddress = addy;
            }
        }
    }

    public boolean isAuthenticated() {
        assertValid();
        return authenticated;
    }

    public Session getSession() {
        return getSession(true);
    }

    public Session getSession(boolean create) {
        assertValid();
        if (this.session == null && create) {
            this.session = securityManager.start(getInetAddress());
        }
        return this.session;
    }

    public void invalidate() {
        if (isInvalidated()) {
            return;
        }
        setInvalidated(true);

        Session s = getSession(false);
        if (s != null) {
            try {
                s.stop();
            } catch (InvalidSessionException ise) {
                //ignored - we're invalidating, and have no further need of the session anyway
                //log just in case someone wants to know:
                if (log.isTraceEnabled()) {
                    log.trace("Session has already been invalidated.  Ignoring and continuing logout ...", ise);
                }
            }
        }

        this.securityManager.logout(getPrincipal());
        this.session = null;
        this.principals = new ArrayList();
        this.authenticated = false;
        this.inetAddress = null;
        this.securityManager = null;
    }

}
