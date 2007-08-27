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

import org.jsecurity.SecurityManager;
import org.jsecurity.authz.AuthorizationException;
import org.jsecurity.authz.AuthorizedAction;
import org.jsecurity.authz.NoSuchPrincipalException;
import org.jsecurity.authz.Permission;
import org.jsecurity.context.SecurityContext;
import org.jsecurity.session.Session;

import java.net.InetAddress;
import java.security.Principal;
import java.util.*;

/**
 * Simple implementation of the <tt>SecurityContext</tt> interface that delegates
 * method calls to an underlying {@link org.jsecurity.SecurityManager SecurityManager} instance for security checks.
 * It is essentially a <tt>SecurityManager</tt> proxy.
 *
 * <p>This implementation does not maintain state such as roles and permissions (only a subject
 * identifier, such as a user primary key or username) for better performance in a stateless
 * architecture.  It instead asks the underlying <tt>SecurityManager</tt> every time to perform
 * the authorization check.
 *
 * <p>A common misconception in using this implementation is that an EIS resource (RDBMS, etc) would
 * be &quot;hit&quot; every time a method is called.  This is not necessarily the case and is
 * up to the implementation of the underlying <tt>SecurityManager</tt> instance.  If caching of authorization
 * context data is desired (to eliminate EIS round trips and therefore improve database performance), it is considered
 * much more elegant to let the underlying <tt>SecurityManager</tt> implementation manage caching, not this class.  A
 * <tt>SecurityManager</tt> is considered a business-tier component, where caching strategies are better suited.
 *
 * <p>Applications from large and clustered to simple and vm local all benefit from
 * stateless architectures.  This implementation plays a part in the stateless programming
 * paradigm and should be used whenever possible.
 *
 * @author Les Hazlewood
 * @author Jeremy Haile
 * @since 0.1
 */
public class DelegatingSecurityContext implements SecurityContext {

    protected List<Principal> principals;
    protected boolean authenticated;
    protected InetAddress inetAddress = null;
    protected Session session = null;
    protected SecurityManager securityManager;
    protected boolean invalidated = false;

    private static List<Principal> toList( Principal p ) {
        List<Principal> principals = new ArrayList<Principal>(1);
        if ( p != null ) {
            principals.add( p );
        }
        return principals;
    }

    private static List<Principal> toList( List<Principal> ps ) {
        List<Principal> principals = new ArrayList<Principal>( ps != null ? ps.size() : 1 );
        principals.addAll( ps );
        return principals;
    }

    public DelegatingSecurityContext( Principal principal, boolean authenticated, InetAddress inetAddress,
                                      Session session, SecurityManager securityManager ) {
        this( toList( principal ), authenticated, inetAddress, session, securityManager );
    }

    public DelegatingSecurityContext( List<Principal> principals, boolean authenticated, InetAddress inetAddress,
                                      Session session, SecurityManager securityManager ) {
        if ( securityManager == null ) {
            throw new IllegalArgumentException( "SecurityManager cannot be null." );
        }
        this.principals = toList( principals );
        this.authenticated = authenticated;
        this.inetAddress = inetAddress;
        this.session = session;
        this.securityManager = securityManager;
    }

    protected boolean isInvalidated() {
        return invalidated;
    }

    protected void setInvalidated( boolean invalidated ) {
        this.invalidated = invalidated;
    }

    protected void assertValid() throws InvalidSecurityContextException {
        if ( isInvalidated() ) {
            String msg = "The SecurityContext has been invalidated.  It can no longer be used.";
            throw new InvalidSecurityContextException( msg );
        }
    }

    /**
     * Returns the InetAddress associated with the client who created/is interacting with this SecurityContext.
     * <p/>
     * <p>The default implementation attempts to get the InetAddress from a thread local for use in server-side
     * environments.  Subclasses can override this method to retrieve the InetAddress from somewhere else (for
     * example, as a system property in a standalone application, or an applet parameter for an applet).
     *
     * @return the InetAddress associated with the client who created/is interacting with this SecurityContext.
     */
    protected InetAddress getInetAddress() {
        assertValid();
        return this.inetAddress;
    }

    /**
     * If multiple principals are defined, this method will return the first
     * principal in the list of principals.
     *
     * @see org.jsecurity.context.SecurityContext#getPrincipal()
     */
    public Principal getPrincipal() {
        assertValid();
        if ( this.principals.isEmpty() ) {
            return null;
        } else {
            return this.principals.get( 0 );
        }
    }

    /**
     * @see org.jsecurity.context.SecurityContext#getAllPrincipals()
     */
    public List<Principal> getAllPrincipals() {
        assertValid();
        return principals;
    }

    /**
     * @see org.jsecurity.context.SecurityContext#getPrincipalByType(Class) ()
     */
    public Principal getPrincipalByType( Class<Principal> principalType ) throws NoSuchPrincipalException {
        assertValid();
        for ( Principal principal : principals ) {
            if ( principalType.isAssignableFrom( principal.getClass() ) ) {
                return principal;
            }
        }
        return null;
    }

    /**
     * @see org.jsecurity.context.SecurityContext#getAllPrincipalsByType(Class)()
     */
    public Collection<Principal> getAllPrincipalsByType( Class<Principal> principalType ) {
        assertValid();
        Set<Principal> principalsOfType = new HashSet<Principal>();

        for ( Principal principal : principals ) {
            if ( principalType.isAssignableFrom( principal.getClass() ) ) {
                principalsOfType.add( principal );
            }
        }
        return principalsOfType;
    }

    public boolean hasRole( String roleIdentifier ) {
        assertValid();
        return getPrincipal() != null && securityManager.hasRole( getPrincipal(), roleIdentifier );
    }

    public boolean[] hasRoles( List<String> roleIdentifiers ) {
        assertValid();
        if ( getPrincipal() != null ) {
            return securityManager.hasRoles( getPrincipal(), roleIdentifiers );
        } else {
            return new boolean[roleIdentifiers.size()];
        }
    }

    public boolean hasAllRoles( Collection<String> roleIdentifiers ) {
        assertValid();
        return getPrincipal() != null && securityManager.hasAllRoles( getPrincipal(), roleIdentifiers );
    }

    public boolean implies( Permission permission ) {
        assertValid();
        return getPrincipal() != null && securityManager.isPermitted( getPrincipal(), permission );
    }

    public boolean[] implies( List<Permission> permissions ) {
        assertValid();
        if ( getPrincipal() != null ) {
            return securityManager.isPermitted( getPrincipal(), permissions );
        } else {
            return new boolean[permissions.size()];
        }
    }

    public boolean impliesAll( Collection<Permission> permissions ) {
        assertValid();
        return getPrincipal() != null && securityManager.isPermittedAll( getPrincipal(), permissions );
    }

    public void checkPermission( Permission permission ) throws AuthorizationException {
        assertValid();
        securityManager.checkPermission( getPrincipal(), permission );
    }

    public void checkPermissions( Collection<Permission> permissions )
        throws AuthorizationException {
        assertValid();
        securityManager.checkPermissions( getPrincipal(), permissions );
    }

    public void checkRole( String role ) throws AuthorizationException {
        assertValid();
        securityManager.checkRole( getPrincipal(), role );
    }

    public void checkRoles( Collection<String> roles ) throws AuthorizationException {
        assertValid();
        securityManager.checkRoles( getPrincipal(), roles );
    }

    public boolean isAuthorized( AuthorizedAction action ) {
        assertValid();
        return securityManager.isAuthorized( getPrincipal(), action );
    }

    public void checkAuthorization( AuthorizedAction action ) throws AuthorizationException {
        assertValid();
        securityManager.checkAuthorization( getPrincipal(), action );
    }

    public boolean isAuthenticated() {
        assertValid();
        return authenticated;
    }

    public Session getSession() {
        return getSession( true );
    }

    public Session getSession( boolean create ) {
        assertValid();
        if ( this.session == null && create ) {
            this.session = securityManager.start( getInetAddress() );
        }
        return this.session;
    }

    public void invalidate() {
        if ( isInvalidated() ) {
            return;
        }
        Session s = getSession( false );
        if ( s != null ) {
            s.stop();
        }
        this.session = null;
        this.principals.clear();
        this.authenticated = false;
        this.inetAddress = null;
        this.securityManager = null;
        setInvalidated( true );
    }

}
