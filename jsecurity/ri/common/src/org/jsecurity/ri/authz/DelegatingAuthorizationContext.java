/*
 * Copyright (C) 2005 Les Hazlewood
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
package org.jsecurity.ri.authz;

import org.jsecurity.authz.AuthorizationContext;
import org.jsecurity.authz.AuthorizationException;
import org.jsecurity.authz.NoSuchPrincipalException;

import java.security.Permission;
import java.security.Principal;
import java.util.*;

/**
 * Simple implementation of the <tt>AuthorizationContext</tt> interface that delegates all
 * method calls to an underlying {@link Realm Realm} instance for security checks.  It is
 * essentially a <tt>Realm</tt> proxy.
 *
 * <p>This implementation does not maintain state such as roles and permissions (only a subject
 * identifier, such as a  user primary key or username) for better performance in a stateless
 * architecture.  It instead asks the underlying <tt>Realm</tt> every time to perform
 * the authorization check.
 *
 * <p>A common misconception in using this implementation is that an EIS resource (RDBMS, etc) would
 * be &quot;hit&quot; every time a method is called.  This is not necessarily the case and is
 * up to the implementation of the underlying <tt>Realm</tt> instance.  If caching of authorization
 * context data is desiered (to eliminate EIS round trips and therefore improve database
 * performance), it is considered much more
 * elegant to let the underlying Realm implementation manage caching, not this class.  A Realm is
 * considered a business-tier component, where caching strategies are better managed.
 *
 * <p>Applications from large and clustered to simple and vm local all benefit from
 * stateless architectures.  This implementation plays a part in the stateless programming
 * paradigm and should be used whenever possible.
 *
 * @author Les Hazlewood
 * @author Jeremy Haile
 */
public class DelegatingAuthorizationContext implements AuthorizationContext {

    protected List<Principal> principals;

    protected Realm realm;

    public DelegatingAuthorizationContext() {}

    public DelegatingAuthorizationContext( Principal subjectIdentifier, Realm realm ) {
        this.principals = new ArrayList<Principal>(1);
        this.principals.add( subjectIdentifier );
        this.realm = realm;
    }

    public DelegatingAuthorizationContext(List<Principal> principals, Realm realm) {
        this.principals = principals;
        this.realm = realm;
    }

    public Realm getRealm() {
        return realm;
    }

    /**
     * If multiple principals are defined, this method will return the first
     * principal in the list of principals.
     * @see org.jsecurity.authz.AuthorizationContext#getPrincipal()
     */
    public Principal getPrincipal() {
        if( principals.size() < 1 ) {
            throw new IllegalStateException( "No principals are associated with this authorization context." );
        }
        return this.principals.get(0);
    }

    /**
     * @see org.jsecurity.authz.AuthorizationContext#getAllPrincipals()
     */
    public Collection<Principal> getAllPrincipals() {
        return principals;
    }

    /**
     * @see org.jsecurity.authz.AuthorizationContext#getPrincipalByType(Class) ()
     */
    public Principal getPrincipalByType(Class principalType) throws NoSuchPrincipalException {
        for( Principal principal : principals ) {
            if( principalType.isAssignableFrom( principal.getClass() ) ) {
                return principal;
            }
        }
        return null;
    }

    /**
     * @see org.jsecurity.authz.AuthorizationContext#getAllPrincipalsByType(Class)()
     */
    public Collection<Principal> getAllPrincipalsByType(Class principalType) {
        Set<Principal> principalsOfType = new HashSet<Principal>();

        for( Principal principal : principals ) {
            if( principalType.isAssignableFrom( principal.getClass() ) ) {
                principalsOfType.add( principal );
            }
        }
        return principalsOfType;
    }

    public boolean hasRole( String roleIdentifier ) {
        return realm.hasRole( getPrincipal(), roleIdentifier );
    }

    public boolean[] hasRoles( List<String> roleIdentifiers ) {
        return realm.hasRoles( getPrincipal(), roleIdentifiers );
    }

    public boolean hasAllRoles( Collection<String> roleIdentifiers ) {
        return realm.hasAllRoles( getPrincipal(), roleIdentifiers );
    }

    public boolean hasPermission( Permission permission ) {
        return realm.isPermitted( getPrincipal(), permission );
    }

    public boolean[] hasPermissions( List<Permission> permissions ) {
        return realm.isPermitted( getPrincipal(), permissions );
    }

    public boolean hasAllPermissions( Collection<Permission> permissions ) {
        return realm.isPermittedAll( getPrincipal(), permissions );
    }

    public void checkPermission( Permission permission ) throws AuthorizationException {
        realm.checkPermission( getPrincipal(), permission );
    }

    public void checkPermissions( Collection<Permission> permissions )
        throws AuthorizationException {
        realm.checkPermissions( getPrincipal(), permissions );
    }

}
