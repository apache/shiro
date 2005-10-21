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

import java.security.Permission;
import java.security.Principal;
import java.util.Collection;
import java.util.List;

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
 */
public class DelegatingAuthorizationContext implements AuthorizationContext {

    private Principal subjectIdentifier;

    private Realm realm;

    public DelegatingAuthorizationContext() {}

    public DelegatingAuthorizationContext( Principal subjectIdentifier, Realm realm ) {
        setSubjectIdentifier( subjectIdentifier );
        setRealm( realm );
    }

    public Principal getSubjectIdentifier() {
        return subjectIdentifier;
    }

    public void setSubjectIdentifier( Principal subjectIdentifier ) {
        this.subjectIdentifier = subjectIdentifier;
    }

    public Realm getRealm() {
        return realm;
    }

    public void setRealm( Realm realm ) {
        this.realm = realm;
    }

    public Principal getPrincipal() {
        return getSubjectIdentifier();
    }

    public boolean hasRole( String roleIdentifier ) {
        return realm.hasRole( subjectIdentifier, roleIdentifier );
    }

    public boolean[] hasRoles( List<String> roleIdentifiers ) {
        return realm.hasRoles( subjectIdentifier, roleIdentifiers );
    }

    public boolean hasAllRoles( Collection<String> roleIdentifiers ) {
        return realm.hasAllRoles( subjectIdentifier, roleIdentifiers );
    }

    public boolean hasPermission( Permission permission ) {
        return realm.isPermitted( subjectIdentifier, permission );
    }

    public boolean[] hasPermissions( List<Permission> permissions ) {
        return realm.isPermitted( subjectIdentifier, permissions );
    }

    public boolean hasAllPermissions( Collection<Permission> permissions ) {
        return realm.isPermittedAll( subjectIdentifier, permissions );
    }

    public void checkPermission( Permission permission ) throws AuthorizationException {
        realm.checkPermission( subjectIdentifier, permission );
    }

    public void checkPermissions( Collection<Permission> permissions )
        throws AuthorizationException {
        realm.checkPermissions( subjectIdentifier, permissions );
    }

}
