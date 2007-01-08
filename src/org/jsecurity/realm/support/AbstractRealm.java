/*
 * Copyright (C) 2006 Jeremy Haile
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

package org.jsecurity.realm.support;

import org.jsecurity.authc.module.support.AbstractAuthenticationModule;
import org.jsecurity.authz.AuthorizationException;
import org.jsecurity.authz.NoAuthorizationInfoFoundException;
import org.jsecurity.realm.Realm;

import java.security.Permission;
import java.security.Principal;
import java.util.Collection;
import java.util.List;

/**
 * <p>An abstract implementation of the {@link Realm} interface that allows
 * subclasses to simply implement the {@link AbstractAuthenticationModule#doGetAuthenticationInfo(org.jsecurity.authc.AuthenticationToken)}
 * and {@link AbstractRealm#getAuthorizationInfo(java.security.Principal)} methods.</p>
 *
 * <p>This realm also returns the fully qualified class name of the realm implementation as the
 * realm's unique name - but a name can be specified by the {@link #setName(String)} method.  This is necessary
 * if more than one realm of the same type is used in an application.</p>
 *
 * @since 0.2
 * @author Jeremy Haile
 */
public abstract class AbstractRealm extends AbstractAuthenticationModule implements Realm {

    /*--------------------------------------------
    |             C O N S T A N T S             |
    ============================================*/

    /*--------------------------------------------
    |    I N S T A N C E   V A R I A B L E S    |
    ============================================*/
    /**
     * The name of this realm, or null if the fully-qualified class name should be returned
     * as the realm name.
     */
    private String name;

    /*--------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*/

    /*--------------------------------------------
    |  A C C E S S O R S / M O D I F I E R S    |
    ============================================*/
    public void setName(String name) {
        this.name = name;
    }


    /*--------------------------------------------
    |               M E T H O D S               |
    ============================================*/


    /**
     * This method should be implemented by subclasses to retrieve authorization information for
     * the given principal.
     * @param principal the principal that authorization information should be retrieved for.
     * @return an {@link AuthorizationInfo} object encapsulating the authorization information
     * associated with the given principal.
     * @throws NoAuthorizationInfoFoundException if authorization information could not
     * be found for the given principal.
     */
    protected abstract AuthorizationInfo getAuthorizationInfo(Principal principal);

    /**
     * The default implementation of getName() returns the fully-qualified class name if no
     * name has been specified for this Realm.  If more than one realm of a
     * particular Realm class is used in an application, the name must be
     * manually specified.
     * @return the name associated with this realm, or the fully-qualified class name
     * of the realm implementation if a name has not been assigned.
     */
    public String getName() {
        if( this.name == null ) {
            return getClass().getName();
        } else {
            return this.name;
        }
    }


    /**
     * Checks the returned authorization information for validity.  The default implementation
     * simply checks that it is not null.
     * @param info the info being checked.
     * @param principal the principal that info was retrieved for.
     */
    protected void checkAuthorizationInfo(AuthorizationInfo info, Principal principal) {
        if( info == null ) {
            throw new NoAuthorizationInfoFoundException( "No authorization info found for principal [" + principal + "] in realm [" + getName() + "]" );
        }
    }

    public boolean hasRole(Principal principal, String roleIdentifier) {
        AuthorizationInfo info = getAuthorizationInfo( principal );
        checkAuthorizationInfo( info, principal );
        return info.hasRole( roleIdentifier );
    }


    public boolean[] hasRoles(Principal principal, List<String> roleIdentifiers) {
        AuthorizationInfo info = getAuthorizationInfo( principal );
        checkAuthorizationInfo( info, principal );
        return info.hasRoles( roleIdentifiers );
    }

    public boolean hasAllRoles(Principal principal, Collection<String> roleIdentifiers) {
        AuthorizationInfo info = getAuthorizationInfo( principal );
        checkAuthorizationInfo( info, principal );
        return info.hasAllRoles( roleIdentifiers );
    }

    public boolean isPermitted(Principal principal, Permission permission) {
        AuthorizationInfo info = getAuthorizationInfo( principal );
        checkAuthorizationInfo( info, principal );
        return info.implies( permission );
    }

    public boolean[] isPermitted(Principal principal, List<Permission> permissions) {
        AuthorizationInfo info = getAuthorizationInfo( principal );
        checkAuthorizationInfo( info, principal );
        return info.implies( permissions );
    }

    public boolean isPermittedAll(Principal principal, Collection<Permission> permissions) {
        AuthorizationInfo info = getAuthorizationInfo( principal );
        checkAuthorizationInfo( info, principal );
        return info.impliesAll( permissions );
    }

    public void checkPermission(Principal principal, Permission permission) throws AuthorizationException {
        AuthorizationInfo info = getAuthorizationInfo( principal );
        checkAuthorizationInfo( info, principal );
        info.checkPermission( permission );
    }

    public void checkPermissions(Principal principal, Collection<Permission> permissions) throws AuthorizationException {
        AuthorizationInfo info = getAuthorizationInfo( principal );
        checkAuthorizationInfo( info, principal );
        info.checkPermissions( permissions );
    }


}