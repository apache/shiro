/*
 * Copyright (C) 2005-2007 Les Hazlewood
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
package org.jsecurity.authz;

import org.jsecurity.authz.permission.PermissionResolver;
import org.jsecurity.authz.permission.PermissionResolverAware;
import org.jsecurity.authz.permission.WildcardPermissionResolver;
import org.jsecurity.realm.Realm;
import org.jsecurity.util.Initializable;

import java.util.Collection;
import java.util.List;

/**
 * A <tt>ModularRealmAuthorizer</tt> is an <tt>Authorizer</tt> implementation that consults one or more configured
 * {@link Realm Realm}s during an authorization operation.
 *
 * @author Les Hazlewood
 * @since 0.2
 */
public class ModularRealmAuthorizer implements Authorizer, Initializable, PermissionResolverAware {

    protected Collection<Realm> realms = null;
    protected PermissionResolver permissionResolver = null;

    public ModularRealmAuthorizer() {
    }

    public ModularRealmAuthorizer(List<Realm> realms) {
        setRealms(realms);
        init();
    }

    public Collection<Realm> getRealms() {
        return this.realms;
    }

    public void setRealms(Collection<Realm> realms) {
        this.realms = realms;
    }

    public PermissionResolver getPermissionResolver() {
        return permissionResolver;
    }

    public void setPermissionResolver(PermissionResolver permissionResolver) {
        this.permissionResolver = permissionResolver;
    }

    public void init() {
        Collection<Realm> realms = getRealms();
        if (realms == null || realms.isEmpty()) {
            String msg = "One or more realms must be configured.";
            throw new IllegalStateException(msg);
        }
        PermissionResolver resolver = getPermissionResolver();
        if ( resolver == null ) {
            resolver = new WildcardPermissionResolver();
            setPermissionResolver( resolver );
        }
        for( Realm realm : realms ) {
            if ( realm instanceof PermissionResolverAware ) {
                ((PermissionResolverAware)realm).setPermissionResolver(resolver);
            }
        }
    }


    public boolean isPermitted(Object subjectIdentifier, String permission) {
        for (Realm realm : getRealms()) {
            if (realm.isPermitted(subjectIdentifier, permission)) {
                return true;
            }
        }
        return false;
    }

    public boolean isPermitted(Object subjectIdentifier, Permission permission) {
        for (Realm realm : getRealms()) {
            if (realm.isPermitted(subjectIdentifier, permission)) {
                return true;
            }
        }
        return false;
    }

    public boolean[] isPermitted(Object subjectIdentifier, String... permissions) {
        if (permissions != null && permissions.length > 0) {
            boolean[] isPermitted = new boolean[permissions.length];
            for (int i = 0; i < permissions.length; i++) {
                isPermitted[i] = isPermitted(subjectIdentifier, permissions[i]);
            }
            return isPermitted;
        }
        return new boolean[0];
    }

    public boolean[] isPermitted(Object subjectIdentifier, List<Permission> permissions) {
        if (permissions != null && !permissions.isEmpty()) {
            boolean[] isPermitted = new boolean[permissions.size()];
            int i = 0;
            for (Permission p : permissions) {
                isPermitted[i++] = isPermitted(subjectIdentifier, p);
            }
            return isPermitted;
        }

        return new boolean[0];
    }

    public boolean isPermittedAll(Object subjectIdentifier, String... permissions) {
        if (permissions != null && permissions.length > 0) {
            for (String perm : permissions) {
                if (!isPermitted(subjectIdentifier, perm)) {
                    return false;
                }
            }
        }
        return true;
    }

    public boolean isPermittedAll(Object subjectIdentifier, Collection<Permission> permissions) {
        if (permissions != null && !permissions.isEmpty()) {
            for (Permission permission : permissions) {
                if (!isPermitted(subjectIdentifier, permission)) {
                    return false;
                }
            }
        }
        return true;
    }

    public void checkPermission(Object subjectIdentifier, String permission) throws AuthorizationException {
        if ( !isPermitted(subjectIdentifier, permission ) ) {
            throw new UnauthorizedException("Subject does not have permission [" + permission + "]");
        }
    }

    public void checkPermission(Object subjectIdentifier, Permission permission) throws AuthorizationException {
        if (!isPermitted(subjectIdentifier, permission)) {
            throw new UnauthorizedException("Subject does not have permission [" + permission + "]");
        }
    }

    public void checkPermissions(Object subjectIdentifier, String... permissions) throws AuthorizationException {
        if ( permissions != null && permissions.length > 0 ) {
            for( String perm : permissions ) {
                checkPermission( subjectIdentifier, perm );
            }
        }
    }

    public void checkPermissions(Object subjectIdentifier, Collection<Permission> permissions) throws AuthorizationException {
        if (permissions != null) {
            for (Permission permission : permissions) {
                checkPermission(subjectIdentifier, permission);
            }
        }
    }

    public boolean hasRole(Object subjectIdentifier, String roleIdentifier) {
        for (Realm realm : getRealms()) {
            if (realm.hasRole(subjectIdentifier, roleIdentifier)) {
                return true;
            }
        }
        return false;
    }

    public boolean[] hasRoles(Object subjectIdentifier, List<String> roleIdentifiers) {
        if (roleIdentifiers != null && !roleIdentifiers.isEmpty()) {
            boolean[] isPermitted = new boolean[roleIdentifiers.size()];
            int i = 0;
            for (String roleId : roleIdentifiers ) {
                isPermitted[i++] = hasRole( subjectIdentifier, roleId );
            }
            return isPermitted;
        }

        return new boolean[0];
    }


    public boolean hasAllRoles(Object subjectIdentifier, Collection<String> roleIdentifiers) {
        for (String roleIdentifier : roleIdentifiers) {
            if (!hasRole(subjectIdentifier, roleIdentifier)) {
                return false;
            }
        }
        return true;
    }

    public void checkRole(Object subjectIdentifier, String role) throws AuthorizationException {
        if (!hasRole(subjectIdentifier, role)) {
            throw new UnauthorizedException("Subject does not have role [" + role + "]");
        }
    }

    public void checkRoles(Object subjectIdentifier, Collection<String> roles) throws AuthorizationException {
        if (roles != null) {
            for (String role : roles) {
                checkRole(subjectIdentifier, role);
            }
        }
    }

}
