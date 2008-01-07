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
package org.jsecurity.authz.support;

import org.jsecurity.authz.*;
import org.jsecurity.authz.method.MethodAuthorizer;
import org.jsecurity.realm.Realm;
import org.jsecurity.util.Initializable;
import org.jsecurity.util.JavaEnvironment;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * TODO class JavaDoc
 *
 * @since 0.2
 * @author Les Hazlewood
 */
public class ModularRealmAuthorizer implements Authorizer, Initializable {

    protected Collection<Realm> realms = null;

    //TODO - refactor name (ambiguous)
    protected List<MethodAuthorizer> methodAuthorizers = null;

    public ModularRealmAuthorizer(){}

    public ModularRealmAuthorizer( List<Realm> realms ) {
        setRealms( realms );
        init();
    }

    public Collection<Realm> getRealms() {
        return this.realms;
    }

    public void setRealms( Collection<Realm> realms ) {
        this.realms = realms;
    }

    public List<MethodAuthorizer> getAuthorizationModules() {
        return methodAuthorizers;
    }

    public void setAuthorizationModules( List<MethodAuthorizer> methodAuthorizers) {
        this.methodAuthorizers = methodAuthorizers;
    }

    public void init() {
        Collection<Realm> realms = getRealms();
        if ( realms == null || realms.isEmpty() ) {
            String msg = "One or more realms must be configured.";
            throw new IllegalStateException( msg );
        }
        if ( JavaEnvironment.isAtLeastVersion15() ) {
            methodAuthorizers = new ArrayList<MethodAuthorizer>(2);

            PermissionAnnotationMethodAuthorizer permModule = new PermissionAnnotationMethodAuthorizer();
            permModule.init();
            methodAuthorizers.add( permModule );

            RoleAnnotationMethodAuthorizer roleModule = new RoleAnnotationMethodAuthorizer();
            roleModule.init();
            methodAuthorizers.add( roleModule );
        }
    }


    public boolean hasRole(Object subjectIdentifier, String roleIdentifier) {
        boolean hasRole = false;
        for( Realm realm : getRealms() ) {
            if( realm.hasRole( subjectIdentifier, roleIdentifier ) ) {
                hasRole = true;
                break;
            }
        }
        return hasRole;
    }

    public boolean[] hasRoles(Object subjectIdentifier, List<String> roleIdentifiers) {
        boolean[] hasRoles = new boolean[roleIdentifiers.size()];

        for( Realm realm : getRealms() ) {
            boolean realmHasRoles[] = realm.hasRoles( subjectIdentifier, roleIdentifiers );

            for( int i = 0; i < realmHasRoles.length; i++ ) {
                if( realmHasRoles[i] ) {
                    hasRoles[i] = true;
                }
            }
        }
        return hasRoles;
    }


    public boolean hasAllRoles(Object subjectIdentifier, Collection<String> roleIdentifiers) {
        for( String roleIdentifier : roleIdentifiers ) {
            if( !hasRole( subjectIdentifier, roleIdentifier ) ) {
                return false;
            }
        }
        return true;
    }


    public boolean isPermitted(Object subjectIdentifier, Permission permission) {
        for( Realm realm : getRealms() ) {
            if( realm.isPermitted( subjectIdentifier,  permission ) ) {
                return true;
            }
        }
        return false;
    }


    public boolean[] isPermitted(Object subjectIdentifier, List<Permission> permissions) {
        boolean[] isPermitted = new boolean[permissions.size()];
        for( Realm realm : getRealms() ) {
            boolean realmIsPermitted[] = realm.isPermitted( subjectIdentifier, permissions );

            for( int i = 0; i < realmIsPermitted.length; i++ ) {
                if( realmIsPermitted[i] ) {
                    isPermitted[i] = true;
                }
            }
        }
        return isPermitted;
    }


    public boolean isPermittedAll(Object subjectIdentifier, Collection<Permission> permissions) {
        for( Permission permission : permissions ) {
            if( !isPermitted( subjectIdentifier, permission ) ) {
                return false;
            }
        }
        return true;
    }


    public void checkPermission(Object subjectIdentifier, Permission permission) throws AuthorizationException {
        if( !isPermitted( subjectIdentifier, permission ) ) {
            throw new AuthorizationException( "User does not have permission [" + permission.toString() + "]" );
        }
    }


    public void checkPermissions(Object subjectIdentifier, Collection<Permission> permissions) throws AuthorizationException {
        if( permissions != null ) {
            for( Permission permission : permissions ) {
                checkPermission( subjectIdentifier, permission );
            }
        }
    }

    public void checkRole(Object subjectIdentifier, String role) throws AuthorizationException {
        if( !hasRole( subjectIdentifier, role ) ) {
            throw new AuthorizationException( "User does not have role [" + role + "]" );
        }
    }

    public void checkRoles(Object subjectIdentifier, Collection<String> roles) throws AuthorizationException {
        if( roles != null ) {
            for( String role : roles ) {
                checkRole( subjectIdentifier, role );
            }
        }
    }

}
