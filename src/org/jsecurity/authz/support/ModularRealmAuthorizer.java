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
import org.jsecurity.realm.Realm;
import org.jsecurity.util.Initializable;
import org.jsecurity.util.JavaEnvironment;

import java.security.Principal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * TODO class JavaDoc
 *
 * @since 0.2
 *
 * @author Les Hazlewood
 */
public class ModularRealmAuthorizer implements Authorizer, Initializable {

    protected List<Realm> realms = null;

    //TODO - refactor name (ambiguous)
    protected List<AuthorizationModule> authorizationModules = null;

    public ModularRealmAuthorizer(){}

    public ModularRealmAuthorizer( List<Realm> realms ) {
        setRealms( realms );
        init();
    }

    public List<Realm> getRealms() {
        return this.realms;
    }

    public void setRealms( List<Realm> realms ) {
        this.realms = realms;
    }

    public List<AuthorizationModule> getAuthorizationModules() {
        return authorizationModules;
    }

    public void setAuthorizationModules( List<AuthorizationModule> authorizationModules ) {
        this.authorizationModules = authorizationModules;
    }

    public void init() {
        List<Realm> realms = getRealms();
        if ( realms == null || realms.isEmpty() ) {
            String msg = "One or more realms must be configured.";
            throw new IllegalStateException( msg );
        }
        if ( JavaEnvironment.isAtLeastVersion15() ) {
            authorizationModules = new ArrayList<AuthorizationModule>(2);

            PermissionAnnotationAuthorizationModule permModule = new PermissionAnnotationAuthorizationModule();
            permModule.init();
            authorizationModules.add( permModule );

            RoleAnnotationAuthorizationModule roleModule = new RoleAnnotationAuthorizationModule();
            roleModule.init();
            authorizationModules.add( roleModule );
        }
    }


    public boolean hasRole(Principal subjectIdentifier, String roleIdentifier) {
        boolean hasRole = false;
        for( Realm realm : getRealms() ) {
            if( realm.hasRole( subjectIdentifier, roleIdentifier ) ) {
                hasRole = true;
                break;
            }
        }
        return hasRole;
    }

    public boolean[] hasRoles(Principal subjectIdentifier, List<String> roleIdentifiers) {
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


    public boolean hasAllRoles(Principal subjectIdentifier, Collection<String> roleIdentifiers) {
        for( String roleIdentifier : roleIdentifiers ) {
            if( !hasRole( subjectIdentifier, roleIdentifier ) ) {
                return false;
            }
        }
        return true;
    }


    public boolean isPermitted(Principal subjectIdentifier, Permission permission) {
        for( Realm realm : getRealms() ) {
            if( realm.isPermitted( subjectIdentifier,  permission ) ) {
                return true;
            }
        }
        return false;
    }


    public boolean[] isPermitted(Principal subjectIdentifier, List<Permission> permissions) {
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


    public boolean isPermittedAll(Principal subjectIdentifier, Collection<Permission> permissions) {
        for( Permission permission : permissions ) {
            if( !isPermitted( subjectIdentifier, permission ) ) {
                return false;
            }
        }
        return true;
    }


    public void checkPermission(Principal subjectIdentifier, Permission permission) throws AuthorizationException {
        if( !isPermitted( subjectIdentifier, permission ) ) {
            throw new AuthorizationException( "User does not have permission [" + permission.toString() + "]" );
        }
    }


    public void checkPermissions(Principal subjectIdentifier, Collection<Permission> permissions) throws AuthorizationException {
        if( permissions != null ) {
            for( Permission permission : permissions ) {
                checkPermission( subjectIdentifier, permission );
            }
        }
    }

    public void checkRole(Principal subjectIdentifier, String role) throws AuthorizationException {
        if( !hasRole( subjectIdentifier, role ) ) {
            throw new AuthorizationException( "User does not have role [" + role + "]" );
        }
    }

    public void checkRoles(Principal subjectIdentifier, Collection<String> roles) throws AuthorizationException {
        if( roles != null ) {
            for( String role : roles ) {
                checkRole( subjectIdentifier, role );
            }
        }
    }

    public boolean supports( AuthorizedAction action ) {
        for( Realm realm : getRealms() ) {
            if ( realm.supports( action ) ) {
                return true;
            }
        }

        //the ModularRealmAuthorizer also supports JDK 1.5 Annotations by default as well, configured in the
        //init() method if on JDK 1.5+.  These checks happen independently of Realm access since
        //they use the SecurityContext directly.
        return JavaEnvironment.isAtLeastVersion15();
    }

    public boolean isAuthorized( Principal subjectIdentifier, AuthorizedAction action ) {

        if ( supports( action ) ) {
            for( Realm realm : getRealms() ) {
                if ( realm.supports( action ) ) {
                    if ( !realm.isAuthorized( subjectIdentifier, action ) ) {
                        return false;
                    }
                }
            }
            return true;
        }

        if ( authorizationModules != null && !authorizationModules.isEmpty() ) {
            for( AuthorizationModule module : authorizationModules ) {
                if ( module.supports( action ) ) {
                    if ( module.isAuthorized( action ).equals( AuthorizationVote.deny ) ) {
                        return false;
                    }
                }
            }
            return true;
        }

        return false;
    }

    public void checkAuthorization( Principal subjectIdentifier, AuthorizedAction action ) throws AuthorizationException {
        if ( !isAuthorized( subjectIdentifier, action ) ) {
            String msg = "No configured realm(s) authorized subject [" + subjectIdentifier + "] for " +
                "action [" + action + "].";
            throw new UnauthorizedException( msg );
        }
    }
}
