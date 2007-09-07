/*
* Copyright (C) 2005-2007 Jeremy Haile, Les Hazlewood
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
package org.jsecurity.realm.support.memory;

import org.jsecurity.authc.AuthenticationException;
import org.jsecurity.authc.AuthenticationInfo;
import org.jsecurity.authc.AuthenticationToken;
import org.jsecurity.authc.UsernamePasswordToken;
import org.jsecurity.authc.support.SimpleAuthenticationInfo;
import org.jsecurity.authz.AuthorizationException;
import org.jsecurity.authz.AuthorizedAction;
import org.jsecurity.authz.Permission;
import org.jsecurity.authz.UnauthorizedException;
import org.jsecurity.cache.Cache;
import org.jsecurity.cache.CacheException;
import org.jsecurity.cache.CacheProvider;
import org.jsecurity.cache.support.HashtableCacheProvider;
import org.jsecurity.realm.support.AuthenticatingRealm;
import org.jsecurity.util.Destroyable;
import org.jsecurity.util.Initializable;
import org.jsecurity.util.UsernamePrincipal;

import java.security.Principal;
import java.util.Collection;
import java.util.List;
import java.util.Set;

/**
 * <p>A simple implementation of the {@link org.jsecurity.realm.Realm} interface that
 * uses a set of configured user accounts to authenticate the user.  Each account entry
 * specifies the username, password, and roles for a user.  Roles can also be mapped
 * to permissions and will be associated with users.</p>
 *
 * <p>See the <tt>applicationContext.xml</tt> in the Spring sample application for an example
 * of configuring a <tt>MemoryRealm</tt></p>
 *
 * @author Jeremy Haile
 * @author Les Hazlewood
 * @since 0.1
 */
public class MemoryRealm extends AuthenticatingRealm implements Initializable, Destroyable {

    /*--------------------------------------------
    |             C O N S T A N T S             |
    ============================================*/

    /*--------------------------------------------
    |    I N S T A N C E   V A R I A B L E S    |
    ============================================*/
    protected Cache userCache = null;
    protected Cache roleCache = null;

    private boolean cacheProviderImplicitlyCreated = true;

    /*--------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*/

    /*--------------------------------------------
    |  A C C E S S O R S / M O D I F I E R S    |
    ============================================*/

    /**
     * Sets the account entries that are used to authenticate users and associate them
     * with roles for this realm.
     *
     * @param accounts the accounts for this realm.
     */
    public void setAccounts( Set<AccountEntry> accounts ) {
        //this.accounts = accounts;
    }


    /*--------------------------------------------
    |               M E T H O D S               |
    ============================================*/
    public void init() {
        CacheProvider provider = getCacheProvider();

        if ( provider == null ) {
            provider = new HashtableCacheProvider();
            setCacheProvider( provider );
            this.cacheProviderImplicitlyCreated = true;
        }
        //if ( accounts != null && !accounts.isEmpty() ) {
            //todo - translate into SimpleUser and SimpleRole objects
        //}

    }

    protected void destroy( Cache cache ) {
        if ( cache != null ) {
            try {
                cache.clear();
            } catch ( Throwable t ) {
                if ( log.isInfoEnabled() ) {
                    log.info( "Unable to cleanly clear cache [" + cache + "].  Ingoring (shutting down)." );
                }
            }
            try {
                cache.destroy();
            } catch ( CacheException e ) {
                if ( log.isInfoEnabled() ) {
                    log.info( "Unable to cleanly destroy cache [" + cache + "].  Ignoring (shutting down)." );
                }
            }

        }
    }

    public void destroy() throws Exception {
        destroy( userCache );
        destroy( roleCache );
        if ( this.cacheProviderImplicitlyCreated ) {
            if ( getCacheProvider() instanceof Destroyable ) {
                try {
                    ((Destroyable)getCacheProvider()).destroy();
                } catch ( Exception e ) {
                    if ( log.isInfoEnabled() ) {
                        log.info( "Unable to cleanly destroy implicitly created CacheProvider.  Ignoring (shutting down)" );
                    }
                }
            }
        }
    }

    protected AuthenticationInfo doGetAuthenticationInfo( AuthenticationToken token ) throws AuthenticationException {
        UsernamePasswordToken upToken = (UsernamePasswordToken)token;

        SimpleUser user = (SimpleUser)userCache.get( upToken.getUsername() );
        if ( user == null ) {
            return null;
        }

        Principal principal = new UsernamePrincipal( user.getUsername() );

        return new SimpleAuthenticationInfo( principal, user.getPassword() );

    }

    protected String getUsername( Principal principal ) {
        if ( principal instanceof UsernamePrincipal ) {
            return ( (UsernamePrincipal)principal ).getUsername();
        } else {
            String msg = "The " + getClass().getName() + " implementation expects all Principal arguments to be " +
                "instances of the [" + UsernamePrincipal.class.getName() + "] class";
            throw new IllegalArgumentException( msg );
        }
    }

    protected SimpleUser getUser( Principal principal ) {
        return (SimpleUser)userCache.get( getUsername( principal ) );
    }

    public boolean hasRole( Principal principal, String roleIdentifier ) {
        SimpleUser user = getUser( principal );
        return ( user != null && user.hasRole( roleIdentifier ) );
    }


    public boolean[] hasRoles( Principal principal, List<String> roleIdentifiers ) {
        boolean[] hasRoles = new boolean[roleIdentifiers.size()];
        for ( int i = 0; i < roleIdentifiers.size(); i++ ) {
            hasRoles[i] = hasRole( principal, roleIdentifiers.get( i ) );
        }
        return hasRoles;
    }

    public boolean hasAllRoles( Principal principal, Collection<String> roleIdentifiers ) {
        for ( String rolename : roleIdentifiers ) {
            if ( !hasRole( principal, rolename ) ) {
                return false;
            }
        }
        return true;
    }

    public boolean isPermitted( Principal principal, Permission permission ) {
        SimpleUser user = getUser( principal );
        return user != null && user.isPermitted( permission );
    }

    public boolean[] isPermitted( Principal principal, List<Permission> permissions ) {
        boolean[] permitted = new boolean[permissions.size()];
        for ( int i = 0; i < permissions.size(); i++ ) {
            permitted[i] = isPermitted( principal, permissions.get( i ) );
        }
        return permitted;
    }

    public boolean isPermittedAll( Principal principal, Collection<Permission> permissions ) {
        for ( Permission perm : permissions ) {
            if ( !isPermitted( principal, perm ) ) {
                return false;
            }
        }
        return true;
    }

    public void checkPermission( Principal principal, Permission permission ) throws AuthorizationException {
        if ( !isPermitted( principal, permission ) ) {
            throw new UnauthorizedException( "User does not have permission [" + permission + "]" );
        }
    }

    public void checkPermissions( Principal principal, Collection<Permission> permissions ) throws AuthorizationException {
        if ( permissions != null ) {
            for ( Permission permission : permissions ) {
                if ( !isPermitted( principal, permission ) ) {
                    throw new UnauthorizedException( "User does not have permission [" + permission + "]" );
                }
            }
        }
    }

    public void checkRole( Principal principal, String role ) throws AuthorizationException {
        if ( !hasRole( principal, role ) ) {
            throw new UnauthorizedException( "User does not have role [" + role + "]" );
        }
    }

    public void checkRoles( Principal principal, Collection<String> roles ) throws AuthorizationException {
        if ( roles != null ) {
            for ( String role : roles ) {
                if ( !hasRole( principal, role ) ) {
                    throw new UnauthorizedException( "User does not have role [" + role + "]" );
                }
            }
        }
    }

    /**
     * Default implementation that always returns false (relies on JSecurity 1.5 annotations instead).
     *
     * @param action the action to check for authorized execution
     * @return whether or not the realm supports AuthorizedActions of the given type.
     */
    public boolean supports( AuthorizedAction action ) {
        return false;
    }

    public boolean isAuthorized( Principal subjectIdentifier, AuthorizedAction action ) {
        return true;
    }

    public void checkAuthorization( Principal subjectIdentifier, AuthorizedAction action ) throws AuthorizationException {
        //does nothing
    }

}