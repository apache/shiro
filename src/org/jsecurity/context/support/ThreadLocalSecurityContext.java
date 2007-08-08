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
package org.jsecurity.context.support;

import org.jsecurity.authz.AuthorizationException;
import org.jsecurity.authz.NoSuchPrincipalException;
import org.jsecurity.authz.Permission;
import org.jsecurity.authz.UnauthorizedException;
import org.jsecurity.context.SecurityContext;
import org.jsecurity.session.Session;
import org.jsecurity.util.ThreadContext;

import java.security.Principal;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

/**
 * Retrieves all security context data from the currently executing thread (via the {@link ThreadContext}).  This
 * implementation is most widely used in multi-threaded server environments such as EJB and Servlet containers.
 *
 * @since 0.1
 * @author Les Hazlewood
 */
@SuppressWarnings( {"unchecked"} )
public class ThreadLocalSecurityContext implements SecurityContext {

    public ThreadLocalSecurityContext(){}

    public boolean isAuthenticated() {
        SecurityContext sc = getSecurityContext();
        return sc != null && sc.isAuthenticated();
    }

    public Principal getPrincipal() throws NoSuchPrincipalException {
        SecurityContext secCtx = getSecurityContext();
        return ( secCtx != null ? secCtx.getPrincipal() : null );
    }

    public List<Principal> getAllPrincipals() {
        SecurityContext secCtx = getSecurityContext();
        return ( secCtx != null ? secCtx.getAllPrincipals() : Collections.EMPTY_LIST );
    }

    public Principal getPrincipalByType( Class principalType ) throws NoSuchPrincipalException {
        SecurityContext secCtx = getSecurityContext();
        return ( secCtx != null ? secCtx.getPrincipalByType( principalType ) : null );
    }

    public Collection<Principal> getAllPrincipalsByType( Class principalType ) {
        SecurityContext secCtx = getSecurityContext();
        if ( secCtx != null ) {
            return secCtx.getAllPrincipalsByType( principalType );
        }
        return Collections.EMPTY_LIST;
    }

    public boolean hasRole( String roleIdentifier ) {
        SecurityContext secCtx = getSecurityContext();
        return secCtx != null && secCtx.hasRole( roleIdentifier );
    }

    public boolean[] hasRoles( List<String> roleIdentifiers ) {
        SecurityContext secCtx = getSecurityContext();
        boolean[] hasRoles;

        if ( secCtx != null ) {
            hasRoles = secCtx.hasRoles( roleIdentifiers );
        } else {
            if ( roleIdentifiers != null ) {
                hasRoles = new boolean[roleIdentifiers.size()];
            } else {
                hasRoles = new boolean[0];
            }
        }

        return hasRoles;
    }

    public boolean hasAllRoles( Collection<String> roleIdentifiers ) {
        SecurityContext secCtx = getSecurityContext();
        return secCtx != null && secCtx.hasAllRoles( roleIdentifiers );
    }

    public boolean implies( Permission permission ) {
        SecurityContext secCtx = getSecurityContext();
        return secCtx != null && secCtx.implies( permission );
    }

    public boolean[] implies( List<Permission> permissions ) {
        SecurityContext secCtx = getSecurityContext();
        boolean[] implies;

        if ( secCtx != null ) {
            implies = secCtx.implies( permissions );
        } else {
            if ( permissions != null ) {
                implies = new boolean[permissions.size()];
            } else {
                implies = new boolean[0];
            }
        }

        return implies;
    }

    public boolean impliesAll( Collection<Permission> permissions ) {
        SecurityContext secCtx = getSecurityContext();
        return secCtx != null && secCtx.impliesAll( permissions );
    }

    public void checkPermission( Permission permission ) throws AuthorizationException {
        SecurityContext secCtx = getSecurityContext();
        if ( secCtx != null ) {
            secCtx.checkPermission( permission );
        } else {
            handleNoSecurityContextCheck();
        }
    }

    public void checkPermissions( Collection<Permission> permissions ) throws AuthorizationException {
        SecurityContext secCtx = getSecurityContext();
        if ( secCtx != null ) {
            secCtx.checkPermissions( permissions );
        } else {
            handleNoSecurityContextCheck();
        }
    }

    public void checkRole(String role) throws AuthorizationException {
        SecurityContext secCtx = getSecurityContext();
        if ( secCtx != null ) {
            secCtx.checkRole( role );
        } else {
            handleNoSecurityContextCheck();
        }
    }

    public void checkRoles(Collection<String> roles) throws AuthorizationException {
        SecurityContext secCtx = getSecurityContext();
        if ( secCtx != null ) {
            secCtx.checkRoles( roles );
        } else {
            handleNoSecurityContextCheck();
        }
    }

    protected void handleNoSecurityContextCheck() {
        String msg = "No SecurityContext bound to the current thread: unable to perform authorization check. " +
                "Defaulting to a more secure disallow policy - authorization check failed.";
        throw new UnauthorizedException( msg );
    }

    protected SecurityContext getSecurityContext() {
        return ThreadContext.getSecurityContext();
    }

    public Session getSession() {
        return getSecurityContext().getSession();
    }

    public Session getSession( boolean create ) {
        return getSecurityContext().getSession( create );
    }

    public void invalidate() {
        try {
            getSecurityContext().invalidate();
        } finally {
            ThreadContext.unbindSession();
            ThreadContext.unbindSecurityContext();
        }
    }

}
