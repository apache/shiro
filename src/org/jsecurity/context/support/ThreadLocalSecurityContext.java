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
 * @author Les Hazlewood
 * @since 0.1
 */
@SuppressWarnings( {"unchecked"} )
public class ThreadLocalSecurityContext implements SecurityContext {

    public ThreadLocalSecurityContext(){}

    public static SecurityContext current() {
        return (SecurityContext)ThreadContext.get( ThreadContext.SECURITY_CONTEXT_KEY );
    }

    public boolean isAuthenticated() {
        return getSecurityContext() != null;
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
        return (SecurityContext) ThreadContext.get( ThreadContext.SECURITY_CONTEXT_KEY );
    }

    public Session getSession() {
        return getSecurityContext().getSession();
    }

    public Session getSession( boolean create ) {
        return getSecurityContext().getSession( create );
    }

    public void invalidate() {
        getSecurityContext().invalidate();
    }

}
