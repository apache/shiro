package org.jsecurity.context.support;

import org.jsecurity.authc.AuthenticationException;
import org.jsecurity.authc.AuthenticationToken;
import org.jsecurity.authc.Authenticator;
import org.jsecurity.authz.AuthorizationException;
import org.jsecurity.authz.NoSuchPrincipalException;
import org.jsecurity.authz.UnauthorizedException;
import org.jsecurity.context.SecurityContext;
import org.jsecurity.session.Session;
import org.jsecurity.util.ThreadContext;

import java.security.Permission;
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

    private Authenticator authenticator = null;

    public ThreadLocalSecurityContext(){}

    public ThreadLocalSecurityContext( Authenticator authenticator ) {
        setAuthenticator( authenticator );
    }

    public Authenticator getAuthenticator() {
        return authenticator;
    }

    public void setAuthenticator( Authenticator authenticator ) {
        this.authenticator = authenticator;
    }

    public static SecurityContext current() {
        return (SecurityContext)ThreadContext.get( ThreadContext.SECURITY_CONTEXT_KEY );
    }

    public SecurityContext authenticate( AuthenticationToken authenticationToken )
            throws AuthenticationException {
        
        Authenticator authc = getAuthenticator();
        if ( authc != null ) {
            SecurityContext authzCtx = authc.authenticate( authenticationToken );
            ThreadContext.put( ThreadContext.SECURITY_CONTEXT_KEY, authzCtx );
            return this;
        } else {
            String msg = "underlying Authenticator instance is not set.  The " +
                    getClass().getName() + " class only acts as a delegate to an underlying " +
                    "Authenticator that actually performs the authentication process.  This " +
                    "underlying instance has not been set (it is null) and authenication cannot " +
                    "occur.  Please check your configuration and ensure the delegated " +
                    "Authenticator is available to instances of this class, either via " +
                    "a constructor, or by Dependency Injection.";
            throw new AuthenticationException( msg );
        }
    }


    public boolean isAuthenticated() {
        return getSecurityContext() != null;
    }

    public Principal getPrincipal() throws NoSuchPrincipalException {
        SecurityContext authzCtx = getSecurityContext();
        if ( authzCtx != null ) {
            return authzCtx.getPrincipal();
        }
        return null;
    }

    public List<Principal> getAllPrincipals() {
        SecurityContext authzCtx = getSecurityContext();
        if ( authzCtx != null ) {
            return authzCtx.getAllPrincipals();
        }
        return Collections.EMPTY_LIST;
    }

    public Principal getPrincipalByType( Class principalType ) throws NoSuchPrincipalException {
        SecurityContext authzCtx = getSecurityContext();
        if ( authzCtx != null ) {
            return authzCtx.getPrincipalByType( principalType );
        }
        return null;
    }

    public Collection<Principal> getAllPrincipalsByType( Class principalType ) {
        SecurityContext authzCtx = getSecurityContext();
        if ( authzCtx != null ) {
            return authzCtx.getAllPrincipalsByType( principalType );
        }
        return Collections.EMPTY_LIST;
    }

    public boolean hasRole( String roleIdentifier ) {
        SecurityContext authzCtx = getSecurityContext();
        return authzCtx != null && authzCtx.hasRole( roleIdentifier );
    }

    public boolean[] hasRoles( List<String> roleIdentifiers ) {
        SecurityContext authzCtx = getSecurityContext();
        boolean[] hasRoles;

        if ( authzCtx != null ) {
            hasRoles = authzCtx.hasRoles( roleIdentifiers );
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
        SecurityContext authzCtx = getSecurityContext();
        return authzCtx != null && authzCtx.hasAllRoles( roleIdentifiers );
    }

    public boolean implies( Permission permission ) {
        SecurityContext authzCtx = getSecurityContext();
        return authzCtx != null && authzCtx.implies ( permission );
    }

    public boolean[] implies( List<Permission> permissions ) {
        SecurityContext authzCtx = getSecurityContext();
        boolean[] implies;

        if ( authzCtx != null ) {
            implies = authzCtx.implies( permissions );
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
        SecurityContext authzCtx = getSecurityContext();
        return authzCtx != null && authzCtx.impliesAll( permissions );
    }

    public void checkPermission( Permission permission ) throws AuthorizationException {
        SecurityContext authzCtx = getSecurityContext();
        if ( authzCtx != null ) {
            authzCtx.checkPermission( permission );
        } else {
            String msg = "No SecurityContext bound to the current thread - user has not " +
                    "authenticated yet?  Permission check failed.";
            throw new UnauthorizedException( msg );
        }
    }

    public void checkPermissions( Collection<Permission> permissions ) throws AuthorizationException {
        SecurityContext authzCtx = getSecurityContext();
        if ( authzCtx != null ) {
            authzCtx.checkPermissions( permissions );
        } else {
            String msg = "No SecurityContext bound to the current thread - user has not " +
                    "authenticated yet?  Permissions check failed.";
            throw new UnauthorizedException( msg );
        }
    }

    public Session getSession() {
        return (Session) ThreadContext.get( ThreadContext.SESSION_KEY );
    }

    public SecurityContext getSecurityContext() {
        return (SecurityContext) ThreadContext.get( ThreadContext.SECURITY_CONTEXT_KEY );
    }

    public void invalidate() {

        try {
            Session s = getSession();
            if ( s != null ) {
                s.stop();
            }
        } finally {
            ThreadContext.remove( ThreadContext.SESSION_KEY );
            ThreadContext.remove( ThreadContext.SECURITY_CONTEXT_KEY );
        }
    }

}
