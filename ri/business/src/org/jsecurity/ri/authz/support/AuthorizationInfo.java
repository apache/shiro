package org.jsecurity.ri.authz.support;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.authz.AuthorizationContext;
import org.jsecurity.authz.AuthorizationException;

import java.security.Permission;
import java.util.Collection;
import java.util.List;

/**
 * A value object holding a set of roles and permissions that helps make it easier to
 * implement the {@link org.jsecurity.ri.authz.Realm} interface when all of the authorization information is
 * static.  Used internally by several realm implementeations.
 *
 * @since 0.1
 * @author Jeremy Haile
 */
public class AuthorizationInfo {

    /*--------------------------------------------
    |             C O N S T A N T S             |
    ============================================*/

    /*--------------------------------------------
    |    I N S T A N C E   V A R I A B L E S    |
    ============================================*/
    /**
     * Commons-logger.
     */
    protected transient final Log logger = LogFactory.getLog( getClass() );

    /**
     * The roles that apply to this authorization context.
     */
    protected Collection<String> roles;

    /**
     * The permissions that apply to this authorization context.
     */
    protected Collection<Permission> permissions;


    /*--------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*/
    /**
     * Constructs a new instance of the authorization info with multiple principals.
     * @param roles the roles associated with this auth info.
     * @param permissions the permissions associated with this authorization info.
     */
    public AuthorizationInfo(Collection<String> roles, Collection<Permission> permissions) {
        this.roles = roles;
        this.permissions = permissions;
    }

    /*--------------------------------------------
    |               M E T H O D S               |
    ============================================*/

    /**
     * @see org.jsecurity.authz.AuthorizationContext#hasRole(String)
     */
    public boolean hasRole(String roleIdentifier) {
        return roles.contains( roleIdentifier );
    }

    /**
     * @see org.jsecurity.authz.AuthorizationContext#hasRoles(java.util.List<java.io.Serializable>)
     */
    public boolean[] hasRoles(List<String> roleIdentifiers) {
        boolean[] hasRoles = new boolean[roleIdentifiers.size()];

        for( int i = 0; i < roleIdentifiers.size(); i++ ) {
            hasRoles[i] = hasRole( roleIdentifiers.get(i) );
        }

        return hasRoles;
    }


    /**
     * @see org.jsecurity.authz.AuthorizationContext#hasAllRoles(java.util.Collection<java.io.Serializable>)
     */
    public boolean hasAllRoles(Collection<String> roleIdentifiers) {
        for( String roleIdentifier : roleIdentifiers ) {
            if( !hasRole( roleIdentifier ) ) {
                return false;
            }
        }
        return true;
    }


    /**
     * @see AuthorizationContext#implies(java.security.Permission)
     */
    public boolean implies(Permission permission) {

        if( permissions != null ) {
            for( Permission perm : permissions ) {
                if( perm.implies( permission ) ) {
                    return true;
                }
            }
        }

        if( logger.isDebugEnabled() ) {
            logger.debug( "Context does not imply permission [" + permission + "]" );

            if( permissions == null ) {
                logger.debug( "No permissions are associated with this context.  Permissions are null." );
            } else {
                logger.debug( "Implies permissions:" );
                for( Permission perm : permissions ) {
                    logger.debug( "\t" + perm );
                }
            }
        }

        return false;
    }

    /**
     * @see AuthorizationContext#implies(java.util.List<java.security.Permission>)
     */
    public boolean[] implies(List<Permission> permissions) {
        boolean[] implies = new boolean[permissions.size()];

        for( int i = 0; i < permissions.size(); i++ ) {
            implies[i] = implies( permissions.get(i) );
        }
        return implies;
    }


    /**
     * @see AuthorizationContext#impliesAll(java.util.Collection<java.security.Permission>)
     */
    public boolean impliesAll(Collection<Permission> permissions) {

        if( permissions != null ) {
            for( Permission perm : permissions ) {
                if( !implies(perm) ) {
                    return false;
                }
            }
        }
        return true;
    }


    /**
     * @see AuthorizationContext#checkPermission(java.security.Permission)
     */
    public void checkPermission(Permission permission) throws AuthorizationException {
        if( !implies( permission ) ) {
            throw new AuthorizationException( "User does " +
                                              "not have permission [" + permission.toString() + "]" );
        }
    }


    /**
     * @see org.jsecurity.authz.AuthorizationContext#checkPermissions(java.util.Collection<java.security.Permission>)
     */
    public void checkPermissions(Collection<Permission> permissions) throws AuthorizationException {

        if( permissions != null ) {
            for( Permission permission : permissions ) {
                if( !implies( permission ) ) {
                   throw new AuthorizationException( "User does " +
                                                     "not have permission [" + permission.toString() + "]" );
                }
            }
        }
    }

    public String toString() {
        StringBuffer sb = new StringBuffer();

        sb.append( "Roles [" );
        if( roles != null ) {
            for( String role : roles ) {
                sb.append( role ).append( " " );
            }
        }
        sb.append( "] " );

        sb.append( "Permissions [" );
        if( permissions != null ) {
            for( Permission permission : permissions ) {
                sb.append( permission ).append( " " );
            }
        }
        sb.append( "] " );

        return sb.toString();
    }

}