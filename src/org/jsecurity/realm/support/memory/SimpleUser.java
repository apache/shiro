package org.jsecurity.realm.support.memory;

import org.jsecurity.authz.Permission;

import java.io.Serializable;
import java.util.HashSet;
import java.util.Set;

/**
 * A simple representation of a user that encapsulates the user's name, password, and security roles.  This object
 * can be used internally by Realms to maintain cached authentication and authorization information.  This class
 * also implements several userful methods that can be used by Realms to check authorization based on roles
 * and permissions.
 *
 * @since 0.2
 * @author Les Hazlewood
 */
public class SimpleUser implements Serializable {

    protected String username = null;
    protected String password = null;

    protected Set<SimpleRole> roles = null;

    public SimpleUser() {
    }

    public SimpleUser( String username, String password ) {
        setUsername( username );
        setPassword( password );
    }

    public SimpleUser( String username, String password, Set<SimpleRole> roles ) {
        this( username, password );
        setRoles( roles );
    }

    public String getUsername() {
        return username;
    }

    public void setUsername( String username ) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword( String password ) {
        this.password = password;
    }

    public Set<SimpleRole> getRoles() {
        return roles;
    }

    public void setRoles( Set<SimpleRole> roles ) {
        this.roles = roles;
    }

    public Set<Permission> getPermissions() {
        Set<Permission> permissions = new HashSet<Permission>();
        for( SimpleRole role : roles ) {
            permissions.addAll( role.getPermissions() );
        }
        return permissions;
    }

    public Set<String> getRolenames() {
        Set<String> rolenames = new HashSet<String>();
        for( SimpleRole role : roles ) {
            rolenames.add( role.getName() );
        }
        return rolenames;
    }

    public void add( SimpleRole role ) {
        Set<SimpleRole> roles = getRoles();
        if ( roles == null ) {
            roles = new HashSet<SimpleRole>();
            setRoles( roles );
        }
        roles.add( role );
    }

    public boolean hasRole( String rolename ) {
        Set<SimpleRole> roles = getRoles();
        if ( roles != null && !roles.isEmpty() ) {
            for( SimpleRole role : roles ) {
                if ( role.getName().equals( rolename ) ) {
                    return true;
                }
            }
        }
        return false;
    }

    public boolean isPermitted( Permission permission ) {
        Set<SimpleRole> roles = getRoles();
        if ( roles != null && !roles.isEmpty() ) {
            for( SimpleRole role : roles ) {
                if ( role.isPermitted( permission ) ) {
                    return true;
                }
            }
        }
        return false;
    }

    public int hashCode() {
        return ( getUsername() != null ? getUsername().hashCode() : 0 );
    }

    public boolean equals( Object o ) {
        if ( o == this ) {
            return true;
        }
        if ( o instanceof SimpleUser ) {
            SimpleUser sa = (SimpleUser)o;
            //usernames should be unique across the application, so only check this for equality:
            return ( getUsername() != null ? getUsername().equals( sa.getUsername() ) : sa.getUsername() == null );
        }
        return false;
    }

    public String toString() {
        return getUsername();
    }

}
