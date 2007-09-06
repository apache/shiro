package org.jsecurity.realm.support.memory;

import org.jsecurity.authz.Permission;

import java.io.Serializable;
import java.util.HashSet;
import java.util.Set;

/**
 * TODO class JavaDoc
 *
 * @author Les Hazlewood
 */
public class SimpleRole implements Serializable {

    protected String name = null;
    protected Set<Permission> permissions;

    public SimpleRole(){}

    public SimpleRole( String name ) {
        setName( name );
    }

    public SimpleRole( String name, Set<Permission> permissions ) {
        setName( name );
        setPermissions( permissions );
    }

    public String getName() {
        return name;
    }

    public void setName( String name ) {
        this.name = name;
    }

    public Set<Permission> getPermissions() {
        return permissions;
    }

    public void setPermissions( Set<Permission> permissions ) {
        this.permissions = permissions;
    }

    public void add( Permission permission ) {
        Set<Permission> permissions = getPermissions();
        if ( permissions == null ) {
            permissions = new HashSet<Permission>();
            setPermissions( permissions );
        }
        permissions.add( permission );
    }

    public boolean isPermitted( Permission p ) {
        Set<Permission> perms = getPermissions();
        if ( perms != null && !perms.isEmpty() ) {
            for( Permission perm : perms ) {
                if ( perm.implies( p ) ) {
                    return true;
                }
            }
        }
        return false;
    }

    public int hashCode() {
        return ( getName() != null ? getName().hashCode() : 0 );
    }

    public boolean equals( Object o ) {
        if ( o == this ) {
            return true;
        }
        if ( o instanceof SimpleRole ) {
            SimpleRole sr = (SimpleRole)o;
            //only check name, since role names should be unique across an entire application:
            return ( getName() != null ? getName().equals( sr.getName() ) : sr.getName() == null );
        }
        return false;
    }

    public String toString() {
        return getName();
    }
}
