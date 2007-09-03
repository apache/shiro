package org.jsecurity.authz.support;

import org.jsecurity.authz.Permission;

import java.io.Serializable;

/**
 * Simple default/abstract implementation of the core Permission interface.
 *
 * @since 0.1
 * @author Les Hazlewood
 */
public abstract class AbstractPermission implements Permission, Serializable {

    protected String name = null;

    protected AbstractPermission() {
    }

    public AbstractPermission( String name ) {
        setName( name );
    }

    public String getName() {
        return this.name;
    }

    protected void setName( String name ) {
        this.name = name;
    }

    public boolean implies( Permission p ) {

        boolean implies = false;

        if ( p != null && ( getClass().getName().equals( p.getClass().getName() ) ) ) {
            String name = getName();

            if ( name != null ) {
                implies = name.equals( WILDCARD ) || name.contains( p.getName() );
            } else {
                implies = ( p.getName() == null );
            }
        }

        return implies;
    }

    public String toString() {
        return toStringBuffer().toString();
    }

    protected StringBuffer toStringBuffer() {
        StringBuffer sb = new StringBuffer();
        sb.append( "(\"" ).append( getClass().getName() ).append( "\" " );
        sb.append( "\"" ).append( getName() ).append( "\")" );
        return sb;
    }

    public boolean equals( Object o ) {
        if ( o == this ) {
            return true;
        }

        if ( o instanceof AbstractPermission ) {
            AbstractPermission ap = (AbstractPermission)o;
            return ( getClass().getName().equals( ap.getClass().getName() ) ) &&
                   ( getName() != null ? getName().equals( ap.getName() ) : ap.getName() == null );
        }

        return false;
    }

    public int hashCode() {
        int result = getClass().getName().hashCode();
        result = 29 * result + ( getName() != null ? getName().hashCode() : 0 );
        return result;
    }

    @Override
    @SuppressWarnings( { "CloneDoesntDeclareCloneNotSupportedException" } )
    public Object clone() {
        AbstractPermission ap;
        try {
            ap = (AbstractPermission)super.clone();
        } catch ( CloneNotSupportedException e ) {
            String msg = "Unable to clone AbstractTargetedPermission of type [" +
                    getClass().getName() + "].  Check implementation (this should never " +
                    "happen).";
            throw new InternalError( msg );
        }
        ap.name = getName();
        return ap;
    }
}
