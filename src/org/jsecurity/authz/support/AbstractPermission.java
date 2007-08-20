package org.jsecurity.authz.support;

import org.jsecurity.authz.Permission;

import java.io.Serializable;

/**
 * TODO class JavaDoc
 *
 * @author Les Hazlewood
 */
public abstract class AbstractPermission implements Permission, Serializable {

    /**
     * Used to specify all possible names when used in the {@link #getName() name} field.
     */
    public static final String WILDCARD = "*";
    public static final char WILDCARD_CHAR = '*';
    
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

    /**
     * Returns a string describing this Permission.  The convention is to
     * specify the class name, the permission name, and the actions in
     * the following format: '("ClassName" "name" "actions")'.
     * <p/>
     * <b>N.B.</b> Subclasses should not override this method.  Instead, they should override the
     * {@link #toStringBuffer()} implementation which is more efficient.
     */
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
