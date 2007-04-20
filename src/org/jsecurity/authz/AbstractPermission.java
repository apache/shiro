package org.jsecurity.authz;

import java.io.Serializable;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * An AbstractPermission represents an action or actions that might be performed on a single
 * identifiable object instance or multiple instances of a particular object type.
 *
 * <p>The target of this Permission is an object's <tt>identifier</tt>, or the
 * {@link #WILDCARD WILDCARD} constant.
 *
 * <p>An instance's <tt>identifier</tt> is obtained in a system-specific manner.  For example,
 * in most database-driven applications, this identifier is usally a primary key value that is
 * obtained from an instance's <tt>getId()</tt> (or similar) method.  
 *
 * <p>The {@link #WILDCARD WILDCARD} constant represents <b>all</b> instances of a particular
 * object type, or if used in the actions field, <b>all</b> possible actions.
 *
 * <p>For example, the following instance:
 *
 * <pre>new com.domain.PrinterPermission( WILDCARD, "print" );</pre>
 *
 * means that any <tt>role</tt> assigned that permission would have
 * the ability to "print" documents to any printer available to a system.  Such a permission
 * could be assigned to all users in a system where printers are not considered
 * restricted resources.  Then any user may print to any printer they wish.
 *
 * <p>This instance:
 * <pre>new com.domain.UserPermission( aUser.getId(), "read, write" );</pre>
 *
 * means that any <tt>role</tt> assigned that permission would have
 * the ability to "read" (view) and "write" (change) the user account data for the user with the
 * system id <tt>aUser.getId()</tt>.  Such a permission might be associated with the user
 * account with the same Id, so the user could edit their own account information.
 *
 * <p>Finally, this instance:
 * <pre>new com.domain.UserPermission( WILDCARD, WILDCARD );</pre>
 *
 * means that the <tt>role</tt> assigned that permission would have the
 * ability to do anything (create, read, update, delete) <em>any</em> user account.  Such a
 * permission would generally be assigned to an administrative role.
 *
 * @since 0.2
 * @author Les Hazlewood
 */
public abstract class AbstractPermission implements Permission, Serializable {

    private Serializable targetId = null;

    /**
     * Used to specify all instances of an object type when used in the {@link #getTargetId() targetId}
     * field or all permission actions when used in the {@link #getActions actions} field.
     */
    public static final String WILDCARD = "*";
    public static final char WILDCARD_CHAR = '*';

    /**
     * Used to delimit mutli-value action strings.
     */
    public static final String ACTION_DELIMITER = ",";
    public static final char ACTION_DELIMITER_CHAR = ',';

    private static final Pattern DELIMITER_SPLIT_PATTERN = Pattern.compile( "[,; ][ ]*" );

    private static final Set<String> WILDCARD_SET = initWildcardSet();


    private static Set<String> initWildcardSet() {
        Set<String> set = new LinkedHashSet<String>( 1 );
        set.add( WILDCARD );
        return set;
    }

    /**
     * The actions of an instance of this class, which is a
     * perfect subset of the <code>getPossibleActions</code> Set. It is constructed
     * by this class during the setActions method
     */
    private Set<String> actions = null;
    private String actionsString = null; //cached version of the actions set in canonical form

    public AbstractPermission() {
        this( WILDCARD, WILDCARD_SET );
    }

    public AbstractPermission( Serializable targetId, Set<String> actions ) {
        setTargetId( targetId );
        setActions( actions );
    }

    public AbstractPermission( Serializable targetId, String delimited ) {
        setTargetId( targetId );
        setActions( fromActionsString( delimited ) );
    }

    protected String toCommaDelimited( Set<String> actions ) {
        String actionsString = null;
        if ( actions != null ) {
            StringBuffer buffer = new StringBuffer();
            Iterator<String> i = actions.iterator();
            while ( i.hasNext() ) {
                buffer.append( i.next() );
                if ( i.hasNext() ) {
                    buffer.append( ACTION_DELIMITER_CHAR );
                }
            }
            actionsString = buffer.toString();
        }
        return actionsString;
    }

    protected Set<String> toSet( String commaDelimited ) {
        if ( commaDelimited == null || commaDelimited.equals( "" ) ) {
            String msg = "actions string parameter cannot be null";
            throw new IllegalArgumentException( msg );
        }

        String[] actionsArray = DELIMITER_SPLIT_PATTERN.split( commaDelimited, 0 );

        Set<String> set = new LinkedHashSet<String>( actionsArray.length );
        for ( String s : actionsArray ) {
            set.add( s );
        }
        return set;
    }

    protected Set<String> canonicalize( Set<String> original ) {
        if ( original == null || original.isEmpty() ) {
            String msg = "argument cannot be null or empty.";
            throw new IllegalArgumentException( msg );
        }

        Set<String> possibleActions = getPossibleActions();
        if ( possibleActions == null || possibleActions.isEmpty() ) {
            String msg = "Subclass implementation '" + getClass().getName() + " did not " +
                    "return a valid possibleActions Set from the getPossibleActions() " +
                    "method.  A non-null and populated Set is required.";
            throw new IllegalStateException( msg );
        }

        //ensure the actions in the set are those understood by this class:
        for ( String s : original ) {
            if ( !possibleActions.contains( s ) ) {
                String msg = "Action \"" + s + "\" is unknown to class [" + getClass().getName() + "]";
                throw new UnknownPermissionActionException( msg );
            }
        }

        Set<String> canonical = new LinkedHashSet<String>( original.size() );

        //Now arrange them in canonical order
        for ( String s : possibleActions ) {
            if ( original.contains( s ) ) {
                canonical.add( s );
            }
        }

        return canonical;
    }

    protected Set<String> fromActionsString( String delimited ) {
        return canonicalize( toSet( delimited ) );
    }

    public Serializable getTargetId() {
        return targetId;
    }


    protected void setTargetId( Serializable targetId ) {
        this.targetId = targetId;
    }

    /**
     * Default implementation simply returns <tt>getTargetId().toString()</tt> if getTargetId() is non-null, otherwise
     * it returns <tt>null</tt>.  Can be overridden by subclasses.
     *
     * @return <tt>getTargetId().toString()</tt> if getTargetId() returns non-null, otherwise returns <tt>null</tt>.
     *         Can be overridden by subclasses.
     */
    public String getTargetName() {
        Serializable targetId = getTargetId();
        if ( targetId != null ) {
            return targetId.toString();
        }
        return null;
    }

    /**
     * @see org.jsecurity.authz.Permission#getActions
     */
    public Set<String> getActions() {
        return this.actions;
    }


    protected void setActions( Set<String> actions ) {
        this.actions = canonicalize( actions );
        this.actionsString = toCommaDelimited( this.actions );
    }

    /**
     * Sets the {@link #getActions() actions} for this instance.  Once set on this instance,
     * either via this method or via a constructor, they cannot be set again or
     * changed - Permissions are intended to be immutable like Strings.
     *
     * @param actions the actions to set for this instance
     */
    protected void setActionsString( String actions ) {
        this.actions = fromActionsString( actions );
        this.actionsString = toCommaDelimited( this.actions );
    }


    /**
     * Returns the comma-delimited canonical string representation
     * of this instance's declared actions.
     *
     * @return the canonical string representation of this instance's permission actions.
     */
    public String getActionsString() {
        return this.actionsString;
    }


    /**
     * Returns a "canonically ordered" Set of all actions that this permission
     * class understands.  This set is used to verify instantiation of a new permission.
     * <p/>
     * <p>That is, when a permission is being instantiated, the actions given to the constructor
     * are verified to be either equivalent to or a proper subset of the values found in this
     * Set.
     * <p/>
     * <p>Since this Set never changes for any given AbstractPermission subclass, the returned Set
     * should be constructed via a static initializer that will be executed when the class
     * is loaded by the class loader.  This ensures the Set is only constructed once for
     * <em>all</em> instances, better for performance.
     * <p/>
     * <p>E.g.:
     * <p/>
     * <pre>public class MyPermission extends AbstractPermission {
     * ...
     * private static final LinkedHashSet&lt;String&gt; possibleActions = initPossibleActionsSet();
     * ...
     * private static LinkedHashSet&lt;String&gt; initPossibleActionsSet() {
     * LinkedHashSet&lt;String&gt; possibleActions = new LinkedHashSet&lt;String&gt;();
     * //make sure the actions are added in canonical order:
     * possibleActions.add( "action1" );
     * possibleActions.add( "action2" );
     * ...
     * return possibleActions;
     * }
     * ...
     * }</pre>
     *
     * @return the set of actions that are supported by this permission type.
     */
    public abstract Set<String> getPossibleActions();


    public boolean implies( Permission p ) {

        boolean implies = false;

        if ( p != null && ( p instanceof AbstractPermission ) ) {
            AbstractPermission ap = (AbstractPermission)p;

            Serializable targetId = getTargetId();

            if ( targetId != null ) {
                implies = targetId.equals( WILDCARD ) || targetId.equals( ap.getTargetId() );
            } else {
                implies = ( ap.getTargetId() == null );
            }

            if ( implies ) {
                if ( !getActions().contains( WILDCARD ) ) {
                    implies = getActions().containsAll( ap.getActions() );
                }
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
        sb.append( "\"" ).append( getTargetId() ).append( "\" " );
        sb.append( "\"" ).append( getActionsString() ).append( "\")" );
        return sb;
    }

    public boolean equals( Object o ) {
        if ( o == this ) {
            return true;
        }

        if ( o instanceof AbstractPermission ) {
            AbstractPermission ap = (AbstractPermission)o;
            return ( getClass().getName().equals( ap.getClass().getName() ) ) &&
                    ( getTargetId() != null ? getTargetId().equals( ap.getTargetId() ) : ap.getTargetId() == null ) &&
                    ( getActionsString() != null ? getActionsString().equals( ap.getActionsString() ) : ap.getActionsString() == null );
        }

        return false;
    }

    public int hashCode() {
        int result = getClass().getName().hashCode();
        result = 29 * result + ( getTargetId() != null ? getTargetId().hashCode() : 0 );
        result = 29 * result + ( getActionsString() != null ? getActionsString().hashCode() : 0 );
        return result;
    }

    @Override
    @SuppressWarnings( { "CloneDoesntDeclareCloneNotSupportedException" } )
    public Object clone() {
        AbstractPermission ap;
        try {
            ap = (AbstractPermission)super.clone();
        } catch ( CloneNotSupportedException e ) {
            String msg = "Unable to clone AbstractPermission of type [" +
                    getClass().getName() + "].  Check implementation (this should never " +
                    "happen).";
            throw new InternalError( msg );
        }
        ap.setActionsString( getActionsString() );
        return ap;
    }
}
