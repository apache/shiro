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
package org.jsecurity.authz;

import java.io.Serializable;
import java.security.Permission;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * A InstancePermission represents an action or actions that might be performed on a single
 * identifiable instance or multiple instances of a particular object type.
 *
 * <p>The target of this Permission is an instance's <tt>identifier</tt>, or the
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
 * system id <tt>aUser.getId()</tt>.  Such a permission would usually be associated with the user
 * account with the same Id, so the user could edit their own account information.
 *
 * <p>Finally, this instance:
 * <pre>new com.domain.UserPermission( WILDCARD, WILDCARD );</pre>
 *
 * means that the <tt>role</tt> assigned that permission would have the
 * ability to do anything (create, read, update, delete) <em>any</em> user account.  Such a
 * permission would generally be assigned to an administrative role.
 *
 * @since 0.1
 * @author Les Hazlewood
 */
public abstract class InstancePermission extends Permission implements Serializable, Cloneable {

    /**
     * Used to specify all instances of an object type when used in the {@link #getName() name/target}
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


    /**
     * Canonically ordered actions string for an instance of this class.
     */
    private String actions;

    /**
     * The actions of an instance of this class, which is a
     * perfect subset of the <code>getPossibleActions</code> Set. It is constructed
     * by this class during the setActions method
     */
    private Set<String> actionsSet;

    /**
     * Constructs an instance with <em>all</em> actions (via the {@link #WILDCARD WILDCARD}
     * constant).
     * @param targetName name of the permission target.
     */
    protected InstancePermission( String targetName ) {
        this( targetName, WILDCARD );
    }

    /**
     * Constructs a new InstancePermission associated with an entity instance with the given
     * identifier with <em>all</em> actions (via the {@link #WILDCARD WILDCARD}
     * constant).
     * @param identifier the instance identifier
     */
    protected InstancePermission( Serializable identifier ) {
        this( identifier.toString() );
    }

    /**
     * Creates a new InstancePermission object with the specified target and
     * instance-specific actions.
     *
     * <p>The actions
     * String is a comma-delimited list of instance-specific actions.  That is,
     * all actions specified must be a perfect subset of those in the
     * {@link #getPossibleActions() possibleActions} Set.  If all actions are to be set, the
     * {@link #WILDCARD wildcard} character may be specified instead of explicitly listing each
     * action explicitly.
     *
     * @param targetName - the logical name (unique identifier) of the permission's target instance
     * @param actions - a comma-delimited string of actions understood
     *        by this class, or the wildcard string (&quot;*&quot;) if setting all actions.
     * @throws UnknownPermissionActionException if an action in the
     *         <code>actions</code> string is unknown to the class.
     */
    protected InstancePermission( String targetName, String actions ) {
        super( targetName );
        setActions(actions);
    }

    protected InstancePermission( Serializable identifier, String actions ) {
        this( identifier.toString(), actions );
    }

    /**
     * Sets the {@link #getActions() actions} for this instance.  Once set on this instance,
     * either via this method or via a constructor, they cannot be set again or
     * changed - as per the {@link Permission Permission} JavaDoc, Permissions are intended to be
     * immutable like Strings.  This method is only provided to be JavaBeans compatible.
     * @param actions the actions to set for this instance
     */
    public void setActions( String actions ) {

        if ( actions == null ) {
            String msg = "actions parameter cannot be null";
            throw new NullPointerException( msg );
        }

        if ( actions.contains( WILDCARD ) ) {
            this.actions = WILDCARD;
            this.actionsSet = new HashSet<String>(1);
            this.actionsSet.add( WILDCARD );
            return;
        }

        Set<String> possibleActions = getPossibleActions();
        if ( possibleActions == null || possibleActions.size() <= 0 ) {
            String msg = "Subclass implementation '" + getClass().getName() + " did not " +
                         "return a valid possibleActions Set from the getPossibleActions() " +
                         "method.  A non-null and populated Set is required.";
            throw new IllegalStateException( msg );
        }

        Set<String> nonCanonicalActions = new LinkedHashSet<String>();

        String[] actionsArray = DELIMITER_SPLIT_PATTERN.split( actions, 0 );

        for( String s : actionsArray ) {
            if ( !possibleActions.contains( s ) ) {
                String msg = "Action \"" + s + "\" is unknown to class [" +
                             getClass().getName() + "]";
                throw new UnknownPermissionActionException( msg );
            }
            nonCanonicalActions.add( s );
        }


        //Now arrange them in canonical order, as required by the
        //java.security.Permission class:
        Set<String> canonicalActions = new LinkedHashSet<String>();
        for( String s : possibleActions ) {
            if ( nonCanonicalActions.contains( s ) ) {
                canonicalActions.add( s );
            }
        }

        //now, the actions string must be in the same order as well:
        StringBuffer sb = new StringBuffer();
        Iterator<String> i = canonicalActions.iterator();
        while( i.hasNext() ) {
            sb.append( i.next() );
            if ( i.hasNext() ) {
                sb.append( ACTION_DELIMITER_CHAR );
            }
        }
        this.actions = sb.toString();

        this.actionsSet = canonicalActions;
    }


    /**
     * Returns the comma-delimited canonical string representation
     * of this instance's declared actions.
     * @return the canonical string representation of this instance's permission actions.
     */
    public String getActions() {
        return this.actions;
    }


    /**
     * Returns this permission's actions in <em>canonical order</em>
     * @return the set of actions for this permission.
     */
    public Set<String> getActionsSet() {
        return this.actionsSet;
    }


    /**
     * Returns a "canonically ordered" Set of all actions that this permission
     * class understands.  This set is used to verify instantiation of a new permission.
     *
     * <p>That is, when a permission is being instantiated, the actions given to the constructor
     * are verified to be either equivalent to or a proper subset of the values found in this
     * Set.
     *
     * <p>Since this Set never changes for any given InstancePermission subclass, the returned Set
     * should be constructed via a static initializer that will be executed when the class
     * is loaded by the class loader.  This ensures the Set is only constructed once for
     * <em>all</em> instances, increasing overall performance.
     *
     * <p>E.g.:
     *
     * <pre>public class MyPermission extends InstancePermission {
    ...
    private static final LinkedHashSet&lt;String&gt; possibleActions = initPossibleActionsSet();
    ...
    private static LinkedHashSet&lt;String&gt; initPossibleActionsSet() {
        LinkedHashSet&lt;String&gt; possibleActions = new LinkedHashSet&lt;String&gt;();
        //make sure the actions are added in canonical order:
        possibleActions.add( "action1" );
        possibleActions.add( "action2" );
        ...
        return possibleActions;
    }
    ...
}</pre>
     * @return the set of actions that are supported by this permission type.
     */
    public abstract Set<String> getPossibleActions();


    public boolean implies( Permission p ) {

        boolean implies = false;

        if ( p != null && (p instanceof InstancePermission ) ) {
            InstancePermission ep = (InstancePermission)p;

            String name = getName();
            if ( name != null ) {
                implies = name.equals( WILDCARD ) || name.equals( ep.getName() );
            } else {
                implies = (ep.getName() == null);
            }

            if ( implies ) {
                if ( !getActions().equals( WILDCARD ) ) {
                    implies = getActionsSet().containsAll( ep.getActionsSet() );
                }
            }
        }

        return implies;
    }

    /**
     * Returns a string describing this Permission.  The convention is to
     * specify the class name, the permission name, and the actions in
     * the following format: '("ClassName" "name" "actions")'.
     *
     * <b>N.B.</b> Subclasses should not override this method.  Instead, they should override the
     * {@link #toStringBuffer()} implementation which is more efficient.
     */
    public String toString() {
        return toStringBuffer().toString();
    }

    protected StringBuffer toStringBuffer() {
        StringBuffer sb = new StringBuffer();
        sb.append( "(\"" ).append( getClass().getName() ).append("\" ");
        sb.append( "\"" ).append( getName() ).append("\" ");
        sb.append( "\"" ).append( getActions() ).append( "\")" );
        return sb;
    }

    public boolean equals( Object o ) {
        if ( o == this ) {
            return true;
        }

        if ( o instanceof InstancePermission ) {
            InstancePermission ep = (InstancePermission)o;
            return ( getClass().getName().equals( ep.getClass().getName() ) ) &&
                   ( getName() != null ? getName().equals(ep.getName()) : ep.getName() == null ) &&
                   ( this.actions != null ? this.actions.equals( ep.actions ) : ep.actions == null );
        }

        return false;
    }

    public int hashCode() {
        int result = getClass().getName().hashCode();
        result = 29 * result + ( getName() != null ? getName().hashCode() : 0 );
        result = 29 * result + ( this.actions != null ? this.actions.hashCode() : 0 );
        return result;
    }

    @Override
    @SuppressWarnings({"CloneDoesntDeclareCloneNotSupportedException"})
    public Object clone() {
        InstancePermission ip;
        try {
            ip = (InstancePermission)super.clone();
        } catch ( CloneNotSupportedException e ) {
            String msg = "Unable to clone InstancePermission of type [" +
                         getClass().getName() + "].  Check implementation (this should never " +
                         "happen).";
            throw new InternalError( msg );
        }
        ip.setActions( getActions() );
        return ip;

    }
}
