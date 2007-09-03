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

/**
 * A Permission represents the ability to perform an action or access to a resource.  A Permission is the most
 * granular, i.e. atomic, unit in a system's security policy and is the cornerstone upon which security models are
 * built.
 *
 * <p>It is important to understand a Permission instance only represents behavior or access - it does not grant it.
 * Granting access to an application behavior or a particular resource is done by the application's security
 * configuration, typically by assigning Permissions to users, roles and/or groups.
 *
 * <p>Most typical systems are what the JSecurity team calls <em>role-based</em> in nature, where a role represents
 * common behavior for certain user types.  For example, a system might have an <em>Aministrator</em> role, a
 * <em>User</em> or <em>Guest</em> roles, etc.  But roles by themselves aren't very useful.  What matters is what
 * <em>permissions</em> are assigned to these roles.  In fact, under this description a role can be simply considered as
 * just a named collection of Permissions.  Granting permissions to users then becomes a simple
 * exercise of associating users to permissions in some way.
 *
 * <p>Most applications do this by associating a role with permissions (i.e. a role 'has a' collection of Permissions)
 * and then associate the user with roles (i.e. a user 'has a' collection of roles) so that by transitive association,
 * the user 'has' the permissions in their roles.  There are numerous variations on this theme (permissions
 * assigned directly to users, or assigned to groups, and users added to groups and these groups in turn have roles,
 * etc, etc).
 *
 * <p>A benefit to JSecurity is that, although it assumes most systems are based on these types of Permissioning
 * schemes, it does not require a system to model their security data this way - all Permission checks are relegated to
 * {@link org.jsecurity.realm.Realm} implementations, and only those implementatons really determine how a user
 * 'has' a permission or not.  The realm could use the semantics described here, or it could utilize some other
 * mechanism entirely - it is always up to the application.
 *
 * @since 0.2
 * @author Les Hazlewood
 */
public interface Permission {

    public static final String WILDCARD = "*";
    public static final char WILDCARD_CHAR = '*';

    /**
     * Returns the 'name' of this permission, typically whatever value that best represents behavior or access to a
     * resource.  If the value returned is the {@link #WILDCARD WILDCARD} constant, it means <b>all</b> possible name
     * values for the <tt>Permission</tt> type.
     *
     * <p>Somewhat abstract, the 'name' of a standard permission can mean whatever
     * the application wishes it to mean.  In many systems it would be something like 'createUsers' or
     * 'userSearch', or anything else the application feels is meaningful.
     *
     * <p>The {@link #WILDCARD WILDCARD} constant means it would <em>{@link #implies(Permission) imply}</em> all other
     * Permission <tt>name</tt>s of the same Permission type.  In other words, the following must always be true:
     *
     * <p><code><pre>Permission wildcardPerm = new com.domain.SimpleNamedermission( WILDCARD );
Permission specificPerm = new com.domain.SimpleNamedPermission( "anyValue" );
wildcardPerm.implies( specificPerm ) === true</pre></code>
     *
     * @return the 'name' of the permission, where the name value usually represents some named behavior or resource
     * access.
     */
    String getName();

    /**
     * Returns <tt>true</tt> if this current instance <em>implies</em> all the functionality and/or resource access
     * described by the specified <tt>Permission</tt> argument, <tt>false</tt> otherwise.
     *
     * <p>That is, this current instance must be exactly equal to or a <em>superset</em> of the functionalty
     * and/or resource access described by the given <tt>Permission</tt> argument.  Yet another way of saying this
     * would be:
     *
     * <p>If &quot;permission1 implies permission2&quot;, then any subject/user granted <tt>permission1</tt> would also
     * have the ability defined by <tt>permission2</tt>.
     *
     * @param p the permission to check for behavior/functionality comparison.
     * @return <tt>true</tt> if this current instance <em>implies</em> all the functionality and/or resource access
     * described by the specified <tt>Permission</tt> argument, <tt>false</tt> otherwise.
     */
    boolean implies( Permission p );

    /**
     * Returns a string describing this Permission.  The convention is to
     * specify the class name and permission name in the the following format: <tt>("ClassName" "name")</tt>.
     * @return the String representation of this <tt>Permission</tt> instance, preferably prescribing to this JavaDoc's
     * recommended format.
     */
    String toString();

    /**
     * Returns whether or not this given <tt>Permission</tt> instance is logically identical to the given
     * argument.  Note this method implementation should check for actual logical equality and not permission
     * implication - permission implication is reserved for the {@link #implies implies} method.
     * @param o the object to test for equality comparison.
     * @return <tt>true</tt> if the given argument is logically identical to this instance, false otherwise.
     */
    boolean equals( Object o );

    /**
     * Returns the hashCode representation of the instance.
     * @return the hashCode representation of the instance.
     */
    int hashCode();
}
