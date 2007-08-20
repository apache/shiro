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

import java.util.Set;

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

    /**
     * Returns the 'name' of this permission. typically whatever value that best represents behavior or access to a
     * resource.
     *
     * <p>Somewhat abstract, the 'name' of a standard permission can mean whatever
     * the application wishes it to mean.  In many systems it would be something like 'createUsers' or
     * 'userSearch', or anything else the application feels is meaningful.
     *
     * @return the 'name' of the permission, where the name value usually represents behavior or access to a resource.
     */
    String getName();

    /**
     * Returns the target's name.  That is, if this Permission and its actions are targed at a specific
     * resource, this method returns the name of that resource.  For example, this instance:<br/><br/>
     *
     * <pre>new FilePermission( "/bin/bash", "execute" );</pre>
     *
     * <p>would have a <tt>targetName</tt> of &quot;/bin/bash&quot;, since that is the <em>target</em> of actions
     * represented by this permission (&quot;execute&quot;).
     *
     * @return the name of the target corresponding to the permission's actions, or <tt>null</tt> if no specific
     * resource is targeted.
     */
    String getTargetName();

    /**
     * Returns all actions represented by the permission instance, or <tt>null</tt> if there are none.
     *
     * <p>If the permission is {@link #getTargetName targeted}, these are the actions associated with that target
     *
     * @return all actions represented by the permission instance or <tt>null</tt> if there are none.
     */
    Set<String> getActionsSet();

    /**
     * Returns the canonically ordered String containing all actions represented by a permission
     * instance, or <tt>null</tt> if there are no actions.  The string must be composed of, and match exactly, those
     * actions in the {@link #getActions actions} set. 
     *
     * <p>For example, a FilePermission class might have the possible actions of <tt>read</tt>, <tt>write</tt>, and
     * <tt>execute</tt> and <tt>delete</tt>.  If there were a FilePermission for a target of
     * <tt>/home/jsmith</tt>, a FilePermission instance for that file might return an actions string of
     * &quot;read,write&quot; only.
     *
     * @return the canonically ordered string representation of this instance's permission actions, or <tt>null</tt> if
     * there are none.
     */
    String getActions();

    boolean implies( Permission p );

    String toString();

    boolean equals( Object o );

    int hashCode();
}
