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

/**
 * A Permission represents access to a specific type of resource or ability to perform an action.  It is the most
 * granular, i.e. atomic, unit in a system's security policy and is the cornerstone upon which security models are
 * built.
 *
 * <p>Most Permission instances will have an &quot;actions&quot; <tt>Set</tt> that specifies the behavior
 * allowed on the resource identified by the {@link #getTargetId() targetId}.  For example a <tt>FilePermission</tt>
 * class might have the total actions available of &quot;read&quot;, &quot;write&quot;, &quot;execute&quot;, and
 * &quot;delete&quot;.  A specific instance of the <tt>FilePermission</tt> might have a targetId of "/bin/bash" with
 * actions of &quot;read&quot; and &quot;execute&quot;, meaning whoever is granted that permission could only read and
 * execute <tt>/bin/bash</tt>, but not write to it or delete it.  The actions <tt>Set</tt> is optional though - a
 * permission class is not required to recognize actions, as in the
 * {@link org.jsecurity.authz.AllPermission AllPermission} class.
 *
 * <p>It is important to understand a Permission instance only represents access or behavior - it does not grant it.
 * Granting access to a particular resource or application behavior is done by the application's security configuration,
 * typically by assigning Permissions to users, groups, and/or roles.
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
     * Returns the permission target's identifier in the application's native format.
     *
     * <p>A &quot;target identifier&quot; is whatever object that best represents the target for which the permission
     * models access, according to the application's needs.
     *
     * <p>For example, a <tt>UrlPermission</tt> class would represent access to a URL.  Calling
     * <tt>UrlPermission.getTargetId()</tt>
     * might return an actual {@link java.net.URL URL} instance, where the application could perform specific logic on
     * it (open a connection, call toString, whatever).
     *
     * <p>Another example might be a <tt>UserPermission</tt> class, representing access to a specific user.  In this
     * example, <tt>UserPermission.getTargetId()</tt> might return the actual ID of a user in the application.  This ID
     * object could be a String username in some systems, a Integer representing a RDBMS primary key in others,
     * a {@link java.util.UUID UUID} in others (etc., etc).
     *
     * <p>This method allows applications to represent access to (or behavior on) resources in the format they prefer.
     *  
     * @return the permission target's identifier in the application's native format.
     */
    Serializable getTargetId();

    /**
     * Returns the permission target's identifier in a convenient string format.
     * See {@link #getTargetId() getTargetId()}'s JavaDoc for some examples on what a &quot;target identifier&quot;
     * means.
     *
     * <p>This will typically return a string suitable for printing in log files, error messages, or any other form that
     * would generally be considered useful for human legibility.
     *
     * <p>If you're implementing an instance of this class, most times it is perfectly acceptable to just return
     * <tt>getTargetId().toString()</tt>, assuming of course the object returned from getTargetId() has a proper
     * toString() implementation and it is easy/safe for people to read.  Just realize that this implemention 
     * technique is not required by this interface.
     *
     * <p>As this is more or less a convenience method, the {@link #implies} implementation should not use this value
     * in the implication check - the {@link #getTargetId() targetId} should be used instead.
     *
     * @return the {@link #getTargetId() permission target's identifier} in a convenient string format.
     */
    String getTargetName();

    boolean implies( Permission p );

    String toString();

    boolean equals( Object o );

    int hashCode();
}
