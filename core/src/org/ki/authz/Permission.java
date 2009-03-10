/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.ki.authz;

/**
 * A Permission represents the ability to perform an action or access a resource.  A Permission is the most
 * granular, or atomic, unit in a system's security policy and is the cornerstone upon which fine-grained security
 * models are built.
 *
 * <p>It is important to understand a Permission instance only represents functionality or access - it does not grant it.
 * Granting access to an application functionality or a particular resource is done by the application's security
 * configuration, typically by assigning Permissions to users, roles and/or groups.
 *
 * <p>Most typical systems are what the JSecurity team calls <em>role-based</em> in nature, where a role represents
 * common behavior for certain user types.  For example, a system might have an <em>Aministrator</em> role, a
 * <em>User</em> or <em>Guest</em> roles, etc.
 *
 * <p>But if you have a dynamic security model, where roles can be created and deleted at runtime, you can't hard-code
 * role names in your code.  In this environment, roles themselves arent aren't very useful.  What matters is what
 * <em>permissions</em> are assigned to these roles.
 *
 * <p>Under this paradigm, permissions are immutable and reflect an application's raw functionality
 * (opening files, accessing a web URL, creating users, etc).  This is what allows a system's security policy
 * to be dynamic: because Permission classes represent raw functionality and only change when the application's
 * source code changes, they are immutable at runtime - they represent 'what' the system can do.  Roles, users, and
 * groups are the 'who' of the application.  Determining 'who' can do 'what' then becomes a simple exercise of
 * associating Permissions to roles, users, and groups in some way.
 *
 * <p>Most applications do this by associating a named role with permissions (i.e. a role 'has a' collection of
 * Permissions) and then associate users with roles (i.e. a user 'has a' collection of roles) so that by transitive
 * association, the user 'has' the permissions in their roles.  There are numerous variations on this theme
 * (permissions assigned directly to users, or assigned to groups, and users added to groups and these groups in turn
 * have roles, etc, etc).  When employing a permission-based security model instead of a role-based one, users, roles,
 * and groups can all be created, configured and/or deleted at runtime.  This enables  an extremely powerful security
 * model.
 *
 * <p>A benefit to JSecurity is that, although it assumes most systems are based on these types of static role or
 * dynamic role w/ permission schemes, it does not require a system to model their security data this way - all
 * Permission checks are relegated to {@link org.ki.realm.Realm} implementations, and only those implementatons
 * really determine how a user 'has' a permission or not.  The Realm could use the semantics described here, or it
 * could utilize some other mechanism entirely - it is always up to the application developer.
 *
 * <p>JSecurity provides a very powerful default implementation of this interface in the form of the
 * {@link org.ki.authz.permission.WildcardPermission WildcardPermission}.  We highly recommend that you
 * investigate this class before trying to implement your own <code>Permission</code>s.
 *
 * @author Les Hazlewood
 * @see org.ki.authz.permission.WildcardPermission WildcardPermission
 * @since 0.2
 */
public interface Permission {

    /**
     * Returns <tt>true</tt> if this current instance <em>implies</em> all the functionality and/or resource access
     * described by the specified <tt>Permission</tt> argument, <tt>false</tt> otherwise.
     *
     * <p>That is, this current instance must be exactly equal to or a <em>superset</em> of the functionalty
     * and/or resource access described by the given <tt>Permission</tt> argument.  Yet another way of saying this
     * would be:
     *
     * <p>If &quot;permission1 implies permission2&quot;, (i.e. <code>permission1.implies( permission2 ) )</code>,
     * then any Subject granted <tt>permission1</tt> would have ability greater than or equal to that defined by
     * <tt>permission2</tt>.
     *
     * @param p the permission to check for behavior/functionality comparison.
     * @return <tt>true</tt> if this current instance <em>implies</em> all the functionality and/or resource access
     *         described by the specified <tt>Permission</tt> argument, <tt>false</tt> otherwise.
     */
    boolean implies(Permission p);
}
