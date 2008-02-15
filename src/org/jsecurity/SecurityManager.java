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
package org.jsecurity;

import org.jsecurity.authc.AuthenticationException;
import org.jsecurity.authc.AuthenticationToken;
import org.jsecurity.authc.Authenticator;
import org.jsecurity.authz.AuthorizationException;
import org.jsecurity.authz.Authorizer;
import org.jsecurity.context.SecurityContext;
import org.jsecurity.session.SessionFactory;

import java.util.Collection;
import java.util.List;

/**
 * A <tt>SecurityManager</tt> executes all security operations for <em>all</em> Subjects (aka users) across a
 * single application.
 *
 * <p>The interface itself primarily exists as a convenience - it extends the {@link Authenticator},
 * {@link Authorizer}, and {@link SessionFactory} interfaces, thereby consolidating
 * these behaviors into a single point of reference.  But for most JSecurity usages, this simplifies configuration and
 * tends to be a more convenient approach than referencing <code>Authenticator</code>, <code>Authorizer</code>, and
 * <code>SessionFactory</code> instances seperately;  instead one only needs to interact with a
 * single <tt>SecurityManager</tt> instance.</p>
 *
 * <p>In addition to the above three interfaces, three unique methods are provided by this interface by itself,
 * {@link #login}, {@link #logout} and {@link #getSecurityContext}.  A <tt>SecurityContext</tt> executes
 * authentication, authorization, and session operations for a <em>single</em> user, and as such can only be
 * managed by <tt>A SecurityManager</tt> which is aware of all three capabilities.  The three parent interfaces on the
 * other hand do not 'know about' SecurityContexts to ensure a clean separation of concerns.
 *
 * <p>Usage Note:  In actuality the large majority of application programmers won't interact with a SecurityManager
 * very often, if at all.  <em>Most</em> application programmers only care about security operations for the currently
 * executing user.  In that case, the application programmer can call the
 * {@link #getSecurityContext() getSecurityContext()} method and then use the returned instance for all the remaining
 * interaction with JSecurity.
 *
 * <p>Framework developers on the other hand might find working with an actual SecurityManager useful.
 *
 * @see DefaultSecurityManager
 *
 * @since 0.2
 * 
 * @author Les Hazlewood
 */
public interface SecurityManager extends Authenticator, Authorizer, SessionFactory {

    SecurityContext login( AuthenticationToken authenticationToken ) throws AuthenticationException;

    /**
     * Logs out the specified Subject/User from the system.
     *
     * @param subjectIdentifier the identifier of the subject/user to log out.
     */
    void logout( Object subjectIdentifier );

    /**
     * Returns the <tt>SecurityContext</tt> instance representing the currently executing user.
     * @return the <tt>SecurityContext</tt> instance representing the currently executing user.
     */
    SecurityContext getSecurityContext();

    /**
     * Returns <tt>true</tt> if the subject with the given <tt>subjectIdentifier</tt> is
     * permitted to perform an action or access a resource summarized by the specified permission.
     *
     * <p>More specifically, this method should determine if any <tt>Permission</tt>s associated
     * with the subject {@link org.jsecurity.authz.Permission#implies(org.jsecurity.authz.Permission) imply} the
     * specified permission.
     *
     * <p>In most systems, the <tt>subjectIdentifier</tt> is usually an object
     * representing a <tt>User</tt> database primary
     * key or a String username.  The runtime value of the <tt>subjectIdentifier</tt>
     * is specific to the application and
     * determined by the application's JSecurity configuration.
     *
     * @param subjectIdentifier the application-specific identifier
     * for the subject to check (usually a user id or username).
     * @param permission the permission that is being checked.
     * @return true if the user associated with this context is permitted, false otherwise.
     */
    boolean isPermitted( Object subjectIdentifier, String permission );

    /**
     * Checks a collection of permissions to see if they are associated with the subject with
     * the given <tt>subjectIdentifier</tt> and and returns a boolean array indicating which
     * permissions are associated with the subject.
     *
     * <p>More specifically, this method should determine if each <tt>Permission</tt> in
     * the array is {@link org.jsecurity.authz.Permission#implies(org.jsecurity.authz.Permission) implied by} permissions
     * already associated with the subject.
     *
     * <p>This is primarily a performance-enhancing method to help reduce the number of
     * {@link #isPermitted} invocations over the wire in client/server systems.
     *
     * <p>In most systems, the <tt>subjectIdentifier</tt> is usually an object
     * representing a <tt>User</tt> database primary
     * key or a String username.  The runtime value of the <tt>subjectIdentifier</tt>
     * is specific to the application and
     * determined by the application's JSecurity configuration.
     *
     * @param subjectIdentifier the application-specific identifier
     * for the subject to check (usually a user id or username).
     * @param permissions the permissions to check for.
     * @return an array of booleans whose indices correspond to the index of the
     * permissions in the given list.  A true value at an index indicates the user is permitted for
     * for the associated <tt>Permission</tt> object in the list.  A false value at an index
     * indicates otherwise.
     */
    boolean[] isPermitted( Object subjectIdentifier, List<String> permissions );

    /**
     * Checks if the the subject with the given <tt>subjectIdentifier</tt> implies all the
     * specified permissions.
     *
     * <p>More specifically, this method should determine if <em>all</em> of the given
     * <tt>Permission</tt>s are {@link org.jsecurity.authz.Permission#implies(org.jsecurity.authz.Permission) implied by}
     * permissions already associated with the subject.
     *
     * <p>In most systems, the <tt>subjectIdentifier</tt> is usually an object
     * representing a <tt>User</tt> database primary
     * key or a String username.  The runtime value of the <tt>subjectIdentifier</tt>
     * is specific to the application and
     * determined by the application's JSecurity configuration.
     * @param subjectIdentifier the application-specific identifier
     * for the subject to check (usually a user id or username).
     * @param permissions the permissions to be checked.
     * @return true if the user has all permissions, false otherwise.
     */
    boolean isPermittedAll( Object subjectIdentifier, Collection<String> permissions );


    /**
     * A convenience method to ensure a subject (and/or user)
     * {@link org.jsecurity.authz.Permission#implies(org.jsecurity.authz.Permission)} implies} the specified <tt>Permission</tt>.
     * If the subject's exisiting associated permissions do not
     * {@link org.jsecurity.authz.Permission#implies(org.jsecurity.authz.Permission)} imply} the given permission,
     * an {@link org.jsecurity.authz.AuthorizationException} will be thrown.
     *
     * <p>In most systems, the <tt>subjectIdentifier</tt> is usually an object
     * representing a <tt>User</tt> database primary
     * key or a String username.  The runtime value of the <tt>subjectIdentifier</tt>
     * is specific to the application and
     * determined by the application's JSecurity configuration.
     *
     * @param subjectIdentifier the application-specific identifier
     * for the subject to check (usually a user id or username).
     * @param permission the permission to check.
     * @throws org.jsecurity.authz.AuthorizationException if the user does not have the permission.
     */
    void checkPermission( Object subjectIdentifier, String permission ) throws AuthorizationException;


    /**
     * A convenience method to ensure a subject (and/or user)
     * {@link org.jsecurity.authz.Permission#implies(org.jsecurity.authz.Permission) implies} <em>all</em> of the
     * specified <tt>Permission</tt>s.
     * If the subject's exisiting associated permissions do not
     * {@link org.jsecurity.authz.Permission#implies(org.jsecurity.authz.Permission) imply} <em>all</em> of the given permissions,
     * an {@link org.jsecurity.authz.AuthorizationException} will be thrown.
     * @param subjectIdentifier the application-specific identifier
     * for the subject to check (usually a user id or username).
     * @param permissions the permissions to check.
     * @throws AuthorizationException if the user does not have all of the given
     * permissions.
     */
    void checkPermissions( Object subjectIdentifier, Collection<String> permissions ) throws AuthorizationException;
}