/*
 * Copyright (C) 2005-2007 Les Hazlewood, Jeremy Haile
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
package org.jsecurity.context;

import org.jsecurity.authz.AuthorizationException;
import org.jsecurity.authz.Permission;
import org.jsecurity.session.Session;

import java.util.Collection;
import java.util.List;

/**
 * Provides all access control behavior and session access for a subject (aka a 'user' account).  This is the primary
 * JSecurity interaction point for a single subject (user).
 *
 * @see org.jsecurity.authc.Authenticator
 *
 * @since 0.1
 * @author Les Hazlewood
 * @author Jeremy Haile
 */
public interface SecurityContext {

    /**
     * Returns the primary identifier of the subject associated with this
     * <tt>SecurityContext</tt> (usually a user id or username), or <tt>null</tt> if there is no subject/user
     * yet associated with the security context (e.g. hasn't logged in yet).
     *
     * <p>This is a convenience method for contexts that only use a single principal.  If multiple
     * principals are associated with the context, the primary principal will be returned.
     * The interpretation of the meaning of &quot;primary principal&quot; is left to the implementation
     * (although most will choose a unique identifier such as a user id or username).
     * @return the primary principal (a.k.a. identifying attribute) of the subject associated with this SecurityContext.
     */
    Object getPrincipal();

    /**
     * Returns all principals associated with this <tt>SecurityContext</tt>, or an empty List if no principals
     * are yet associated with this security context.
     * @return a List of principals associated with this context, or an empty collection
     * if no principals are associated with this security context
     */
    List<?> getAllPrincipals();

    /**
     * Returns a single principal assignable from the specified type
     * that is associated with this <tt>SecurityContext</tt>, or <tt>null</tt> if there are none of the specified type.
     *
     * <p>If multiple principals of
     * this type are associated with this context, it is up to the specific implementation as
     * to which principal will be returned and may be undefined.
     *
     * @param principalType the type of the principal that should be returned.
     * @return a principal of the specified type.
     */
    Object getPrincipalByType( Class principalType );

    /**
     * Returns all principals assignable from the specified type that is associated with
     * this <tt>SecurityContext</tt>, or an empty List if no principals are yet associated with this security
     * context.
     *
     * @param principalType the principal type that should be returned.
     * @return a List of principals that are assignable from the specified type, or
     * an empty List if no principals of this type are associated.
     */
    List<?> getAllPrincipalsByType( Class principalType );

    /**
     * Checks if the given role identifier is associated with this context.
     * @param role the role identifier that is being checked.
     * @return true if the user associated with this context has the role, false otherwise.
     */
    boolean hasRole( String role );

    /**
     * Checks a set of role identifiers to see if they are associated with this
     * context and returns a boolean array indicating which roles are associated
     * with this context.
     *
     * <p>This is primarily a performance-enhancing method to help reduce the number of
     * {@link #hasRole} invocations over the wire in client/server systems.
     *
     * @param roles the role identifiers to check for.
     * @return an array of booleans whose indices correspond to the index of the
     * roles in the given identifiers.  A true value indicates the user has the
     * role at that index.  False indicates the user does not have the role.
     */
    boolean[] hasRoles( List<String> roles);

    /**
     * Checks if the user has all of the given roles.
     * @param roles the roles to be checked.
     * @return true if the user has all roles, false otherwise.
     */
    boolean hasAllRoles( Collection<String> roles );

    /**
     * Returns <tt>true</tt> if this context is
     * permitted to perform an action or access a resource summarized by the specified permission.
     *
     * @param permission the permission that is being checked.
     * @return true if the user associated with this context is permitted, false otherwise.
     */
    boolean isPermitted( Permission permission );

    /**
     * Checks a collection of permissions to see if this context is permitted any of the specified permissions, and
     * and returns a boolean array indicating which ones are permitted.
     *
     * @param permissions the permissions to check for.
     * @return an array of booleans whose indices correspond to the index of the
     * permissions in the given list.  A true value at an index indicates the context is permitted for
     * for the associated <tt>Permission</tt> object in the list.  A false value at an index
     * indicates otherwise.
     */
    boolean[] isPermitted( List<Permission> permissions );

    /**
     * Returns <tt>true</tt> if the context has all of the given permissions, <tt>false</tt> otherwise.
     * @param permissions the permissions to be checked.
     * @return <tt>true</tt> if the context has all of the given permissions, <tt>false</tt> otherwise.
     */
    boolean isPermittedAll( Collection<Permission> permissions );


    /**
     * A convenience method to check if this context isPermitted the specified permission.
     * If the security context does not imply the given permission, an
     * {@link org.jsecurity.authz.AuthorizationException} will be thrown.
     * @param permission the permission to check.
     * @throws org.jsecurity.authz.AuthorizationException if the user does not have the permission.
     */
    void checkPermission( Permission permission ) throws AuthorizationException;


    /**
     * A convenience method for checking if this context isPermitted all of the specified permissions.
     * If the security context does not imply all of the given permissions, an
     * {@link org.jsecurity.authz.AuthorizationException} will be thrown.
     * @param permissions the permissions to check.
     * @throws AuthorizationException if the context does not imply all of the given permissions.
     */
    void checkPermissions( Collection<Permission> permissions ) throws AuthorizationException;

    /**
     * A convenience method to check if the given role is associated with this context.
     * If the security context does not imply the given role, an
     * {@link org.jsecurity.authz.AuthorizationException} will be thrown.
     * @param role the role identifier to check.
     * @throws org.jsecurity.authz.AuthorizationException if the user does not have the role.
     */
    void checkRole( String role ) throws AuthorizationException;


    /**
     * A convenience method for checking if all of the given roles are associated with this context.
     * If the security context does not imply all of the given roles, an
     * {@link org.jsecurity.authz.AuthorizationException} will be thrown.
     * @param roles the roles to check..
     * @throws AuthorizationException if the context is not associated with the given roles.
     */
    void checkRoles( Collection<String> roles ) throws AuthorizationException;

    /**
     * Returns <tt>true</tt> if the user represented by this <tt>SecurityContxt</tt> has proven their identity
     * by providing valid credentials matching those known to the system, <tt>false</tt> otherwise.
     * @return <tt>true</tt> if the user represented by this <tt>SecurityContxt</tt> has proven their identity
     * by providing valid credentials matching those known to the system, <tt>false</tt> otherwise.
     */
    boolean isAuthenticated();

    /**
     * Returns the application <tt>Session</tt> associated with this SecurityContext.  If no session exists when this
     * method is called, a new session will be created, associated with this context, and then returned.
     * 
     * @see #getSession(boolean)
     *
     * @return the application <tt>Session</tt> associated with this context.
     */
    Session getSession();

    /**
     * Returns the application <tt>Session</tt> associated with this SecurityContext.  Based on the boolean argument,
     * this method functions as follows:
     *
     * <ul>
     *   <li>If there is already an existing session associated with this <tt>SecurityContext</tt>, it is returned and
     * the <tt>create</tt> argument is ignored.</li>
     *   <li>If no session exists and <tt>create</tt> is <tt>true</tt>, a new session will be created, associated with
     * this <tt>SecurityContext</tt> and then returned.</li>
     *   <li>If no session exists and <tt>create</tt> is <tt>false</tt>, <tt>null</tt> is returned.</li>
     * </ul>
     *
     * @param create boolean argument determining if a new session should be created or not if there is no existing session.
     * @return the application <tt>Session</tt> associated with this <tt>SecurityContext</tt> or <tt>null</tt> based
     * on the above described logic.
     */
    Session getSession( boolean create );

    /**
     * Invalidates and removes any entities (such as a {@link Session Session} and authorization
     * data associated with this <tt>SecurityContext</tt>.
     *
     * @see #getSession
     */
    public abstract void invalidate();

}
