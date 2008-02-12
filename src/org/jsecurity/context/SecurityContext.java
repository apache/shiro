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

import org.jsecurity.authc.AuthenticationException;
import org.jsecurity.authc.AuthenticationToken;
import org.jsecurity.authz.AuthorizationException;
import org.jsecurity.authz.Permission;
import org.jsecurity.session.Session;

import java.util.Collection;
import java.util.List;

/**
 * Provides all authentication (login), authorization (access control), and session operations for a single
 * application <em>Subject</em> (aka 'user').  This is the primary JSecurity interaction point for single-user
 * operations.
 *
 * @since 0.1
 * @author Les Hazlewood
 * @author Jeremy Haile
 */
public interface SecurityContext {

    /**
     * Returns the application-specific Subject identity associated with this <tt>SecurityContext</tt>
     * (usually a user id or username), or <tt>null</tt> if there is no subject/user yet associated
     * (hasn't logged in yet).
     *
     * <p><b>N.B.</b> In a multi-realm configuration, it is possible that this Object encapsulates more than one
     * principal.  Because it is inherently application-specific, You will have to cast this object based on your
     * application's Authentication and Realm configuration.
     *
     * <p>In effect, the Object returned should be the same as the return value from
     * <tt>{@link org.jsecurity.authc.Authenticator#authenticate(org.jsecurity.authc.AuthenticationToken) Authenticator.authenticate(token).}{@link org.jsecurity.authc.Account#getPrincipal() getPrincipal()}
     *
     * @return the application-specific identity of this Subject.
     */
    Object getPrincipal();

    /**
     * Returns a single principal assignable from the specified type, or <tt>null</tt> if there are none of the
     * specified type.
     *
     * <p>If multiple principals of this type are associated with this Subject, it is up to the specific implementation
     * as to which principal will be returned.
     *
     * @param principalType the type of the principal that should be returned.
     * @return a principal of the specified type.
     */
    <T> T getPrincipalByType(Class<T> principalType);

    /**
     * Returns all principals assignable from the specified type that is associated with this <tt>Subject</tt>, or an
     * empty List if no principals are associated.
     *
     * @param principalType the principal type that should be returned.
     * @return a List of principals that are assignable from the specified type, or
     * an empty List if no principals of this type are associated.
     */
    <T> List<T> getAllPrincipalsByType(Class<T> principalType);

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
     * Performs a login attempt for the Subject associated with the calling code.  If unsuccessful,
     * an {@link AuthenticationException} is thrown, the subclass of which identifies why the attempt failed.
     * If successful, the Subject/account data associated with the submitted principals/credentials will be
     * associated with this <tt>SecurityContext</tt> and the method will return quietly.
     *
     * <p>Upon returninq quietly, this <tt>SecurityContext</tt> instance can be considered
     * authenticated and {@link #getPrincipal() getPrincipal()} will be non-null and
     * {@link #isAuthenticated() isAuthenticated()} will be <tt>true</tt>.
     *
     * @param token the token encapsulating the subject's principals and credentials to be passed to the
     * Authentication subsystem for verification.
     * @throws AuthenticationException if the authentication attempt fails.
     *
     * @since 1.0
     */
    void login( AuthenticationToken token ) throws AuthenticationException;

    /**
     * Returns <tt>true</tt> if the user represented by this <tt>SecurityContxt</tt> has proven their identity
     * by providing valid credentials matching those known to the system, <tt>false</tt> otherwise.
     * @return <tt>true</tt> if the user represented by this <tt>SecurityContxt</tt> has proven their identity
     * by providing valid credentials matching those known to the system, <tt>false</tt> otherwise.
     *
     * @since 1.0
     */
    boolean isAuthenticated();

    /**
     * Returns the application <tt>Session</tt> associated with this SecurityContext.  If no session exists when this
     * method is called, a new session will be created, associated with this context, and then returned.
     * 
     * @see #getSession(boolean)
     *
     * @return the application <tt>Session</tt> associated with this context.
     *
     * @since 0.2
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
     *
     * @since 0.2
     */
    Session getSession( boolean create );

    /**
     * Invalidates and removes any entities (such as a {@link Session Session} and authorization
     * data associated with this <tt>SecurityContext</tt>.
     *
     * @see #getSession
     */
    void invalidate();

}
