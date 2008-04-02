/*
 * Copyright 2005-2008 Les Hazlewood, Jeremy Haile
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.jsecurity.subject;

import org.jsecurity.authc.AuthenticationException;
import org.jsecurity.authc.AuthenticationToken;
import org.jsecurity.authz.AuthorizationException;
import org.jsecurity.authz.Permission;
import org.jsecurity.session.Session;

import java.util.Collection;
import java.util.List;

/**
 * A <tt>Subject</tt> represents state and security operations for a <em>single</em> application user.
 * These operations include authentication (login/logout), authorization (access control), and
 * session access. It is JSecurity's primary mechanism for single-user security functionality.
 *
 * <p>Note that there are many *Permission methods in this interface overloaded to accept String arguments instead of
 * {@link Permission Permission} instances. They are a convenience allowing the caller to use a String representation of
 * a {@link Permission Permission} if desired.  The underlying Authorization subsystem implementations will usually
 * simply convert these String values to {@link Permission Permission} instances and then just call the corresponding
 * type-safe method.  (JSecurity's default implementations do String-to-Permission conversion for these methods using
 * {@link org.jsecurity.authz.permission.PermissionResolver PermissionResolver}s.)
 *
 * <p>These overloaded *Permission methods <em>do</em> forego type-saftey for the benefit of convenience and simplicity,
 * so you should choose which ones to use based on your preferences and needs.
 *
 * @since 0.1
 * @author Les Hazlewood
 * @author Jeremy Haile
 */
public interface Subject {

    /**
     * Returns this Subject's uniquely-identifying principal, or <tt>null</tt> if this
     * Subject doesn't yet have account data associated with it (for example, if they haven't logged in).
     *
     * <p>The term <em>principal</em> is just a fancy security term for any identifying attribute(s) of an application
     * user, such as a username, or user id, or public key, or anything else you might use in your application to
     * identify a user.  And although given names and family names (first/last) are technically principals as well,
     * JSecurity expects the object(s) returned from this method to be uniquely identifying attibute(s) for
     * your application.  This implies that things like given names and family names are usually poor candidates as
     * return values since they are rarely guaranteed to be unique.</p>
     *
     * <p>Most single-Realm applications would return from this method a single unique principal as noted above
     * (for example a String username or Long user id, etc, etc).  Single-realm applications represent the large 
     * majority of JSecurity applications.</p>
     *
     * <p>However, in <em>multi</em>-Realm configurations, which are fully supported by JSecurity as well, it is
     * possible that the return value encapsulates more than one principal.  Typically multi-realm applications need to
     * retain the unique principals for <em>each</em> Realm so subsequent security checks against these Realms can
     * utilize these multiple principals.  In these cases, the object returned could be a Collection or any
     * application-specific instance that encapsulates the principals.</p>
     *
     * @return this Subject's application-specific identity.
     */
    Object getPrincipal();


    PrincipalCollection getPrincipals();


    /**
     * Returns <tt>true</tt> if this Subject is permitted to perform an action or access a resource summarized by the
     * specified permission string.
     *
     * <p>This is an overloaded method for the corresponding type-safe {@link Permission Permission} variant.
     * Please see the class-level JavaDoc for more information on these String-based permission methods.
     *
     * @param permission the String representation of a Permission that is being checked.
     * @return true if this Subject is permitted, false otherwise.
     * @since 0.9
     * @see #isPermitted(Permission permission)
     */
    boolean isPermitted( String permission );

    /**
     * Returns <tt>true</tt> if this Subject is permitted to perform an action or access a resource summarized by the
     * specified permission.
     *
     * <p>More specifically, this method determines if any <tt>Permission</tt>s associated
     * with the subject {@link Permission#implies(Permission) imply} the specified permission.
     *
     * @param permission the permission that is being checked.
     * @return true if this Subject is permitted, false otherwise.
     */
    boolean isPermitted( Permission permission );

    /**
     * Checks if this Subject implies the given permission strings and returns a boolean array indicating which
     * permissions are implied.
     *
     * <p>This is an overloaded method for the corresponding type-safe {@link Permission Permission} variant.
     * Please see the class-level JavaDoc for more information on these String-based permission methods.
     *
     * @param permissions the String representations of the Permissions that are being checked.
     * @return an array of booleans whose indices correspond to the index of the
     * permissions in the given list.  A true value at an index indicates this Subject is permitted for
     * for the associated <tt>Permission</tt> string in the list.  A false value at an index
     * indicates otherwise.
     * @since 0.9
     */
    boolean[] isPermitted( String... permissions );

    /**
     * Checks if this Subject implies the given Permissions and returns a boolean array indicating which permissions
     * are implied.
     *
     * <p>More specifically, this method should determine if each <tt>Permission</tt> in
     * the array is {@link Permission#implies(Permission) implied} by permissions
     * already associated with the subject.
     *
     * <p>This is primarily a performance-enhancing method to help reduce the number of
     * {@link #isPermitted} invocations over the wire in client/server systems.
     *
     * @param permissions the permissions that are being checked.
     * @return an array of booleans whose indices correspond to the index of the
     * permissions in the given list.  A true value at an index indicates this Subject is permitted for
     * for the associated <tt>Permission</tt> object in the list.  A false value at an index
     * indicates otherwise.
     */
    boolean[] isPermitted( List<Permission> permissions );

    /**
     * Returns <tt>true</tt> if this Subject implies all of the specified permission strings, <tt>false</tt> otherwise.
     *
     * <p>This is an overloaded method for the corresponding type-safe {@link Permission Permission} variant.
     * Please see the class-level JavaDoc for more information on these String-based permission methods.
     *
     * @param permissions the String representations of the Permissions that are being checked.
     * @return true if this Subject has all of the specified permissions, false otherwise.
     * @see #isPermittedAll(Collection)
     * @since 0.9
     */
    boolean isPermittedAll( String... permissions );

    /**
     * Returns <tt>true</tt> if this Subject implies all of the specified permissions, <tt>false</tt> otherwise.
     *
     * <p>More specifically, this method determines if all of the given <tt>Permission</tt>s are
     * {@link Permission#implies(Permission) implied by} permissions already associated with this Subject.
     *
     * @param permissions the permissions to check.
     * @return true if this Subject has all of the specified permissions, false otherwise.
     */
    boolean isPermittedAll( Collection<Permission> permissions );

    /**
     * Ensures this Subject implies the specified permission String.
     *
     * <p>If this subject's existing associated permissions do not {@link Permission#implies(Permission)} imply}
     * the given permission, an {@link org.jsecurity.authz.AuthorizationException} will be thrown.
     *
     * <p>This is an overloaded method for the corresponding type-safe {@link Permission Permission} variant.
     * Please see the class-level JavaDoc for more information on these String-based permission methods.
     *
     * @param permission the String representation of the Permission to check.
     * @throws org.jsecurity.authz.AuthorizationException if the user does not have the permission.
     * @since 0.9
     */
    void checkPermission( String permission ) throws AuthorizationException;

    /**
     * Ensures this Subject {@link Permission#implies(Permission) implies} the specified <tt>Permission</tt>.
     *
     * <p>If this subject's exisiting associated permissions do not {@link Permission#implies(Permission) imply}
     * the given permission, an {@link org.jsecurity.authz.AuthorizationException} will be thrown.
     *
     * @param permission the Permission to check.
     * @throws org.jsecurity.authz.AuthorizationException if this Subject does not have the permission.
     */
    void checkPermission( Permission permission ) throws AuthorizationException;

    /**
     * Ensures this Subject
     * {@link org.jsecurity.authz.Permission#implies(org.jsecurity.authz.Permission) implies} all of the
     * specified permission strings.
     *
     * If this subject's exisiting associated permissions do not
     * {@link org.jsecurity.authz.Permission#implies(org.jsecurity.authz.Permission) imply} all of the given permissions,
     * an {@link org.jsecurity.authz.AuthorizationException} will be thrown.
     *
     * <p>This is an overloaded method for the corresponding type-safe {@link Permission Permission} variant.
     * Please see the class-level JavaDoc for more information on these String-based permission methods.
     *
     * @param permissions the string representations of Permissions to check.
     * @throws AuthorizationException if this Subject does not have all of the given permissions.
     * @since 0.9
     */
    void checkPermissions( String... permissions ) throws AuthorizationException;

    /**
     * Ensures this Subject 
     * {@link org.jsecurity.authz.Permission#implies(org.jsecurity.authz.Permission) implies} all of the
     * specified permission strings.
     *
     * If this subject's exisiting associated permissions do not
     * {@link org.jsecurity.authz.Permission#implies(org.jsecurity.authz.Permission) imply} all of the given permissions,
     * an {@link org.jsecurity.authz.AuthorizationException} will be thrown.
     *
     * @param permissions the Permissions to check.
     * @throws AuthorizationException if this Subject does not have all of the given permissions.
     */
    void checkPermissions( Collection<Permission> permissions ) throws AuthorizationException;

    /**
     * Returns <tt>true</tt> if this Subject has the specified role, <tt>false</tt> otherwise.
     *
     * @param roleIdentifier the application-specific role identifier (usually a role id or role name).
     * @return <tt>true</tt> if this Subject has the specified role, <tt>false</tt> otherwise.
     */
    boolean hasRole( String roleIdentifier );

    /**
     * Checks if this Subject has the specified roles, returning a boolean array indicating
     * which roles are associated.
     *
     * <p>This is primarily a performance-enhancing method to help reduce the number of
     * {@link #hasRole} invocations over the wire in client/server systems.
     *
     * @param roleIdentifiers the application-specific role identifiers to check (usually role ids or role names).
     * @return an array of booleans whose indices correspond to the index of the
     * roles in the given identifiers.  A true value indicates this Subject has the
     * role at that index.  False indicates this Subject does not have the role at that index.
     */
    boolean[] hasRoles( List<String> roleIdentifiers );

    /**
     * Returns <tt>true</tt> if this Subject has all of the specified roles, <tt>false</tt> otherwise.
     *
     * @param roleIdentifiers the application-specific role identifiers to check (usually role ids or role names).
     * @return true if this Subject has all the roles, false otherwise.
     */
    boolean hasAllRoles( Collection<String> roleIdentifiers );

    /**
     * Asserts this Subject has the specified role by returning quietly if they do or throwing an
     * {@link org.jsecurity.authz.AuthorizationException} if they do not.
     *
     * @param roleIdentifier the application-specific role identifier (usually a role id or role name ).
     * @throws org.jsecurity.authz.AuthorizationException if this Subject does not have the role.
     */
    void checkRole( String roleIdentifier ) throws AuthorizationException;

    /**
     * Asserts this Subject has all of the specified roles by returning quietly if they do or throwing an
     * {@link org.jsecurity.authz.AuthorizationException} if they do not.
     *
     * @param roleIdentifiers the application-specific role identifiers to check (usually role ids or role names).
     * @throws org.jsecurity.authz.AuthorizationException if this Subject does not have all of the specified roles.
     */
    void checkRoles( Collection<String> roleIdentifiers ) throws AuthorizationException;

    /**
     * Performs a login attempt for this Subject/user.  If unsuccessful,
     * an {@link AuthenticationException} is thrown, the subclass of which identifies why the attempt failed.
     * If successful, the account data associated with the submitted principals/credentials will be
     * associated with this <tt>Subject</tt> and the method will return quietly.
     *
     * <p>Upon returninq quietly, this <tt>Subject</tt> instance can be considered
     * authenticated and {@link #getPrincipal() getPrincipal()} will be non-null and
     * {@link #isAuthenticated() isAuthenticated()} will be <tt>true</tt>.
     *
     * @param token the token encapsulating the subject's principals and credentials to be passed to the
     * Authentication subsystem for verification.
     * @throws AuthenticationException if the authentication attempt fails.
     * @since 0.9
     */
    void login( AuthenticationToken token ) throws AuthenticationException;

    /**
     * Returns <tt>true</tt> if this Subject/user has proven their identity <em>during their current session</em>
     * by providing valid credentials matching those known to the system, <tt>false</tt> otherwise.
     * 
     * <p>Note that even if this Subject's identity has been remembered via 'remember me' services, this method will
     * still return <tt>false</tt> unless the user has actually logged in with proper credentials <em>during their
     * current session</em>.  See the
     * {@link org.jsecurity.authc.RememberMeAuthenticationToken RememberMeAuthenticationToken} class JavaDoc for why
     * this would occur.</p>
     *
     * @return <tt>true</tt> if this Subject has proven their identity during their current session 
     * by providing valid credentials matching those known to the system, <tt>false</tt> otherwise.
     * @since 0.9
     */
    boolean isAuthenticated();

    /**
     * Returns the application <tt>Session</tt> associated with this Subject.  If no session exists when this
     * method is called, a new session will be created, associated with this Subject, and then returned.
     * 
     * @see #getSession(boolean)
     * @return the application <tt>Session</tt> associated with this Subject.
     * @since 0.2
     */
    Session getSession();

    /**
     * Returns the application <tt>Session</tt> associated with this Subject.  Based on the boolean argument,
     * this method functions as follows:
     *
     * <ul>
     *   <li>If there is already an existing session associated with this <tt>Subject</tt>, it is returned and
     * the <tt>create</tt> argument is ignored.</li>
     *   <li>If no session exists and <tt>create</tt> is <tt>true</tt>, a new session will be created, associated with
     * this <tt>Subject</tt> and then returned.</li>
     *   <li>If no session exists and <tt>create</tt> is <tt>false</tt>, <tt>null</tt> is returned.</li>
     * </ul>
     *
     * @param create boolean argument determining if a new session should be created or not if there is no existing session.
     * @return the application <tt>Session</tt> associated with this <tt>Subject</tt> or <tt>null</tt> based
     * on the above described logic.
     * @since 0.2
     */
    Session getSession( boolean create );

    /**
     * Logs out this Subject and invalidates and/or removes any associated entities
     * (such as a {@link Session Session} and authorization data.
     */
    void logout();

}
