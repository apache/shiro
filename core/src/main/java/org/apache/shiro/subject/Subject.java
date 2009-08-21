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
package org.apache.shiro.subject;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.authz.Permission;
import org.apache.shiro.session.Session;

import java.util.Collection;
import java.util.List;
import java.util.concurrent.Callable;

/**
 * A {@code Subject} represents state and security operations for a <em>single</em> application user.
 * These operations include authentication (login/logout), authorization (access control), and
 * session access. It is Shiro's primary mechanism for single-user security functionality.
 * <p/>
 * Note that there are many *Permission methods in this interface overloaded to accept String arguments instead of
 * {@link Permission Permission} instances. They are a convenience allowing the caller to use a String representation of
 * a {@link Permission Permission} if desired.  The underlying Authorization subsystem implementations will usually
 * simply convert these String values to {@link Permission Permission} instances and then just call the corresponding
 * type-safe method.  (Shiro's default implementations do String-to-Permission conversion for these methods using
 * {@link org.apache.shiro.authz.permission.PermissionResolver PermissionResolver}s.)
 * <p/>
 * These overloaded *Permission methods <em>do</em> forgo type-saftey for the benefit of convenience and simplicity,
 * so you should choose which ones to use based on your preferences and needs.
 *
 * @author Les Hazlewood
 * @author Jeremy Haile
 * @since 0.1
 */
public interface Subject {

    /**
     * Returns this Subject's uniquely-identifying principal, or {@code null} if this
     * Subject doesn't yet have account data associated with it (for example, if they haven't logged in).
     * <p/>
     * The term <em>principal</em> is just a fancy security term for any identifying attribute(s) of an application
     * user, such as a username, or user id, or public key, or anything else you might use in your application to
     * identify a user.  And although given names and family names (first/last) are technically principals as well,
     * Shiro expects the object(s) returned from this method to be uniquely identifying attribute(s) for
     * your application.  This implies that things like given names and family names are usually poor candidates as
     * return values since they are rarely guaranteed to be unique.
     * <p/>
     * Most single-Realm applications would return from this method a single unique principal as noted above
     * (for example a String username or Long user id, etc, etc).  Single-realm applications represent the large
     * majority of Shiro applications.
     * <p/>
     * However, in <em>multi</em>-Realm configurations, which are fully supported by Shiro as well, it is
     * possible that the return value encapsulates more than one principal.  Typically multi-realm applications need to
     * retain the unique principals for <em>each</em> Realm so subsequent security checks against these Realms can
     * utilize these multiple principals.  In these cases, the object returned could be a Collection or any
     * application-specific instance that encapsulates the principals.
     *
     * @return this Subject's application-specific identity.
     */
    Object getPrincipal();

    /**
     * Returns all of this Subject's principals (identifying attributes) in the form of a {@code PrincipalCollection}.
     * <p/>
     * The word &quot;principals&quot; is nothing more than a fancy security term for identifying attributes associated
     * with a Subject, aka, application user.  For example, user id, a surname (family/last name), given (first) name,
     * social security number, nickname, username, etc, are all examples of a principal.
     * <p/>
     * This method returns all of the principals associated with the Subject, and it is expected that at least one of
     * the principals contained within this collection represent an absolute unique identifier for the application.
     * User IDs, such a {@code Long} database primary key or UUID, or maybe a globally unique username or email
     * address are all good candidates for such a unique identifier.  Non-unique things, such as surnames and
     * given names, are often poor candidates.
     * <p/>
     * For convenience's sake, it is convention that the first principal in this collection be the application's
     * &quot;primary&quot; principal.  That is, {@code getPrincipals().iterator().next();} would return this
     * primary uniquely-identifying principal.
     * In fact, this logic is often the implementation of the {@link #getPrincipal() getPrincipal()} method.
     *
     * @return all of this Subject's principals (identifying attributes).
     * @see #getPrincipal()
     */
    PrincipalCollection getPrincipals();

    /**
     * Returns {@code true} if this Subject is permitted to perform an action or access a resource summarized by the
     * specified permission string.
     * <p/>
     * This is an overloaded method for the corresponding type-safe {@link Permission Permission} variant.
     * Please see the class-level JavaDoc for more information on these String-based permission methods.
     *
     * @param permission the String representation of a Permission that is being checked.
     * @return true if this Subject is permitted, false otherwise.
     * @see #isPermitted(Permission permission)
     * @since 0.9
     */
    boolean isPermitted(String permission);

    /**
     * Returns {@code true} if this Subject is permitted to perform an action or access a resource summarized by the
     * specified permission.
     * <p/>
     * More specifically, this method determines if any {@code Permission}s associated
     * with the subject {@link Permission#implies(Permission) imply} the specified permission.
     *
     * @param permission the permission that is being checked.
     * @return true if this Subject is permitted, false otherwise.
     */
    boolean isPermitted(Permission permission);

    /**
     * Checks if this Subject implies the given permission strings and returns a boolean array indicating which
     * permissions are implied.
     * <p/>
     * This is an overloaded method for the corresponding type-safe {@link Permission Permission} variant.
     * Please see the class-level JavaDoc for more information on these String-based permission methods.
     *
     * @param permissions the String representations of the Permissions that are being checked.
     * @return a boolean array where indices correspond to the index of the
     *         permissions in the given list.  A true value at an index indicates this Subject is permitted for
     *         for the associated {@code Permission} string in the list.  A false value at an index
     *         indicates otherwise.
     * @since 0.9
     */
    boolean[] isPermitted(String... permissions);

    /**
     * Checks if this Subject implies the given Permissions and returns a boolean array indicating which permissions
     * are implied.
     * <p/>
     * More specifically, this method should determine if each {@code Permission} in
     * the array is {@link Permission#implies(Permission) implied} by permissions
     * already associated with the subject.
     * <p/>
     * This is primarily a performance-enhancing method to help reduce the number of
     * {@link #isPermitted} invocations over the wire in client/server systems.
     *
     * @param permissions the permissions that are being checked.
     * @return a boolean array where indices correspond to the index of the
     *         permissions in the given list.  A true value at an index indicates this Subject is permitted for
     *         for the associated {@code Permission} object in the list.  A false value at an index
     *         indicates otherwise.
     */
    boolean[] isPermitted(List<Permission> permissions);

    /**
     * Returns {@code true} if this Subject implies all of the specified permission strings, {@code false} otherwise.
     * <p/>
     * This is an overloaded method for the corresponding type-safe {@link org.apache.shiro.authz.Permission Permission}
     * variant.  Please see the class-level JavaDoc for more information on these String-based permission methods.
     *
     * @param permissions the String representations of the Permissions that are being checked.
     * @return true if this Subject has all of the specified permissions, false otherwise.
     * @see #isPermittedAll(Collection)
     * @since 0.9
     */
    boolean isPermittedAll(String... permissions);

    /**
     * Returns {@code true} if this Subject implies all of the specified permissions, {@code false} otherwise.
     * <p/>
     * More specifically, this method determines if all of the given {@code Permission}s are
     * {@link Permission#implies(Permission) implied by} permissions already associated with this Subject.
     *
     * @param permissions the permissions to check.
     * @return true if this Subject has all of the specified permissions, false otherwise.
     */
    boolean isPermittedAll(Collection<Permission> permissions);

    /**
     * Ensures this Subject implies the specified permission String.
     * <p/>
     * If this subject's existing associated permissions do not {@link Permission#implies(Permission)} imply}
     * the given permission, an {@link org.apache.shiro.authz.AuthorizationException} will be thrown.
     * <p/>
     * This is an overloaded method for the corresponding type-safe {@link Permission Permission} variant.
     * Please see the class-level JavaDoc for more information on these String-based permission methods.
     *
     * @param permission the String representation of the Permission to check.
     * @throws org.apache.shiro.authz.AuthorizationException
     *          if the user does not have the permission.
     * @since 0.9
     */
    void checkPermission(String permission) throws AuthorizationException;

    /**
     * Ensures this Subject {@link Permission#implies(Permission) implies} the specified {@code Permission}.
     * <p/>
     * If this subject's existing associated permissions do not {@link Permission#implies(Permission) imply}
     * the given permission, an {@link org.apache.shiro.authz.AuthorizationException} will be thrown.
     *
     * @param permission the Permission to check.
     * @throws org.apache.shiro.authz.AuthorizationException
     *          if this Subject does not have the permission.
     */
    void checkPermission(Permission permission) throws AuthorizationException;

    /**
     * Ensures this Subject
     * {@link org.apache.shiro.authz.Permission#implies(org.apache.shiro.authz.Permission) implies} all of the
     * specified permission strings.
     * <p/>
     * If this subject's existing associated permissions do not
     * {@link org.apache.shiro.authz.Permission#implies(org.apache.shiro.authz.Permission) imply} all of the given permissions,
     * an {@link org.apache.shiro.authz.AuthorizationException} will be thrown.
     * <p/>
     * This is an overloaded method for the corresponding type-safe {@link Permission Permission} variant.
     * Please see the class-level JavaDoc for more information on these String-based permission methods.
     *
     * @param permissions the string representations of Permissions to check.
     * @throws AuthorizationException if this Subject does not have all of the given permissions.
     * @since 0.9
     */
    void checkPermissions(String... permissions) throws AuthorizationException;

    /**
     * Ensures this Subject
     * {@link org.apache.shiro.authz.Permission#implies(org.apache.shiro.authz.Permission) implies} all of the
     * specified permission strings.
     * <p/>
     * If this subject's existing associated permissions do not
     * {@link org.apache.shiro.authz.Permission#implies(org.apache.shiro.authz.Permission) imply} all of the given permissions,
     * an {@link org.apache.shiro.authz.AuthorizationException} will be thrown.
     *
     * @param permissions the Permissions to check.
     * @throws AuthorizationException if this Subject does not have all of the given permissions.
     */
    void checkPermissions(Collection<Permission> permissions) throws AuthorizationException;

    /**
     * Returns {@code true} if this Subject has the specified role, {@code false} otherwise.
     *
     * @param roleIdentifier the application-specific role identifier (usually a role id or role name).
     * @return {@code true} if this Subject has the specified role, {@code false} otherwise.
     */
    boolean hasRole(String roleIdentifier);

    /**
     * Checks if this Subject has the specified roles, returning a boolean array indicating
     * which roles are associated.
     * <p/>
     * This is primarily a performance-enhancing method to help reduce the number of
     * {@link #hasRole} invocations over the wire in client/server systems.
     *
     * @param roleIdentifiers the application-specific role identifiers to check (usually role ids or role names).
     * @return a boolean array where indices correspond to the index of the
     *         roles in the given identifiers.  A true value indicates this Subject has the
     *         role at that index.  False indicates this Subject does not have the role at that index.
     */
    boolean[] hasRoles(List<String> roleIdentifiers);

    /**
     * Returns {@code true} if this Subject has all of the specified roles, {@code false} otherwise.
     *
     * @param roleIdentifiers the application-specific role identifiers to check (usually role ids or role names).
     * @return true if this Subject has all the roles, false otherwise.
     */
    boolean hasAllRoles(Collection<String> roleIdentifiers);

    /**
     * Asserts this Subject has the specified role by returning quietly if they do or throwing an
     * {@link org.apache.shiro.authz.AuthorizationException} if they do not.
     *
     * @param roleIdentifier the application-specific role identifier (usually a role id or role name ).
     * @throws org.apache.shiro.authz.AuthorizationException
     *          if this Subject does not have the role.
     */
    void checkRole(String roleIdentifier) throws AuthorizationException;

    /**
     * Asserts this Subject has all of the specified roles by returning quietly if they do or throwing an
     * {@link org.apache.shiro.authz.AuthorizationException} if they do not.
     *
     * @param roleIdentifiers the application-specific role identifiers to check (usually role ids or role names).
     * @throws org.apache.shiro.authz.AuthorizationException
     *          if this Subject does not have all of the specified roles.
     */
    void checkRoles(Collection<String> roleIdentifiers) throws AuthorizationException;

    /**
     * Performs a login attempt for this Subject/user.  If unsuccessful,
     * an {@link AuthenticationException} is thrown, the subclass of which identifies why the attempt failed.
     * If successful, the account data associated with the submitted principals/credentials will be
     * associated with this {@code Subject} and the method will return quietly.
     * <p/>
     * Upon returning quietly, this {@code Subject} instance can be considered
     * authenticated and {@link #getPrincipal() getPrincipal()} will be non-null and
     * {@link #isAuthenticated() isAuthenticated()} will be {@code true}.
     *
     * @param token the token encapsulating the subject's principals and credentials to be passed to the
     *              Authentication subsystem for verification.
     * @throws org.apache.shiro.authc.AuthenticationException
     *          if the authentication attempt fails.
     * @since 0.9
     */
    void login(AuthenticationToken token) throws AuthenticationException;

    /**
     * Returns {@code true} if this Subject/user proved their identity <em>during their current session</em>
     * by providing valid credentials matching those known to the system, {@code false} otherwise.
     * <p/>
     * Note that even if this Subject's identity has been remembered via 'remember me' services, this method will
     * still return {@code false} unless the user has actually logged in with proper credentials <em>during their
     * current session</em>.  See the
     * {@link org.apache.shiro.authc.RememberMeAuthenticationToken RememberMeAuthenticationToken} class JavaDoc for why
     * this would occur.
     *
     * @return {@code true} if this Subject proved their identity during their current session
     *         by providing valid credentials matching those known to the system, {@code false} otherwise.
     * @since 0.9
     */
    boolean isAuthenticated();

    /**
     * Returns the application {@code Session} associated with this Subject.  If no session exists when this
     * method is called, a new session will be created, associated with this Subject, and then returned.
     *
     * @return the application {@code Session} associated with this Subject.
     * @see #getSession(boolean)
     * @since 0.2
     */
    Session getSession();

    /**
     * Returns the application {@code Session} associated with this Subject.  Based on the boolean argument,
     * this method functions as follows:
     * <ul>
     * <li>If there is already an existing session associated with this {@code Subject}, it is returned and
     * the {@code create} argument is ignored.</li>
     * <li>If no session exists and {@code create} is {@code true}, a new session will be created, associated with
     * this {@code Subject} and then returned.</li>
     * <li>If no session exists and {@code create} is {@code false}, {@code null} is returned.</li>
     * </ul>
     *
     * @param create boolean argument determining if a new session should be created or not if there is no existing session.
     * @return the application {@code Session} associated with this {@code Subject} or {@code null} based
     *         on the above described logic.
     * @since 0.2
     */
    Session getSession(boolean create);

    /**
     * Logs out this Subject and invalidates and/or removes any associated entities,
     * such as a {@link Session Session} and authorization data.  After this method is called, the Subject is
     * considered 'anonymous' and may continue to be used for another log-in if desired.
     */
    void logout();

    /**
     * Returns a {@code Callable} instance matching the given argument while additionally ensuring that it will
     * retain and execute under this Subject's identity.  The returned object can be used with an
     * {@link java.util.concurrent.ExecutorService ExecutorService} to execute as this Subject.
     *
     * @param callable the callable to execute as this {@code Subject}
     * @param <V>      the {@code Callable}s return value type
     * @return a {@code Callable} that can be run as this {@code Subject}.
     * @since 1.0
     */
    <V> Callable<V> createCallable(Callable<V> callable);

    /**
     * Returns a {@code Runnable} instance matching the given argument while additionally ensuring that it will
     * retain and execute under this Subject's identity.  The returned object can be used with an
     * {@link java.util.concurrent.Executor Executor} or another thread to execute as this Subject.
     * <p/>
     * *Note that if you need a return value to be returned as a result of the runnable's execution or if you need to
     * react to any Exceptions, it is highly recommended to use the
     * {@link #createCallable(java.util.concurrent.Callable) createCallable} method instead of this one.
     *
     * @param runnable the runnable to execute as this {@code Subject}
     * @return a {@code Runnable} that can be run as this {@code Subject} on another thread.
     * @see #createCallable(java.util.concurrent.Callable)
     * @since 1.0
     */
    Runnable createRunnable(Runnable runnable);

    /*void runAs(PrincipalCollection identity);

    <V> V runAs(PrincipalCollection identity, Callable<V> work);

    PrincipalCollection getRunAsIdentity();*/

}
