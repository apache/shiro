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

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.authz.Permission;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.mgt.SubjectFactory;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.support.DefaultSubjectContext;
import org.apache.shiro.lang.util.StringUtils;

import java.io.Serializable;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.Callable;

/**
 * A {@code Subject} represents state and security operations for a <em>single</em> application user.
 * These operations include authentication (login/logout), authorization (access control), and
 * session access. It is Shiro's primary mechanism for single-user security functionality.
 * <h3>Acquiring a Subject</h3>
 * To acquire the currently-executing {@code Subject}, application developers will almost always use
 * {@code SecurityUtils}:
 * <pre>
 * {@link SecurityUtils SecurityUtils}.{@link org.apache.shiro.SecurityUtils#getSubject() getSubject()}</pre>
 * Almost all security operations should be performed with the {@code Subject} returned from this method.
 * <h3>Permission methods</h3>
 * Note that there are many *Permission methods in this interface overloaded to accept String arguments instead of
 * {@link Permission Permission} instances. They are a convenience allowing the caller to use a String representation of
 * a {@link Permission Permission} if desired.  The underlying Authorization subsystem implementations will usually
 * simply convert these String values to {@link Permission Permission} instances and then just call the corresponding
 * type-safe method.  (Shiro's default implementations do String-to-Permission conversion for these methods using
 * {@link org.apache.shiro.authz.permission.PermissionResolver PermissionResolver}s.)
 * <p/>
 * These overloaded *Permission methods forgo type-safety for the benefit of convenience and simplicity,
 * so you should choose which ones to use based on your preferences and needs.
 *
 * @since 0.1
 */
public interface Subject {

    /**
     * Returns this Subject's application-wide uniquely identifying principal, or {@code null} if this
     * Subject is anonymous because it doesn't yet have any associated account data (for example,
     * if they haven't logged in).
     * <p/>
     * The term <em>principal</em> is just a fancy security term for any identifying attribute(s) of an application
     * user, such as a username, or user id, or public key, or anything else you might use in your application to
     * identify a user.
     * <h4>Uniqueness</h4>
     * Although given names and family names (first/last) are technically considered principals as well,
     * Shiro expects the object returned from this method to be an identifying attribute unique across
     * your entire application.
     * <p/>
     * This implies that things like given names and family names are usually poor
     * candidates as return values since they are rarely guaranteed to be unique;  Things often used for this value:
     * <ul>
     * <li>A {@code long} RDBMS surrogate primary key</li>
     * <li>An application-unique username</li>
     * <li>A {@link java.util.UUID UUID}</li>
     * <li>An LDAP Unique ID</li>
     * </ul>
     * or any other similar suitable unique mechanism valuable to your application.
     * <p/>
     * Most implementations will simply return
     * <code>{@link #getPrincipals()}.{@link org.apache.shiro.subject.PrincipalCollection#getPrimaryPrincipal() getPrimaryPrincipal()}</code>
     *
     * @return this Subject's application-specific unique identity.
     * @see org.apache.shiro.subject.PrincipalCollection#getPrimaryPrincipal()
     */
    Object getPrincipal();

    /**
     * Returns this Subject's principals (identifying attributes) in the form of a {@code PrincipalCollection} or
     * {@code null} if this Subject is anonymous because it doesn't yet have any associated account data (for example,
     * if they haven't logged in).
     * <p/>
     * The word &quot;principals&quot; is nothing more than a fancy security term for identifying attributes associated
     * with a Subject, aka, application user.  For example, user id, a surname (family/last name), given (first) name,
     * social security number, nickname, username, etc, are all examples of a principal.
     *
     * @return all of this Subject's principals (identifying attributes).
     * @see #getPrincipal()
     * @see org.apache.shiro.subject.PrincipalCollection#getPrimaryPrincipal()
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
     * Same as {@link #checkRoles(Collection<String> roleIdentifiers) checkRoles(Collection<String> roleIdentifiers)} but
     * doesn't require a collection as a an argument.
     * Asserts this Subject has all of the specified roles by returning quietly if they do or throwing an
     * {@link org.apache.shiro.authz.AuthorizationException} if they do not.
     *
     * @param roleIdentifiers roleIdentifiers the application-specific role identifiers to check (usually role ids or role names).
     * @throws AuthorizationException org.apache.shiro.authz.AuthorizationException
     *          if this Subject does not have all of the specified roles.
     * @since 1.1.0
     */
    void checkRoles(String... roleIdentifiers) throws AuthorizationException;

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
     * current session</em>.  See the {@link #isRemembered() isRemembered()} method JavaDoc for more.
     *
     * @return {@code true} if this Subject proved their identity during their current session
     *         by providing valid credentials matching those known to the system, {@code false} otherwise.
     * @since 0.9
     */
    boolean isAuthenticated();


    /**
     * Returns {@code true} if this {@code Subject} has an identity (it is not anonymous) and the identity
     * (aka {@link #getPrincipals() principals}) is remembered from a successful authentication during a previous
     * session.
     * <p/>
     * Although the underlying implementation determines exactly how this method functions, most implementations have
     * this method act as the logical equivalent to this code:
     * <pre>
     * {@link #getPrincipal() getPrincipal()} != null && !{@link #isAuthenticated() isAuthenticated()}</pre>
     * <p/>
     * Note as indicated by the above code example, if a {@code Subject} is remembered, they are
     * <em>NOT</em> considered authenticated.  A check against {@link #isAuthenticated() isAuthenticated()} is a more
     * strict check than that reflected by this method.  For example, a check to see if a subject can access financial
     * information should almost always depend on {@link #isAuthenticated() isAuthenticated()} to <em>guarantee</em> a
     * verified identity, and not this method.
     * <p/>
     * Once the subject is authenticated, they are no longer considered only remembered because their identity would
     * have been verified during the current session.
     * <h4>Remembered vs Authenticated</h4>
     * Authentication is the process of <em>proving</em> you are who you say you are.  When a user is only remembered,
     * the remembered identity gives the system an idea who that user probably is, but in reality, has no way of
     * absolutely <em>guaranteeing</em> if the remembered {@code Subject} represents the user currently
     * using the application.
     * <p/>
     * So although many parts of the application can still perform user-specific logic based on the remembered
     * {@link #getPrincipals() principals}, such as customized views, it should never perform highly-sensitive
     * operations until the user has legitimately verified their identity by executing a successful authentication
     * attempt.
     * <p/>
     * We see this paradigm all over the web, and we will use <a href="http://www.amazon.com">Amazon.com</a> as an
     * example:
     * <p/>
     * When you visit Amazon.com and perform a login and ask it to 'remember me', it will set a cookie with your
     * identity.  If you don't log out and your session expires, and you come back, say the next day, Amazon still knows
     * who you <em>probably</em> are: you still see all of your book and movie recommendations and similar user-specific
     * features since these are based on your (remembered) user id.
     * <p/>
     * BUT, if you try to do something sensitive, such as access your account's billing data, Amazon forces you
     * to do an actual log-in, requiring your username and password.
     * <p/>
     * This is because although amazon.com assumed your identity from 'remember me', it recognized that you were not
     * actually authenticated.  The only way to really guarantee you are who you say you are, and therefore allow you
     * access to sensitive account data, is to force you to perform an actual successful authentication.  You can
     * check this guarantee via the {@link #isAuthenticated() isAuthenticated()} method and not via this method.
     *
     * @return {@code true} if this {@code Subject}'s identity (aka {@link #getPrincipals() principals}) is
     *         remembered from a successful authentication during a previous session, {@code false} otherwise.
     * @since 1.0
     */
    boolean isRemembered();

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
     * <h3>Web Environment Warning</h3>
     * Calling this method in web environments will usually remove any associated session cookie as part of
     * session invalidation.  Because cookies are part of the HTTP header, and headers can only be set before the
     * response body (html, image, etc) is sent, this method in web environments must be called before <em>any</em>
     * content has been rendered.
     * <p/>
     * The typical approach most applications use in this scenario is to redirect the user to a different
     * location (e.g. home page) immediately after calling this method.  This is an effect of the HTTP protocol
     * itself and not a reflection of Shiro's implementation.
     * <p/>
     * Non-HTTP environments may of course use a logged-out subject for login again if desired.
     */
    void logout();

    /**
     * Associates the specified {@code Callable} with this {@code Subject} instance and then executes it on the
     * currently running thread.  If you want to execute the {@code Callable} on a different thread, it is better to
     * use the {@link #associateWith(Callable)} method instead.
     *
     * @param callable the Callable to associate with this subject and then execute.
     * @param <V>      the type of return value the {@code Callable} will return
     * @return the resulting object returned by the {@code Callable}'s execution.
     * @throws ExecutionException if the {@code Callable}'s {@link Callable#call call} method throws an exception.
     * @since 1.0
     */
    <V> V execute(Callable<V> callable) throws ExecutionException;

    /**
     * Associates the specified {@code Runnable} with this {@code Subject} instance and then executes it on the
     * currently running thread.  If you want to execute the {@code Runnable} on a different thread, it is better to
     * use the {@link #associateWith(Runnable)} method instead.
     * <p/>
     * <b>Note</b>: This method is primarily provided to execute existing/legacy Runnable implementations.  It is better
     * for new code to use {@link #execute(Callable)} since that supports the ability to return values and catch
     * exceptions.
     *
     * @param runnable the {@code Runnable} to associate with this {@code Subject} and then execute.
     * @since 1.0
     */
    void execute(Runnable runnable);

    /**
     * Returns a {@code Callable} instance matching the given argument while additionally ensuring that it will
     * retain and execute under this Subject's identity.  The returned object can be used with an
     * {@link java.util.concurrent.ExecutorService ExecutorService} to execute as this Subject.
     * <p/>
     * This will effectively ensure that any calls to
     * {@code SecurityUtils}.{@link SecurityUtils#getSubject() getSubject()} and related functionality will continue
     * to function properly on any thread that executes the returned {@code Callable} instance.
     *
     * @param callable the callable to execute as this {@code Subject}
     * @param <V>      the {@code Callable}s return value type
     * @return a {@code Callable} that can be run as this {@code Subject}.
     * @since 1.0
     */
    <V> Callable<V> associateWith(Callable<V> callable);

    /**
     * Returns a {@code Runnable} instance matching the given argument while additionally ensuring that it will
     * retain and execute under this Subject's identity.  The returned object can be used with an
     * {@link java.util.concurrent.Executor Executor} or another thread to execute as this Subject.
     * <p/>
     * This will effectively ensure that any calls to
     * {@code SecurityUtils}.{@link SecurityUtils#getSubject() getSubject()} and related functionality will continue
     * to function properly on any thread that executes the returned {@code Runnable} instance.
     * <p/>
     * *Note that if you need a return value to be returned as a result of the runnable's execution or if you need to
     * react to any Exceptions, it is highly recommended to use the
     * {@link #associateWith(java.util.concurrent.Callable) createCallable} method instead of this one.
     *
     * @param runnable the runnable to execute as this {@code Subject}
     * @return a {@code Runnable} that can be run as this {@code Subject} on another thread.
     * @see #associateWith (java.util.concurrent.Callable)
     * @since 1.0
     */
    Runnable associateWith(Runnable runnable);

    /**
     * Allows this subject to 'run as' or 'assume' another identity indefinitely.  This can only be
     * called when the {@code Subject} instance already has an identity (i.e. they are remembered from a previous
     * log-in or they have authenticated during their current session).
     * <p/>
     * Some notes about {@code runAs}:
     * <ul>
     * <li>You can tell if a {@code Subject} is 'running as' another identity by calling the
     * {@link #isRunAs() isRunAs()} method.</li>
     * <li>If running as another identity, you can determine what the previous 'pre run as' identity
     * was by calling the {@link #getPreviousPrincipals() getPreviousPrincipals()} method.</li>
     * <li>When you want a {@code Subject} to stop running as another identity, you can return to its previous
     * 'pre run as' identity by calling the {@link #releaseRunAs() releaseRunAs()} method.</li>
     * </ul>
     *
     * @param principals the identity to 'run as', aka the identity to <em>assume</em> indefinitely.
     * @throws NullPointerException  if the specified principals collection is {@code null} or empty.
     * @throws IllegalStateException if this {@code Subject} does not yet have an identity of its own.
     * @since 1.0
     */
    void runAs(PrincipalCollection principals) throws NullPointerException, IllegalStateException;

    /**
     * Returns {@code true} if this {@code Subject} is 'running as' another identity other than its original one or
     * {@code false} otherwise (normal {@code Subject} state).  See the {@link #runAs runAs} method for more
     * information.
     *
     * @return {@code true} if this {@code Subject} is 'running as' another identity other than its original one or
     *         {@code false} otherwise (normal {@code Subject} state).
     * @see #runAs
     * @since 1.0
     */
    boolean isRunAs();

    /**
     * Returns the previous 'pre run as' identity of this {@code Subject} before assuming the current
     * {@link #runAs runAs} identity, or {@code null} if this {@code Subject} is not operating under an assumed
     * identity (normal state). See the {@link #runAs runAs} method for more information.
     *
     * @return the previous 'pre run as' identity of this {@code Subject} before assuming the current
     *         {@link #runAs runAs} identity, or {@code null} if this {@code Subject} is not operating under an assumed
     *         identity (normal state).
     * @see #runAs
     * @since 1.0
     */
    PrincipalCollection getPreviousPrincipals();

    /**
     * Releases the current 'run as' (assumed) identity and reverts back to the previous 'pre run as'
     * identity that existed before {@code #runAs runAs} was called.
     * <p/>
     * This method returns 'run as' (assumed) identity being released or {@code null} if this {@code Subject} is not
     * operating under an assumed identity.
     *
     * @return the 'run as' (assumed) identity being released or {@code null} if this {@code Subject} is not operating
     *         under an assumed identity.
     * @see #runAs
     * @since 1.0
     */
    PrincipalCollection releaseRunAs();

    /**
     * Builder design pattern implementation for creating {@link Subject} instances in a simplified way without
     * requiring knowledge of Shiro's construction techniques.
     * <p/>
     * <b>NOTE</b>: This is provided for framework development support only and should typically never be used by
     * application developers.  {@code Subject} instances should generally be acquired by using
     * <code>SecurityUtils.{@link SecurityUtils#getSubject() getSubject()}</code>
     * <h4>Usage</h4>
     * The simplest usage of this builder is to construct an anonymous, session-less {@code Subject} instance:
     * <pre>
     * Subject subject = new Subject.{@link #Builder() Builder}().{@link #buildSubject() buildSubject()};</pre>
     * The default, no-arg {@code Subject.Builder()} constructor shown above will use the application's
     * currently accessible {@code SecurityManager} via
     * <code>SecurityUtils.{@link SecurityUtils#getSecurityManager() getSecurityManager()}</code>.  You may also
     * specify the exact {@code SecurityManager} instance to be used by the additional
     * <code>Subject.{@link #Builder(org.apache.shiro.mgt.SecurityManager) Builder(securityManager)}</code>
     * constructor if desired.
     * <p/>
     * All other methods may be called before the {@link #buildSubject() buildSubject()} method to
     * provide context on how to construct the {@code Subject} instance.  For example, if you have a session id and
     * want to acquire the {@code Subject} that 'owns' that session (assuming the session exists and is not expired):
     * <pre>
     * Subject subject = new Subject.Builder().sessionId(sessionId).buildSubject();</pre>
     * <p/>
     * Similarly, if you want a {@code Subject} instance reflecting a certain identity:
     * <pre>
     * PrincipalCollection principals = new SimplePrincipalCollection("username", <em>yourRealmName</em>);
     * Subject subject = new Subject.Builder().principals(principals).build();</pre>
     * <p/>
     * <b>Note*</b> that the returned {@code Subject} instance is <b>not</b> automatically bound to the application (thread)
     * for further use.  That is,
     * {@link org.apache.shiro.SecurityUtils SecurityUtils}.{@link org.apache.shiro.SecurityUtils#getSubject() getSubject()}
     * will not automatically return the same instance as what is returned by the builder.  It is up to the framework
     * developer to bind the built {@code Subject} for continued use if desired.
     *
     * @since 1.0
     */
    public static class Builder {

        /**
         * Hold all contextual data via the Builder instance's method invocations to be sent to the
         * {@code SecurityManager} during the {@link #buildSubject} call.
         */
        private final SubjectContext subjectContext;

        /**
         * The SecurityManager to invoke during the {@link #buildSubject} call.
         */
        private final SecurityManager securityManager;

        /**
         * Constructs a new {@link Subject.Builder} instance, using the {@code SecurityManager} instance available
         * to the calling code as determined by a call to {@link org.apache.shiro.SecurityUtils#getSecurityManager()}
         * to build the {@code Subject} instance.
         */
        public Builder() {
            this(SecurityUtils.getSecurityManager());
        }

        /**
         * Constructs a new {@link Subject.Builder} instance which will use the specified {@code SecurityManager} when
         * building the {@code Subject} instance.
         *
         * @param securityManager the {@code SecurityManager} to use when building the {@code Subject} instance.
         */
        public Builder(SecurityManager securityManager) {
            if (securityManager == null) {
                throw new NullPointerException("SecurityManager method argument cannot be null.");
            }
            this.securityManager = securityManager;
            this.subjectContext = newSubjectContextInstance();
            if (this.subjectContext == null) {
                throw new IllegalStateException("Subject instance returned from 'newSubjectContextInstance' " +
                        "cannot be null.");
            }
            this.subjectContext.setSecurityManager(securityManager);
        }

        /**
         * Creates a new {@code SubjectContext} instance to be used to populate with subject contextual data that
         * will then be sent to the {@code SecurityManager} to create a new {@code Subject} instance.
         *
         * @return a new {@code SubjectContext} instance
         */
        protected SubjectContext newSubjectContextInstance() {
            return new DefaultSubjectContext();
        }

        /**
         * Returns the backing context used to build the {@code Subject} instance, available to subclasses
         * since the {@code context} class attribute is marked as {@code private}.
         *
         * @return the backing context used to build the {@code Subject} instance, available to subclasses.
         */
        protected SubjectContext getSubjectContext() {
            return this.subjectContext;
        }

        /**
         * Enables building a {@link Subject Subject} instance that owns the {@link Session Session} with the
         * specified {@code sessionId}.
         * <p/>
         * Usually when specifying a {@code sessionId}, no other {@code Builder} methods would be specified because
         * everything else (principals, inet address, etc) can usually be reconstructed based on the referenced
         * session alone.  In other words, this is almost always sufficient:
         * <pre>
         * new Subject.Builder().sessionId(sessionId).buildSubject();</pre>
         * <p/>
         * <b>Although simple in concept, this method provides very powerful functionality previously absent in almost
         * all Java environments:</b>
         * <p/>
         * The ability to reference a {@code Subject} and their server-side session
         * <em>across clients of different mediums</em> such as web applications, Java applets,
         * standalone C# clients over XML-RPC and/or SOAP, and many others. This is a <em>huge</em>
         * benefit in heterogeneous enterprise applications.
         * <p/>
         * To maintain session integrity across client mediums, the {@code sessionId} <b>must</b> be transmitted
         * to all client mediums securely (e.g. over SSL) to prevent man-in-the-middle attacks.  This
         * is nothing new - all web applications are susceptible to the same problem when transmitting
         * {@code Cookie}s or when using URL rewriting.  As long as the
         * {@code sessionId} is transmitted securely, session integrity can be maintained.
         *
         * @param sessionId the id of the session that backs the desired Subject being acquired.
         * @return this {@code Builder} instance for method chaining.
         */
        public Builder sessionId(Serializable sessionId) {
            if (sessionId != null) {
                this.subjectContext.setSessionId(sessionId);
            }
            return this;
        }

        /**
         * Ensures the {@code Subject} being built will reflect the specified host name or IP as its originating
         * location.
         *
         * @param host the host name or IP address to use as the {@code Subject}'s originating location.
         * @return this {@code Builder} instance for method chaining.
         */
        public Builder host(String host) {
            if (StringUtils.hasText(host)) {
                this.subjectContext.setHost(host);
            }
            return this;
        }

        /**
         * Ensures the {@code Subject} being built will use the specified {@link Session} instance.  Note that it is
         * more common to use the {@link #sessionId sessionId} builder method rather than having to construct a
         * {@code Session} instance for this method.
         *
         * @param session the session to use as the {@code Subject}'s {@link Session}
         * @return this {@code Builder} instance for method chaining.
         */
        public Builder session(Session session) {
            if (session != null) {
                this.subjectContext.setSession(session);
            }
            return this;
        }

        /**
         * Ensures the {@code Subject} being built will reflect the specified principals (aka identity).
         * <p/>
         * For example, if your application's unique identifier for users is a {@code String} username, and you wanted
         * to create a {@code Subject} instance that reflected a user whose username is
         * '{@code jsmith}', and you knew the Realm that could acquire {@code jsmith}'s principals based on the username
         * was named &quot;{@code myRealm}&quot;, you might create the '{@code jsmith} {@code Subject} instance this
         * way:
         * <pre>
         * PrincipalCollection identity = new {@link org.apache.shiro.subject.SimplePrincipalCollection#SimplePrincipalCollection(Object, String) SimplePrincipalCollection}(&quot;jsmith&quot;, &quot;myRealm&quot;);
         * Subject jsmith = new Subject.Builder().principals(identity).buildSubject();</pre>
         * <p/>
         * Similarly, if your application's unique identifier for users is a {@code long} value (such as might be used
         * as a primary key in a relational database) and you were using a {@code JDBC}
         * {@code Realm} named, (unimaginatively) &quot;jdbcRealm&quot;, you might create the Subject
         * instance this way:
         * <pre>
         * long userId = //get user ID from somewhere
         * PrincipalCollection userIdentity = new {@link org.apache.shiro.subject.SimplePrincipalCollection#SimplePrincipalCollection(Object, String) SimplePrincipalCollection}(<em>userId</em>, &quot;jdbcRealm&quot;);
         * Subject user = new Subject.Builder().principals(identity).buildSubject();</pre>
         *
         * @param principals the principals to use as the {@code Subject}'s identity.
         * @return this {@code Builder} instance for method chaining.
         */
        public Builder principals(PrincipalCollection principals) {
            if (principals != null && !principals.isEmpty()) {
                this.subjectContext.setPrincipals(principals);
            }
            return this;
        }

        /**
         * Configures whether or not the created Subject instance can create a new {@code Session} if one does not
         * already exist.  If set to {@code false}, any application calls to
         * {@code subject.getSession()} or {@code subject.getSession(true))} will result in a SessionException.
         * <p/>
         * This setting is {@code true} by default, as most applications find value in sessions.
         *
         * @param enabled whether or not the created Subject instance can create a new {@code Session} if one does not
         *                already exist.
         * @return this {@code Builder} instance for method chaining.
         * @since 1.2
         */
        public Builder sessionCreationEnabled(boolean enabled) {
            this.subjectContext.setSessionCreationEnabled(enabled);
            return this;
        }

        /**
         * Ensures the {@code Subject} being built will be considered
         * {@link org.apache.shiro.subject.Subject#isAuthenticated() authenticated}.  Per the
         * {@link org.apache.shiro.subject.Subject#isAuthenticated() isAuthenticated()} JavaDoc, be careful
         * when specifying {@code true} - you should know what you are doing and have a good reason for ignoring Shiro's
         * default authentication state mechanisms.
         *
         * @param authenticated whether or not the built {@code Subject} will be considered authenticated.
         * @return this {@code Builder} instance for method chaining.
         * @see org.apache.shiro.subject.Subject#isAuthenticated()
         */
        public Builder authenticated(boolean authenticated) {
            this.subjectContext.setAuthenticated(authenticated);
            return this;
        }

        /**
         * Allows custom attributes to be added to the underlying context {@code Map} used to construct the
         * {@link Subject} instance.
         * <p/>
         * A {@code null} key throws an {@link IllegalArgumentException}. A {@code null} value effectively removes
         * any previously stored attribute under the given key from the context map.
         * <p/>
         * <b>*NOTE*:</b> This method is only useful when configuring Shiro with a custom {@link SubjectFactory}
         * implementation.  This method allows end-users to append additional data to the context map which the
         * {@code SubjectFactory} implementation can use when building custom Subject instances. As such, this method
         * is only useful when a custom {@code SubjectFactory} implementation has been configured.
         *
         * @param attributeKey   the key under which the corresponding value will be stored in the context {@code Map}.
         * @param attributeValue the value to store in the context map under the specified {@code attributeKey}.
         * @return this {@code Builder} instance for method chaining.
         * @throws IllegalArgumentException if the {@code attributeKey} is {@code null}.
         * @see SubjectFactory#createSubject(SubjectContext)
         */
        public Builder contextAttribute(String attributeKey, Object attributeValue) {
            if (attributeKey == null) {
                String msg = "Subject context map key cannot be null.";
                throw new IllegalArgumentException(msg);
            }
            if (attributeValue == null) {
                this.subjectContext.remove(attributeKey);
            } else {
                this.subjectContext.put(attributeKey, attributeValue);
            }
            return this;
        }

        /**
         * Creates and returns a new {@code Subject} instance reflecting the cumulative state acquired by the
         * other methods in this class.
         * <p/>
         * This {@code Builder} instance will still retain the underlying state after this method is called - it
         * will not clear it; repeated calls to this method will return multiple {@link Subject} instances, all
         * reflecting the exact same state.  If a new (different) {@code Subject} is to be constructed, a new
         * {@code Builder} instance must be created.
         * <p/>
         * <b>Note</b> that the returned {@code Subject} instance is <b>not</b> automatically bound to the application
         * (thread) for further use.  That is,
         * {@link org.apache.shiro.SecurityUtils SecurityUtils}.{@link org.apache.shiro.SecurityUtils#getSubject() getSubject()}
         * will not automatically return the same instance as what is returned by the builder.  It is up to the
         * framework developer to bind the returned {@code Subject} for continued use if desired.
         *
         * @return a new {@code Subject} instance reflecting the cumulative state acquired by the
         *         other methods in this class.
         */
        public Subject buildSubject() {
            return this.securityManager.createSubject(this.subjectContext);
        }
    }

}
