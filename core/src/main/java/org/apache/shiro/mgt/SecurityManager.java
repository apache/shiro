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
package org.apache.shiro.mgt;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.Authenticator;
import org.apache.shiro.authz.Authorizer;
import org.apache.shiro.session.mgt.SessionManager;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.Subject;

import java.util.Map;


/**
 * A <tt>SecurityManager</tt> executes all security operations for <em>all</em> Subjects (aka users) across a
 * single application.
 * <p/>
 * The interface itself primarily exists as a convenience - it extends the {@link org.apache.shiro.authc.Authenticator},
 * {@link Authorizer}, and {@link SessionManager} interfaces, thereby consolidating
 * these behaviors into a single point of reference.  For most Shiro usages, this simplifies configuration and
 * tends to be a more convenient approach than referencing <code>Authenticator</code>, <code>Authorizer</code>, and
 * <code>SessionManager</code> instances seperately;  instead one only needs to interact with a
 * single <tt>SecurityManager</tt> instance.
 * <p/>
 * In addition to the above three interfaces, three unique methods are provided by this interface by itself,
 * {@link #login}, {@link #logout} and {@link #getSubject}.  A {@link org.apache.shiro.subject.Subject Subject} executes
 * authentication, authorization, and session operations for a <em>single</em> user, and as such can only be
 * managed by <tt>A SecurityManager</tt> which is aware of all three functions.  The three parent interfaces on the
 * other hand do not 'know' about <tt>Subject</tt>s to ensure a clean separation of concerns.
 * <p/>
 * <b>Usage Note</b>: In actuality the large majority of application programmers won't interact with a SecurityManager
 * very often, if at all.  <em>Most</em> application programmers only care about security operations for the currently
 * executing user.
 * <p/>
 * In that case, the application programmer can call the
 * {@link #getSubject() getSubject()} method and then use that returned instance for continued interaction with
 * Shiro.  If your application code does not have a direct handle to the application's
 * <code>SecurityManager</code>, you can use {@link org.apache.shiro.SecurityUtils SecurityUtils} anywhere in your code
 * to achieve the same result.
 * <p/>
 * Framework developers on the other hand might find working with an actual SecurityManager useful.
 *
 * @author Les Hazlewood
 * @see org.apache.shiro.mgt.DefaultSecurityManager
 * @since 0.2
 */
public interface SecurityManager extends Authenticator, Authorizer, SessionManager {

    /**
     * Logs in a user, returning a Subject instance if the authentication is successful or throwing an
     * <code>AuthenticationException</code> if it is not.
     * <p/>
     * Note that most application developers should probably not call this method directly unless they have a good
     * reason for doing so.  The preferred way to log in a Subject is to call
     * <code>subject.{@link org.apache.shiro.subject.Subject#login login(authenticationToken)}</code> (usually after
     * acquiring the Subject by calling {@link org.apache.shiro.SecurityUtils#getSubject() SecurityUtils.getSubject()}).
     * <p/>
     * Framework developers on the other hand might find calling this method directly useful in certain cases.
     *
     * @param authenticationToken the token representing the Subject's principal(s) and credential(s)
     * @return an authenticated Subject upon a successful attempt
     * @throws org.apache.shiro.authc.AuthenticationException
     *          if the login attempt failed.
     * @since 0.9
     */
    Subject login(AuthenticationToken authenticationToken) throws AuthenticationException;

    /**
     * Logs out the specified Subject from the system.
     * <p/>
     * Note that most application developers should not call this method unless they have a good reason for doing
     * so.  The preferred way to logout a Subject is to call
     * <code>{@link org.apache.shiro.subject.Subject#logout Subject.logout()}</code>, not the
     * <code>SecurityManager</code> directly.
     * <p/>
     * Framework developers on the other hand might find calling this method directly useful in certain cases.
     *
     * @param subjectIdentifier the identifier of the subject/user to log out.
     * @see #getSubject()
     * @since 0.9
     */
    void logout(PrincipalCollection subjectIdentifier);

    /**
     * Returns the <tt>Subject</tt> instance representing the currently executing user.
     *
     * @return the <tt>Subject</tt> instance representing the currently executing user.
     * @since 0.9
     */
    Subject getSubject();

    /**
     * Returns the {@code Subject} instance reflecting the specified contextual data.
     * <p/>
     * The context can be anything needed by this {@code SecurityManager} to construct a {@code Subject} instance.
     * Most Shiro end-users will never call this method - it exists primarily for
     * framework development and to support any underlying {@link SubjectFactory SubjectFactory} implementations used
     * by the {@code SecurityManager}.
     * <h4>Usage</h4>
     * The difference between calling this method and {@link #getSubject() getSubject()} is that the {@code Subject}
     * instance returned from this method is not automatically 'bound' to the application
     * for further use.  That is, after calling this method, a call to {@code getSubject()} will not necessarily return
     * the same instance.  Callers are expected to know that {@code Subject} instances have local scope only and any
     * other further use beyond the calling method must be managed manually.
     *
     * @param context any data needed to direct how the Subject should be constructed.
     * @return the {@code Subject} instance reflecting the specified initialization data.
     * @see SubjectFactory#createSubject(java.util.Map)
     * @since 1.0
     */
    Subject getSubject(Map context);

    /*Subject getSubject(Map initData);

    Subject getSubjectBySessionId(Serializable sessionId);

    Subject getSubject(PrincipalCollection principals);*/
}
