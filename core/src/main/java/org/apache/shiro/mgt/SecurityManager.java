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
import org.apache.shiro.subject.Subject;
import org.apache.shiro.subject.SubjectContext;


/**
 * A {@code SecurityManager} executes all security operations for <em>all</em> Subjects (aka users) across a
 * single application.
 * <p/>
 * The interface itself primarily exists as a convenience - it extends the {@link org.apache.shiro.authc.Authenticator},
 * {@link Authorizer}, and {@link SessionManager} interfaces, thereby consolidating
 * these behaviors into a single point of reference.  For most Shiro usages, this simplifies configuration and
 * tends to be a more convenient approach than referencing {@code Authenticator}, {@code Authorizer}, and
 * {@code SessionManager} instances separately;  instead one only needs to interact with a single
 * {@code SecurityManager} instance.
 * <p/>
 * In addition to the above three interfaces, this interface provides a number of methods supporting
 * {@link Subject} behavior. A {@link org.apache.shiro.subject.Subject Subject} executes
 * authentication, authorization, and session operations for a <em>single</em> user, and as such can only be
 * managed by {@code A SecurityManager} which is aware of all three functions.  The three parent interfaces on the
 * other hand do not 'know' about {@code Subject}s to ensure a clean separation of concerns.
 * <p/>
 * <b>Usage Note</b>: In actuality the large majority of application programmers won't interact with a SecurityManager
 * very often, if at all.  <em>Most</em> application programmers only care about security operations for the currently
 * executing user, usually attained by calling
 * {@link org.apache.shiro.SecurityUtils#getSubject() SecurityUtils.getSubject()}.
 * <p/>
 * Framework developers on the other hand might find working with an actual SecurityManager useful.
 *
 * @see org.apache.shiro.mgt.DefaultSecurityManager
 * @since 0.2
 */
public interface SecurityManager extends Authenticator, Authorizer, SessionManager {

    /**
     * Logs in the specified Subject using the given {@code authenticationToken}, returning an updated Subject
     * instance reflecting the authenticated state if successful or throwing {@code AuthenticationException} if it is
     * not.
     * <p/>
     * Note that most application developers should probably not call this method directly unless they have a good
     * reason for doing so.  The preferred way to log in a Subject is to call
     * <code>subject.{@link org.apache.shiro.subject.Subject#login login(authenticationToken)}</code> (usually after
     * acquiring the Subject by calling {@link org.apache.shiro.SecurityUtils#getSubject() SecurityUtils.getSubject()}).
     * <p/>
     * Framework developers on the other hand might find calling this method directly useful in certain cases.
     *
     * @param subject             the subject against which the authentication attempt will occur
     * @param authenticationToken the token representing the Subject's principal(s) and credential(s)
     * @return the subject instance reflecting the authenticated state after a successful attempt
     * @throws AuthenticationException if the login attempt failed.
     * @since 1.0
     */
    Subject login(Subject subject, AuthenticationToken authenticationToken) throws AuthenticationException;

    /**
     * Logs out the specified Subject from the system.
     * <p/>
     * Note that most application developers should not call this method unless they have a good reason for doing
     * so.  The preferred way to logout a Subject is to call
     * <code>{@link org.apache.shiro.subject.Subject#logout Subject.logout()}</code>, not the
     * {@code SecurityManager} directly.
     * <p/>
     * Framework developers on the other hand might find calling this method directly useful in certain cases.
     *
     * @param subject the subject to log out.
     * @since 1.0
     */
    void logout(Subject subject);

    /**
     * Creates a {@code Subject} instance reflecting the specified contextual data.
     * <p/>
     * The context can be anything needed by this {@code SecurityManager} to construct a {@code Subject} instance.
     * Most Shiro end-users will never call this method - it exists primarily for
     * framework development and to support any underlying custom {@link SubjectFactory SubjectFactory} implementations
     * that may be used by the {@code SecurityManager}.
     * <h4>Usage</h4>
     * After calling this method, the returned instance is <em>not</em> bound to the application for further use.
     * Callers are expected to know that {@code Subject} instances have local scope only and any
     * other further use beyond the calling method must be managed explicitly.
     *
     * @param context any data needed to direct how the Subject should be constructed.
     * @return the {@code Subject} instance reflecting the specified initialization data.
     * @see SubjectFactory#createSubject(SubjectContext)
     * @see Subject.Builder
     * @since 1.0
     */
    Subject createSubject(SubjectContext context);

}
