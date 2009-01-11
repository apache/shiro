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
package org.jsecurity.mgt;

import org.jsecurity.authc.AuthenticationException;
import org.jsecurity.authc.AuthenticationToken;
import org.jsecurity.authc.Authenticator;
import org.jsecurity.authz.AuthorizationException;
import org.jsecurity.authz.Authorizer;
import org.jsecurity.authz.HostUnauthorizedException;
import org.jsecurity.session.InvalidSessionException;
import org.jsecurity.session.Session;
import org.jsecurity.session.mgt.SessionManager;
import org.jsecurity.subject.PrincipalCollection;
import org.jsecurity.subject.Subject;

import java.io.Serializable;

/**
 * A <tt>SecurityManager</tt> executes all security operations for <em>all</em> Subjects (aka users) across a
 * single application.
 *
 * <p>The interface itself primarily exists as a convenience - it extends the {@link Authenticator},
 * {@link Authorizer}, and {@link SessionManager} interfaces, thereby consolidating
 * these behaviors into a single point of reference.  For most JSecurity usages, this simplifies configuration and
 * tends to be a more convenient approach than referencing <code>Authenticator</code>, <code>Authorizer</code>, and
 * <code>SessionManager</code> instances seperately;  instead one only needs to interact with a
 * single <tt>SecurityManager</tt> instance.</p>
 *
 * <p>In addition to the above three interfaces, three unique methods are provided by this interface by itself,
 * {@link #login}, {@link #logout} and {@link #getSubject}.  A {@link Subject Subject} executes
 * authentication, authorization, and session operations for a <em>single</em> user, and as such can only be
 * managed by <tt>A SecurityManager</tt> which is aware of all three functions.  The three parent interfaces on the
 * other hand do not 'know' about <tt>Subject</tt>s to ensure a clean separation of concerns.
 *
 * <p><b>Usage Note</b>: In actuality the large majority of application programmers won't interact with a SecurityManager
 * very often, if at all.  <em>Most</em> application programmers only care about security operations for the currently
 * executing user.
 *
 * <p>In that case, the application programmer can call the
 * {@link #getSubject() getSubject()} method and then use that returned instance for continued interaction with
 * JSecurity.  If your application code does not have a direct handle to the application's
 * <code>SecurityManager</code>, you can use {@link org.jsecurity.SecurityUtils SecurityUtils} anywhere in your code
 * to achieve the same result.
 *
 * <p>Framework developers on the other hand might find working with an actual SecurityManager useful.
 *
 * @author Les Hazlewood
 * @see DefaultSecurityManager
 * @since 0.2
 */
public interface SecurityManager extends Authenticator, Authorizer, SessionManager {

    /**
     * Logs in a user, returning a Subject instance if the authentication is successful or throwing an
     * <code>AuthenticationException</code> if it is not.
     * <p/>
     * Note that most application developers should probably not call this method directly unless they have a good
     * reason for doing so.  The preferred way to log in a Subject is to call
     * <code>{@link Subject#login Subject.login(authenticationToken)}</code> (usually after acquiring the
     * Subject by calling {@link org.jsecurity.SecurityUtils#getSubject() SecurityUtils.getSubject()}).
     * <p/>
     * Framework developers on the other hand might find calling this method directly useful in certain cases.
     *
     * @param authenticationToken the token representing the Subject's principal(s) and credential(s)
     * @return an authenticated Subject upon a successful attempt
     * @throws AuthenticationException if the login attempt failed.
     * @since 0.9
     */
    Subject login(AuthenticationToken authenticationToken) throws AuthenticationException;

    /**
     * Logs out the specified Subject from the system.
     *
     * <p>Note that most application developers should not call this method unless they have a good reason for doing
     * so.  The preferred way to logout a Subject is to call <code>{@link Subject#logout Subject.logout()}</code>, not
     * the <code>SecurityManager</code> directly.
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
     * Acquires a handle to the session identified by the specified <tt>sessionId</tt>.
     *
     * <p><b>Although simple, this method finally enables behavior absent in Java for years:</b>
     *
     * <p>the
     * ability to participate in a server-side session across clients of different mediums,
     * such as web appliations, Java applets, standalone C# clients over XMLRPC and/or SOAP, and
     * many others.  This is a <em>huge</em> benefit in heterogeneous enterprise applications.
     *
     * <p>To maintain session integrity across client mediums, the sessionId must be transmitted
     * to all client mediums securely (e.g. over SSL) to prevent man-in-the-middle attacks.  This
     * is nothing new - all web applications are susceptible to the same problem when transmitting
     * {@link javax.servlet.http.Cookie Cookie}s or when using URL rewriting.  As long as the
     * <tt>sessionId</tt> is transmitted securely, session integrity can be maintained.
     *
     * @param sessionId the id of the session to acquire.
     * @return a handle to the session identified by <tt>sessionId</tt>
     * @throws org.jsecurity.session.InvalidSessionException
     *          if the session identified by <tt>sessionId</tt> has
     *          been stopped, expired, or doesn't exist.
     * @throws org.jsecurity.authz.AuthorizationException
     *          if the executor of this method is not allowed to acquire
     *          (i.e. join) the session identified by <tt>sessionId</tt>.  The reason for the exception
     *          is implementation specific and could be for any number of reasons.  A common reason in many
     *          systems would be if one host tried to acquire/join a session that originated on an entirely
     *          different host (although it is not a JSecurity requirement this scenario is disallowed -
     *          its just an example that <em>may</em> throw an Exception in many systems).
     * @see HostUnauthorizedException
     * @since 1.0
     */
    Session getSession(Serializable sessionId) throws InvalidSessionException, AuthorizationException;
}