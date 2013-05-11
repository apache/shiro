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

import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.session.Session;

import java.io.Serializable;
import java.util.Map;

/**
 * A {@code SubjectContext} is a 'bucket' of data presented to a {@link SecurityManager} which interprets
 * this data to construct {@link org.apache.shiro.subject.Subject Subject} instances.  It is essentially a Map of data
 * with a few additional type-safe methods for easy retrieval of objects commonly used to construct Subject instances.
 * <p/>
 * While this interface contains type-safe setters and getters for common data types, the map can contain anything
 * additional that might be needed by the {@link SecurityManager} or
 * {@link org.apache.shiro.mgt.SubjectFactory SubjectFactory} implementation to construct {@code Subject} instances.
 * <h2>Data Resolution</h2>
 * The {@link SubjectContext} interface also allows for heuristic resolution of data used to construct a subject
 * instance.  That is, if an attribute has not been explicitly provided via a setter method, the {@code resolve*}
 * methods can use heuristics to obtain that data in another way from other attributes.
 * <p/>
 * For example, if one calls {@link #getPrincipals()} and no principals are returned, perhaps the principals exist
 * in the {@link #getSession() session} or another attribute in the context.  The {@link #resolvePrincipals()} will know
 * how to resolve the principals based on heuristics.  If the {@code resolve*} methods return {@code null} then the
 * data could not be achieved by any heuristics and must be considered as not available in the context.
 * <p/>
 * The general idea is that the normal getters can be called to see if the value was explicitly set.  The
 * {@code resolve*} methods should be used when actually constructing the {@code Subject} instance to ensure the most
 * specific/accurate data can be used.
 * <p/>
 * <b>USAGE</b>: Most Shiro end-users will never use a {@code SubjectContext} instance directly and instead will use a
 * {@link Subject.Builder} (which internally uses a {@code SubjectContext}) and build {@code Subject} instances that
 * way.
 *
 * @see org.apache.shiro.mgt.SecurityManager#createSubject SecurityManager.createSubject
 * @see org.apache.shiro.mgt.SubjectFactory SubjectFactory
 * @since 1.0
 */
public interface SubjectContext extends Map<String, Object> {

    /**
     * Returns the SecurityManager instance that should be used to back the constructed {@link Subject} instance or
     * {@code null} if one has not yet been provided to this context.
     *
     * @return the SecurityManager instance that should be used to back the constructed {@link Subject} instance or
     *         {@code null} if one has not yet been provided to this context.
     */
    SecurityManager getSecurityManager();

    /**
     * Sets the SecurityManager instance that should be used to back the constructed {@link Subject} instance
     * (typically used to support {@link org.apache.shiro.subject.support.DelegatingSubject DelegatingSubject} implementations).
     *
     * @param securityManager the SecurityManager instance that should be used to back the constructed {@link Subject}
     *                        instance.
     */
    void setSecurityManager(SecurityManager securityManager);

    /**
     * Resolves the {@code SecurityManager} instance that should be used to back the constructed {@link Subject}
     * instance (typically used to support {@link org.apache.shiro.subject.support.DelegatingSubject DelegatingSubject} implementations).
     *
     * @return the {@code SecurityManager} instance that should be used to back the constructed {@link Subject}
     *         instance
     */
    SecurityManager resolveSecurityManager();

    /**
     * Returns the session id of the session that should be associated with the constructed {@link Subject} instance.
     * <p/>
     * The construction process is expected to resolve the session with the specified id and then construct the Subject
     * instance based on the resolved session.
     *
     * @return the session id of the session that should be associated with the constructed {@link Subject} instance.
     */
    Serializable getSessionId();

    /**
     * Sets the session id of the session that should be associated with the constructed {@link Subject} instance.
     * <p/>
     * The construction process is expected to resolve the session with the specified id and then construct the Subject
     * instance based on the resolved session.
     *
     * @param sessionId the session id of the session that should be associated with the constructed {@link Subject}
     *                  instance.
     */
    void setSessionId(Serializable sessionId);

    /**
     * Returns any existing {@code Subject} that may be in use at the time the new {@code Subject} instance is
     * being created.
     * <p/>
     * This is typically used in the case where the existing {@code Subject} instance returned by
     * this method is unauthenticated and a new {@code Subject} instance is being created to reflect a successful
     * authentication - you want to return most of the state of the previous {@code Subject} instance when creating the
     * newly authenticated instance.
     *
     * @return any existing {@code Subject} that may be in use at the time the new {@code Subject} instance is
     *         being created.
     */
    Subject getSubject();

    /**
     * Sets the existing {@code Subject} that may be in use at the time the new {@code Subject} instance is
     * being created.
     * <p/>
     * This is typically used in the case where the existing {@code Subject} instance returned by
     * this method is unauthenticated and a new {@code Subject} instance is being created to reflect a successful
     * authentication - you want to return most of the state of the previous {@code Subject} instance when creating the
     * newly authenticated instance.
     *
     * @param subject the existing {@code Subject} that may be in use at the time the new {@code Subject} instance is
     *                being created.
     */
    void setSubject(Subject subject);

    /**
     * Returns the principals (aka identity) that the constructed {@code Subject} should reflect.
     *
     * @return the principals (aka identity) that the constructed {@code Subject} should reflect.
     */
    PrincipalCollection getPrincipals();

    PrincipalCollection resolvePrincipals();

    /**
     * Sets the principals (aka identity) that the constructed {@code Subject} should reflect.
     *
     * @param principals the principals (aka identity) that the constructed {@code Subject} should reflect.
     */
    void setPrincipals(PrincipalCollection principals);

    /**
     * Returns the {@code Session} to use when building the {@code Subject} instance.  Note that it is more
     * common to specify a {@link #setSessionId sessionId} to acquire the desired session rather than having to
     * construct a {@code Session} to be returned by this method.
     *
     * @return the {@code Session} to use when building the {@code Subject} instance.
     */
    Session getSession();

    /**
     * Sets the {@code Session} to use when building the {@code Subject} instance.  Note that it is more
     * common to specify a {@link #setSessionId sessionId} to automatically resolve the desired session rather than
     * constructing a {@code Session} to call this method.
     *
     * @param session the {@code Session} to use when building the {@code Subject} instance.
     */
    void setSession(Session session);

    Session resolveSession();

    /**
     * Returns {@code true} if the constructed {@code Subject} should be considered authenticated, {@code false}
     * otherwise.  Be careful setting this value to {@code true} - you should know what you are doing and have a good
     * reason for ignoring Shiro's default authentication state mechanisms.
     *
     * @return {@code true} if the constructed {@code Subject} should be considered authenticated, {@code false}
     *         otherwise.
     */
    boolean isAuthenticated();

    /**
     * Sets whether or not the constructed {@code Subject} instance should be considered as authenticated.  Be careful
     * when specifying {@code true} - you should know what you are doing and have a good reason for ignoring Shiro's
     * default authentication state mechanisms.
     *
     * @param authc whether or not the constructed {@code Subject} instance should be considered as authenticated.
     */
    void setAuthenticated(boolean authc);

    /**
     * Returns {@code true} if the constructed {@code Subject} should be allowed to create a session, {@code false}
     * otherwise.  Shiro's configuration defaults to {@code true} as most applications find value in Sessions.
     *
     * @return {@code true} if the constructed {@code Subject} should be allowed to create sessions, {@code false}
     * otherwise.
     * @since 1.2
     */
    boolean isSessionCreationEnabled();

    /**
     * Sets whether or not the constructed {@code Subject} instance should be allowed to create a session,
     * {@code false} otherwise.
     *
     * @param enabled whether or not the constructed {@code Subject} instance should be allowed to create a session,
     * {@code false} otherwise.
     * @since 1.2
     */
    void setSessionCreationEnabled(boolean enabled);

    boolean resolveAuthenticated();

    AuthenticationInfo getAuthenticationInfo();

    void setAuthenticationInfo(AuthenticationInfo info);

    AuthenticationToken getAuthenticationToken();

    void setAuthenticationToken(AuthenticationToken token);

    /**
     * Returns the host name or IP that should reflect the constructed {@code Subject}'s originating location.
     *
     * @return the host name or IP that should reflect the constructed {@code Subject}'s originating location.
     */
    String getHost();

    /**
     * Sets the host name or IP that should reflect the constructed {@code Subject}'s originating location.
     *
     * @param host the host name or IP that should reflect the constructed {@code Subject}'s originating location.
     */
    void setHost(String host);

    String resolveHost();
}
