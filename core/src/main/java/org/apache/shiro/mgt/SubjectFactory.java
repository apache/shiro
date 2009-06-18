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

import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.Subject;

import java.net.InetAddress;

/**
 * A {@code SubjectFactory} is responsible for returning {@link Subject Subject} instances as needed.
 *
 * @author Les Hazlewood
 * @since 1.0
 */
public interface SubjectFactory {

    /**
     * Returns a {@code Subject} instance reflecting the state of a <em>successful</em> authentication attempt.
     * <p/>
     * The '{@code existing}' {@code Subject} method argument is the {@code Subject} that executed the
     * authentication attempt but still reflects an unauthenticated state.  The instance returned from this method
     * is the {@code Subject} instance to use for future application use and reflects an authenticated state.
     *
     * @param token    the {@code AuthenticationToken} submitted during the successful authentication attempt.
     * @param info     the {@code AuthenticationInfo} generated due to the successful authentication attempt.
     * @param existing the {@code Subject} that executed the attempt, still in an 'unauthenticated' state.
     * @return the {@code Subject} for the application to use going forward, but in an 'authenticated' state.
     */
    Subject createSubject(AuthenticationToken token, AuthenticationInfo info, Subject existing);

    /**
     * Returns a {@code Subject} instance reflecting the specified Subject identity (aka 'principals'), any
     * existing {@code Session} that might be in place for that identity, whether or not the Subject is to be
     * considered already authenticated, and the originating host from where the Subject instance to be created is
     * being acquired.
     *
     * @param principals      the identifying attributes of the Subject instance to be created, or
     *                        {@code null} if the Subject's identity is unknown because they haven't logged in yet and are not 'remembered'
     *                        from {@code RememberMe} services.
     * @param existing        any {@link org.apache.shiro.session.Session Session} that might be in place for the specified {@link org.apache.shiro.subject.Subject}, or
     *                        {@code null} if there is no session yet created for the specified {@code Subject}.  If non-{@code null},
     *                        it should be retained and used by the {@code Subject} instance returned from this method call.
     * @param authenticated   whether or not the {@code Subject} instance returned should be considered already
     *                        authenticated.
     * @param originatingHost the host location indicating where the {@code Subject} is located.
     * @return a {@code Subject} instance representing the aggregate state of the specified method arguments.
     */
    Subject createSubject(PrincipalCollection principals, Session existing, boolean authenticated, InetAddress originatingHost);

}
