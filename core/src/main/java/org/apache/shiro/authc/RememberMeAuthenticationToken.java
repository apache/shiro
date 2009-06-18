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
package org.apache.shiro.authc;

/**
 * An <tt>AuthenticationToken</tt> that indicates if the user wishes their identity to be remembered across sessions.
 *
 * <p>Please note however that when a new session is created for the corresponding user, that user's identity would be
 * remembered, but they are <em>NOT</em> considered authenticated:
 *
 * <p>Authentication is the process of proving you are who you say you are.  In a RememberMe scenario, a remembered
 * identity gives the system an idea who that person probably is, but in reality, has no way of guaranteeing the
 * remembered identity <em>really</em> is that user.
 *
 * <p>So, although many parts of the application can still perform user-specific logic based on the remembered
 * identity, such as customized views, it should never perform security-sensitive operations until the user has
 * actually executed a successful authentication attempt.
 *
 * <p>We see this paradigm all over the web, and we'll use <tt>amazon.com</tt> as an example:
 *
 * <p>When you visit Amazon.com and perform a login and ask it to 'remember me', it will set a cookie with your
 * identity.  If you don't log out and your session expires, and you come back, say the next day, Amazon still knows
 * who you <em>probably</em> are: you still see all of your book and movie recommendations and similar user-specific
 * features since these are based on your (remembered) user id.</p>
 *
 * <p>BUT, if you try to do some sensitive operations, such as access your account's billing data, Amazon forces you
 * to do an actual log-in, requiring your username and password.
 *
 * <p>This is because although amazon.com assumed your identity from 'remember me', it recognized that you were not
 * actually authenticated.  The only way to really guarantee you are who you say you are, and therefore able to
 * access sensitive account data, is for you to perform an actual authentication.
 *
 * @author Les Hazlewood
 * @since 0.9
 */
public interface RememberMeAuthenticationToken extends AuthenticationToken {

    /**
     * Returns <tt>true</tt> if the submitting user wishes their identity (principal(s)) to be remembered
     * across sessions, <tt>false</tt> otherwise.
     *
     * <p>Please see the class-level JavaDoc for what 'remember me' vs. 'authenticated' means - they are semantically
     * different.
     *
     * @return <tt>true</tt> if the submitting user wishes their identity (principal(s)) to be remembered
     *         across sessions, <tt>false</tt> otherwise.
     */
    boolean isRememberMe();

}
