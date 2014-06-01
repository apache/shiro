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
/**
 * Support for pluggable authentication strategy logic for applications configured with multiple realms.
 * <p/>
 * An {@link org.apache.shiro.authc.strategy.AuthenticationStrategy AuthenticationStrategy} implementation interacts
 * with multiple realms during an authentication attempt and determines how the interactions translates to a successful
 * or failed login attempt.
 * <h3>How It Works</h3>
 * When a Subject attempts to login to the application, the {@link org.apache.shiro.authc.Authenticator Authenticator}
 * implementation (usually a {@link org.apache.shiro.authc.DefaultAuthenticator DefaultAuthenticator}) delegates the
 * actual realm interaction logic to its configured {@code AuthenticationStrategy}.  The {@code AuthenticationStrategy}
 * then interacts with the realms as necessary and determines the outcome of the attempt (success or failure).
 * <p/>
 * The {@link org.apache.shiro.authc.DefaultAuthenticator DefaultAuthenticator} implementation defaults to a
 * {@link org.apache.shiro.authc.strategy.FirstRealmSuccessfulStrategy FirstRealmSuccessfulStrategy} as this appears to
 * suit the needs of most Shiro users, but of course any of the other out-of-the-box Strategy implementations or a
 * custom implementation may be configured if desired.
 *
 * @see org.apache.shiro.authc.strategy.AuthenticationStrategy AuthenticationStrategy
 * @see org.apache.shiro.authc.strategy.FirstRealmSuccessfulStrategy FirstRealmSuccessfulStrategy
 * @see org.apache.shiro.authc.strategy.AtLeastOneRealmSuccessfulStrategy AtLeastOneRealmSuccessfulStrategy
 * @see org.apache.shiro.authc.strategy.AllRealmsSuccessfulStrategy AllRealmsSuccessfulStrategy
 * @see org.apache.shiro.authc.DefaultAuthenticator DefaultAuthenticator
 *
 * @since 2.0
 */
package org.apache.shiro.authc.strategy;
