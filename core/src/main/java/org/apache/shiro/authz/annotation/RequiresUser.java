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
package org.apache.shiro.authz.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Requires the current Subject to be an application <em>user</em> for the annotated class/instance/method to be
 * accessed or invoked.  This is <em>less</em> restrictive than the {@link RequiresAuthentication RequiresAuthentication}
 * annotation.
 * <p/>
 * Shiro defines a &quot;user&quot; as a Subject that is either
 * &quot;remembered&quot; <b><em>or</em></b> authenticated:
 * <ul>
 * <li>An <b>authenticated</b> user is a Subject that has successfully logged in (proven their identity)
 * <em>during their current session</em>.</li>
 * <li>A <b>remembered</b> user is any Subject that has proven their identity at least once, although not necessarily
 * during their current session, and asked the system to remember them.</li>
 * </ul>
 * <p/>
 * See the {@link org.apache.shiro.authc.RememberMeAuthenticationToken RememberMeAuthenticationToken} JavaDoc for an
 * explanation of why these two states are considered different.
 *
 * @see RequiresAuthentication
 * @see RequiresGuest
 *
 * @since 0.9.0
 */
@Target({ElementType.TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
public @interface RequiresUser {
}
