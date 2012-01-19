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
 * Requires the current Subject to have been authenticated <em>during their current session</em> for the annotated
 * class/instance/method to be accessed or invoked.  This is <em>more</em> restrictive than the
 * {@link RequiresUser RequiresUser} annotation.
 * <p/>
 * This annotation basically ensures that
 * <code>{@link org.apache.shiro.subject.Subject subject}.{@link org.apache.shiro.subject.Subject#isAuthenticated() isAuthenticated()} === true</code>
 * <p/>
 * See the {@link RequiresUser RequiresUser} and
 * {@link org.apache.shiro.authc.RememberMeAuthenticationToken RememberMeAuthenticationToken} JavaDoc for an
 * explaination of why these two states are considered different.
 *
 * @see RequiresUser
 * @see RequiresGuest
 *
 * @since 0.9.0
 */
@Target({ElementType.TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
public @interface RequiresAuthentication {
}
