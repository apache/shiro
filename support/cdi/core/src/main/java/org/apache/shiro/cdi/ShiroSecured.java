/*
 * Copyright 2013 Harald Wellmann
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.
 *
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.shiro.cdi;

import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import javax.interceptor.InterceptorBinding;

/**
 * Interceptor binding for declarative security checks using the annotations from the 
 * {@code org.apache.shiro.authz.annotation} package.
 * <p>
 * Usage:
 * <ul>
 * <li>Enable the {@code org.apache.shiro.cdi.interceptor.ShiroInterceptor} in {@code beans.xml}.</li>
 * <li>Add authorization annotations (e.g. {@code @RequiresRoles("admin")}) to classes or
 * methods you want to protect.</li>
 * <li>Add {@code @ShiroSecured} to the given classes to enable the interceptor.</li>
 * </ul>
 * The secured methods will fail with an {@code AuthorizationException} if the current subject
 * does not match the security constraints.
 * 
 * @author Harald Wellmann
 *
 */
@Inherited
@InterceptorBinding
@Target({ ElementType.TYPE, ElementType.METHOD })
@Retention(RetentionPolicy.RUNTIME)
public @interface ShiroSecured {
    //
}
