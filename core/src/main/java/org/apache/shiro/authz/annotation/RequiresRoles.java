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
 * Requires the currently executing {@link org.apache.shiro.subject.Subject Subject} to have all of the 
 * specified roles. If they do not have the role(s), the method will not be executed and
 * an {@link org.apache.shiro.authz.AuthorizationException AuthorizationException} is thrown.
 * <p/>
 * For example,
 * <p/>
 * <code>&#64;RequiresRoles("aRoleName");<br/>
 * void someMethod();</code>
 * <p/>
 * means <tt>someMethod()</tt> could only be executed by subjects who have been assigned the
 * 'aRoleName' role.
 *
 * <p><b>*Usage Note*:</b> Be careful using this annotation if your application has a <em>dynamic</em>
 * security model where roles can be added and deleted at runtime.  If your application allowed the
 * annotated role to be deleted during runtime, the method would not be able to
 * be executed by anyone (at least until a new role with the same name was created again).
 *
 * <p>If you require such dynamic functionality, only the
 * {@link RequiresPermissions RequiresPermissions} annotation makes sense - Permission
 * types will not change during runtime for an application since permissions directly correspond to how
 * the application's functionality is programmed (that is, they reflect the application's functionality only, not
 * <em>who</em> is executing the the functionality).
 *
 * @see org.apache.shiro.subject.Subject#hasRole(String)
 * @since 0.1
 */
@Target({ElementType.TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
public @interface RequiresRoles {

    /**
     * A single String role name or multiple comma-delimited role names required in order for the method
     * invocation to be allowed.
     */
    String[] value();
    
    /**
     * The logical operation for the permission check in case multiple roles are specified. AND is the default
     * @since 1.1.0
     */
    Logical logical() default Logical.AND; 
}
