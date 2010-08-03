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
 * <p>
 * Requires the current executor's Subject to imply a particular permission in
 * order to execute the annotated method.  If the executor's associated
 * {@link org.apache.shiro.subject.Subject Subject} determines that the
 * executor does not imply the specified permission, the method will not be executed.
 * </p>
 *
 * <p>For example, this declaration:
 * <p/>
 * <code>&#64;RequiresPermissions( {"file:read", "write:aFile.txt"} )<br/>
 * void someMethod();</code>
 * <p/>
 * indicates the current user must be able to both <tt>read</tt> and <tt>write</tt>
 * to the file <tt>aFile.txt</tt> in order for the <tt>someMethod()</tt> to execute, otherwise
 * an {@link org.apache.shiro.authz.AuthorizationException AuthorizationException} will be thrown.
 *
 * @see org.apache.shiro.subject.Subject#checkPermission
 * @since 0.1
 */
@Target({ElementType.TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
public @interface RequiresPermissions {

    /**
     * The permission string which will be passed to {@link org.apache.shiro.subject.Subject#isPermitted(String)}
     * to determine if the user is allowed to invoke the code protected by this annotation.
     */
    String[] value();
    
    /**
     * The logical operation for the permission checks in case multiple roles are specified. AND is the default
     * @since 1.1.0
     */
    Logical logical() default Logical.AND; 

}

