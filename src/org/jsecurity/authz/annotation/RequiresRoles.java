/*
 * Copyright 2005-2008 Jeremy Haile, Les Hazlewood
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.jsecurity.authz.annotation;

/**
 * <p>
 * Requires the current executor to have one or more specified roles in order to execute the
 * annotated method.  If the executor's associated
 * {@link org.jsecurity.subject.Subject Subject} determines that the
 * executor does not have the specified role(s), the method will not be executed.
 * </p>
 * <p>For example,<br>
 * <blockquote><pre>
 * &#64;RequiresRoles("aRoleName")
 * void someMethod();
 * </pre>
 * </blockquote>
 *
 * means <tt>someMethod()</tt> could only be executed by subjects who have been assigned the
 * 'aRoleName' role.
 *
 * <p><b>*Usage Note*:</b> Be careful using this annotation if your application has a <em>dynamic</em>
 * security model and the annotated role might be deleted.  If your application allowed the
 * annotated role to be deleted <em>during runtime</em>, the method would not be able to
 * be executed by anyone (at least until a new role with the same name was created again).
 *
 * <p>If you require such dynamic functionality, only the
 * {@link RequiresPermissions RequiresPermissions} annotation makes sense - Permission
 * types will not change during runtime for an application since permissions directly correspond to how
 * the application's functionality is programmed (that is, they reflect the application's functionality only, not
 * <em>who</em> is executing the the functionality).
 *
 * @see org.jsecurity.subject.Subject#hasRole(String)
 *
 * @since 0.1
 * @author Jeremy Haile
 * @author Les Hazlewood
 */
@java.lang.annotation.Target(java.lang.annotation.ElementType.METHOD)
@java.lang.annotation.Retention(java.lang.annotation.RetentionPolicy.RUNTIME)
public @interface RequiresRoles {

    /**
     * A single String role name or multiple comma-delimitted role names required in order for the method
     * invocation to be allowed.
     */
    String value();

}
