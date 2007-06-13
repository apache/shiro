/*
 * Copyright (C) 2005-2007 Les Hazlewood
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General
 * Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the
 *
 * Free Software Foundation, Inc.
 * 59 Temple Place, Suite 330
 * Boston, MA 02111-1307
 * USA
 *
 * Or, you may view it online at
 * http://www.opensource.org/licenses/lgpl-license.php
 */
package org.jsecurity.authz.annotation;

/**
 * <p>
 * Requires the current executor to have one or more specified roles in order to execute the
 * annotated method.  If the executor's associated
 * {@link org.jsecurity.context.SecurityContext SecurityContext} determines that the
 * executor does not have the specified role(s), the method will not be executed.
 * </p>
 * <p>For example,<br>
 * <blockquote><pre>
 * &#64;RolesRequired("aRoleName")
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
 * {@link org.jsecurity.authz.annotation.PermissionsRequired PermissionsRequired} annotation makes sense - Permission
 * capabilities will not change for an application since permissions directly correspond to how
 * the application's functionality is programmed.
 *
 * @see org.jsecurity.context.SecurityContext#hasRole(String)
 *
 * @since 0.1
 * @author Jeremy Haile
 * @author Les Hazlewood
 */
@java.lang.annotation.Target(java.lang.annotation.ElementType.METHOD)
@java.lang.annotation.Retention(java.lang.annotation.RetentionPolicy.RUNTIME)
public @interface RolesRequired {

    /**
     * The name of the role required to be granted this authorization.
     */
    String value();

}
