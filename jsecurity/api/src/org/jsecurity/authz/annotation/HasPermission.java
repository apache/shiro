/*
 * Copyright (C) 2005 Jeremy Haile
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

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;


/**
 * <p>
 * An annotation that indicates that a user must have a permission in order
 * to be granted authorization to execute a particular method.
 * </p>
 * For example,<br>
 * <blockquote><pre>
 * &#64;HasPermission(value="MyFilePermission",target="file",actions={"read","write"})
 * void someMethod();
 * </pre>
 * </blockquote>
 *
 * @author Jeremy Haile
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface HasPermission extends AuthorizationAnnotation {

    /**
     * The fully qualified class name of the permission that is required by
     * this authorization. (e.g. "com.foo.MyPermissionName" )
     */
    String value();

    /**
     * The name of the permission required by this authorization.
     * @see java.security.Permission#name
     */
    String name() default "all";

    /**
     * The actions that the user must have permission to perform required
     * by this authorization.
     * @see java.security.Permission#getActions()
     */
    String[] actions() default "*";

}

