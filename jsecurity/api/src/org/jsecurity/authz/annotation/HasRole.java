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
 * Requires the current executor to have a particular role in order to execute the
 * annotated method.  If the executor's associated
 * {@link org.jsecurity.authz.AuthorizationContext AuthorizationContext} determines that the
 * executor does not have the specified role, the method will not be executed.
 * </p>
 * For example,<br>
 * <blockquote><pre>
 * &#64;HasRole("myRoleName")
 * void someMethod();
 * </pre>
 * </blockquote>
 *
 * @see org.jsecurity.authz.AuthorizationContext#hasRole(java.io.Serializable roleIdentifier)
 *
 * @since 0.1
 * @author Jeremy Haile
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface HasRole {

    /**
     * The name of the role required to be granted this authorization.
     */
    String value();

}

