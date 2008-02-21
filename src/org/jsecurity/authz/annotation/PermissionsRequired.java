/*
 * Copyright (C) 2005-2007 Jeremy Haile, Les Hazlewood
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
 * Requires the current executor's security context to imply a particular permission in
 * order to execute the annotated method.  If the executor's associated
 * {@link org.jsecurity.subject.Subject Subject} determines that the
 * executor does not imply the specified permission, the method will not be executed.
 * </p>
 * For example, this annotation<br>
 * <blockquote><pre>
 * &#64;PermissionsRequired(
 *     type=java.io.FilePermssion.class,
 *     name="aFile.txt",
 *     actions="read,write"
 * )
 * void someMethod();
 * </pre>
 * </blockquote>
 *
 * indicates the current user must be able to both <tt>read</tt> and <tt>write</tt>
 * to the file <tt>aFile.txt</tt> in order for the <tt>someMethod()</tt> to execute, otherwise
 * an {@link org.jsecurity.authz.AuthorizationException AuthorizationException} will be thrown.
 *
 * @see org.jsecurity.subject.Subject#checkPermission
 *
 * @since 0.1
 * @author Jeremy Haile
 * @author Les Hazlewood
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface PermissionsRequired {

    /**
     * The permission string which will be passed to {@link org.jsecurity.subject.Subject#isPermitted(String)}
     * to determine if the user is allowed to invoke the code protected by this annotation.
     */
    String value();

}

