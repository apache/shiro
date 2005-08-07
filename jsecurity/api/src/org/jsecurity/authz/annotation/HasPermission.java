/*
 * Copyright (C) 2005 Jeremy Haile, Les A. Hazlewood
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
import java.security.Permission;


/**
 * <p>
 * An annotation that indicates that a user must have a permission in order
 * to be granted authorization to execute a particular method.
 * </p>
 * For example, this annotation<br>
 * <blockquote><pre>
 * &#64;HasPermission(
 *     type=java.io.FilePermssion.class,
 *     target="aFile.txt",
 *     actions={"read","write"}
 * )
 * void someMethod();
 * </pre>
 * </blockquote>
 *
 * indicates the current user must be able to both <tt>read</tt> and <tt>write</tt>
 * to the file <tt>aFile.txt</tt> in order for the <tt>someMethod()</tt> to execute, otherwise
 * an {@link org.jsecurity.authz.AuthorizationException AuthorizationException} will be thrown.
 *
 * @author Jeremy Haile
 * @author Les Hazlewood
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface HasPermission {

    /**
     * The permission class used to construct a <tt>Permission</tt> object which will be used
     * during the Authorization check.
     */
    Class<Permission> type();

    /**
     * The target of this permission to or on which {@link #actions()} may be performed.
     *
     * For example, the annotation:<br/>
     * <blockquote><pre>
     * &#64;HasPermission(type=java.io.FilePermission.class,target="aFile.txt",actions={"read","write"})
     * </pre></blockquote>
     * the file name &quot;aFile.txt&quot; is the target object on which the &quot;read&quot; and
     * &quot;write&quot; actions may be executed.
     */
    String target() default "*";

    /**
     * Specifies that the method argument at index <tt>targetIndex()</tt> will be used as the
     * permission target.  This allows the method to be secured based on a
     * <em>method argument</em> instead of hard-coding the target name directly in the
     * annotation declaration.  This kind of security is known as
     * <b>dynamic, instance-level</b> security.
     *
     * <p>The {@link Object#toString() toString()} value of the object at <tt>targetIndex</tt> will
     * be used as the <tt>Permission</tt>'s {@link java.security.Permission#getName() name}
     * when constructing the permission.  If instead another string should be used, specify the
     * {@link #targetMethodName()} parameter.  This method will be called on the target object
     * (instead of <tt>toString</tt>) and the toString value of the object returned by
     * <tt>targetMethodName()</tt> will be used as the Permission's name.
     *
     * <p>This property is ignored if a {@link #target()} is specified.
     *
     * @see #targetMethodName() for more details.
     */
    int targetIndex() default -1;

    /**
     * Specifies a method to be called on the method argument at index {@link #targetIndex()} to
     * use for acquiring the <tt>Permission</tt>'s name used during <tt>Permission</tt> construction.
     * The {@link Object#toString() toString()} value of the object returned by this method will
     * be used as the name when constructing the <tt>Permission</tt> for the security check.
     *
     * <p>The usefulness of this property is best explained via an example:
     *
     * <p>If there was a method:
     *
     * <pre>public void saveUser( User aUser );</pre>
     *
     * <p>It could have an annotation:
     *
     * <pre>&#64;HasPermission(
     *     type=my.pkg.security.UserPermission.class,
     *     targetIndex=0,
     *     targetMethodName="getId"
     *     actions={"create","update"}
     * )
     * public void saveUser( User aUser ) { ... }</pre>
     *
     * <p><em>Without</em> specifying the <tt>targetMethodName</tt> annotation property, the
     * <tt>aUser.toString()</tt> value would be used as the <tt>Permission</tt>'s
     * {@link Permission#getName() name} when constructing the Permission.  This may not be
     * desireable since many business object <tt>toString()</tt> methods return more data than
     * what is needed to construct a <tt>Permission</tt> object.
     *
     * <p>When specifying the <tt>targetMethodName<tt> annotation property, the string value
     * used as the <tt>Permission</tt>'s <tt>name</tt> in the above example would be
     * <tt>aUser.getId().toString()</tt>.  This is probably a more meaningful value when doing
     * instance-level security checks since the check will use the unique id associated with that
     * actual <em>instance</em>.
     *
     * <p>This property is ignored if a {@link #target()} is specified.
     */
    String targetMethodName();

    /**
     * The actions that the user must able to perform on the related target in order for the
     * authorization to succeed.
     * @see java.security.Permission#getActions()
     */
    String[] actions() default {"*"};

}

