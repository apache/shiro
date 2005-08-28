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
 * @since 0.1
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
    Class<? extends Permission> type();

    /**
     * The target of this permission to or on which {@link #actions()} may be performed.  If
     * not specified, the default target value of &quot;*&quot; means <em>all</em> instances
     * of the permission type.
     *
     * For example, the annotation:<br/>
     * <blockquote><pre>
     * &#64;HasPermission(type=java.io.FilePermission.class,target="aFile.txt",actions={"read","write"})
     * void doSomething() { ... }
     * </pre></blockquote>
     * means &quot;the current executor must have permission to read from <em>and</em> write to
     * the file 'aFile.txt' in order for the <tt>doSomething()</tt> method to execute&quot;
     * <p>and the annotation:<br/>
     * <blockquote><pre>
     * &#64;HasPermission(type=java.io.FilePermission.class,actions={"read"})
     * void doSomething() { ... }
     * </pre></blockquote>
     * means &quot;the current executor must have permission to read <em>all</em> files in order
     * for the <tt>doSomething()</tt> method to execute&quot;
     *
     * <p>This property is ignored if the {@link #targetPath} property is specified.
     */
    String target() default "*";

    /**
     * Specifies a JavaBeans&reg;-style path indicating the object from which to obtain the
     * String name that will be used during {@link Permission} construction.  The
     * {@link Object#toString() toString()} value of the object returned by this path will
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
     *     targetPath=[0].id
     *     actions={"create","update"}
     * )
     * public void saveUser( User aUser ) { ... }</pre>
     *
     * <p>Here, the <tt>targetPath</tt> property conforms to a beans-style path convention where
     * the character sequence prior to the first period ('.') represents the method argument
     * at a certain index for the current method, and all subsequent
     * period-separated names represent nested objects.  The last object in the path will be used
     * to call toString() for a name to use during permission construction.
     *
     * <p>So the targetPath of <tt>[0].id</tt> in the above example is interpreted as
     * <p>&quot;acquire the <tt>saveUser</tt> method argument at index 0 and use the
     * getId().toString() value as the name during <tt>Permission</tt> construction&quot;
     *
     * <p>Likewise, for another method with 4 arguments and the following annotation:
     * <pre>&#64;HasPermission(
     *     type=my.pkg.security.PostalAddressPermission.class,
     *     targetPath=[2].parent.postalAddress.id
     *     actions={"update","delete"}
     * )
     * void foo( String aString, int anInt, User aUser, boolean aBoolean) { ... }</pre>
     * <p>the following name will be used to construct the PostalAddressPermission object used
     * for authorization:
     * <tt>aUser.getParent().getPostalAddress().getId().toString()</tt>, because
     * 'aUser' is the 3rd method argument (index number 2 in the zero-based argument array).
     *
     * This second example annotation therefore is interpreted as
     * <p>&quot;the current executor must have permission to update <em>and</em> delete the
     * PostalAddress object with id <tt>aUser.getParent().getPostalAddress().getId().toString()</tt>
     * in order to execute the foo(...) method&quot;
     *
     * <p>Granted, this second example is a little far reaching, but it shows the power behind
     * instance-level access control in conjunction with annotations.  Practically any object
     * can be checked via the path structure to determine how to construct the <tt>Permission</tt>
     * instance.
     *
     * <p>If defined, this property overrides any {@link #target} value that may have been specified.
     */
    String targetPath() default "";

    /**
     * The actions that the user must able to perform on the related target in order for the
     * authorization to succeed.
     * @see java.security.Permission#getActions()
     */
    String[] actions() default {"*"};
}

