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

import org.jsecurity.authz.NamedPermission;
import org.jsecurity.authz.Permission;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * <p>
 * Requires the current executor's security context to imply a particular permission in
 * order to execute the annotated method.  If the executor's associated
 * {@link org.jsecurity.context.SecurityContext SecurityContext} determines that the
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
 * @see org.jsecurity.context.SecurityContext#checkPermission
 *
 * @since 0.1
 * @author Jeremy Haile
 * @author Les Hazlewood
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface PermissionsRequired {

    /**
     * The permission class used to construct a <tt>Permission</tt> object which will be used
     * during an {@link org.jsecurity.context.SecurityContext#checkPermission(Permission) SecurityContext.checkPermission}  check.
     */
    Class<? extends Permission> type();

    /**
     * The name of this permission to or on which {@link #actions()} may be performed.  If
     * not specified, the default name value of &quot;*&quot; means <em>all</em> instances
     * of the permission type.
     *
     * <p>For example, the annotation:</br>
     * <blockquote><pre>
     * &#64;PermissionsRequired(type=java.io.FilePermission.class,name="aFile.txt",actions="read,write")
     * void doSomething() { ... }
     * </pre></blockquote>
     * means &quot;the current executor must have permission to read from <em>and</em> write to
     * the file 'aFile.txt' in order for the <tt>doSomething()</tt> method to execute&quot;
     * <p>and the annotation:<br/>
     * <blockquote><pre>
     * &#64;PermissionsRequired(type=java.io.FilePermission.class,actions="read")
     * void doSomething() { ... }
     * </pre></blockquote>
     * means &quot;the current executor must have permission to read <em>any/all</em> files in order
     * for the <tt>doSomething()</tt> method to execute&quot;
     *
     * <p>This property is ignored if the {@link #namePath} property is specified.
     *
     * @see NamedPermission#getName()
     */
    String name() default NamedPermission.WILDCARD;

    /**
     * Uses the {@link Object#toString() toString()} value of the object at the specified
     * path as the <tt>Permission {@link NamedPermission#getName() name}</tt> to use during
     * <tt>Permission</tt> construction.
     *
     * <p>The objects in this path must conform to property getter and setter naming conventions
     * as defined in the <a href="http://java.sun.com/products/javabeans/docs/spec.html">JavaBeans&reg; 1.01 specification</a>
     *
     * <p>Six formats are supported for resolving the object specified in the path:
     *
     * <ul>
     *   <li><b>Method Argument Index</b> (i.e. <tt>[0]</tt>, <tt>[1]</tt>, ... <tt>[n]</tt>) -
     *       This index must correspond
     *       to the method argument in the annotated method call that will be used to resolve
     *       the remainder of the path.  It is always required and must be specified at the
     *       beginning of the path.</li>
     *   <li><b>Simple</b> (i.e. <tt>name</tt>) - The specified <tt>name</tt> identifies an individual
     *       JavaBeans property of a parent object.  So a bean with a property named
     *       &quot;xyz&quot; will have a getter method named <tt>getXyz()</tt> or
     *       <tt>isXyz()</tt> if &quot;xyz&quot; is a boolean property.</li>
     *   <li><b>Nested</b> (i.e. <tt>name1.name2.name3</tt>) - The first name element is used to select a
     *       property getter, as for simple references above. The object returned for this
     *       property is then consulted, using the same approach, for a property getter for a
     *       property named name2, and so on. The property value that is ultimately retrieved
     *       is the one identified by the last name element.</li>
     *   <li><b>Indexed</b> (i.e. <tt>name[index]</tt>) - The underlying property value is assumed to be an
     *       array or {@link java.util.List List}, or the parent bean is assumed to have indexed
     *       property getter and setter methods. The appropriate (zero-indexed) entry in the
     *       array or <tt>List</tt> is selected. If the property is a list, a getter needs to be
     *       defined that returns the list.</li>
     *   <li><b>Mapped</b> (i.e. <tt>name(key)</tt>) - The parent JavaBean is assumed to have a
     *       property getter method that returns a {@link java.util.Map Map} indexed by
     *       java.lang.String keys.
     *   <li><b>Combined</b> i.e. <tt>name1.name2[index].name3(key)</tt> - Combining mapped,
     *       nested, and indexed references are supported.</li>
     * </ul>
     *
     * <p>The usefulness of a <tt>namePath</tt> is best explained via an example:
     *
     * <p>If there was a method:
     *
     * <pre>public void saveUser( User aUser );</pre>
     *
     * <p>It could have an annotation:
     *
     * <pre>&#64;PermissionsRequired(
     *     type=my.pkg.security.UserPermission.class,
     *     namePath=[0].id
     *     actions="create,update"
     * )
     * public void saveUser( User aUser ) { ... }</pre>
     *
     * <p>This annotation declares that a <tt>my.pkg.security.UserPermission</tt> instance with
     * {@link NamedPermission#getName() name} <tt>aUser.getId().toString()</tt> and
     * {@link org.jsecurity.authz.support.AbstractTargetedPermission#getActions actions} &quot;create&quot;,&quot;update&quot; will be created and
     * verified by {@link org.jsecurity.context.SecurityContext#checkPermission(Permission)}.
     *
     * <p>Therefore the above annotation could be read as:</p>
     * <p>&quot;The current executor must have permission to create <em>and</em> update the
     * user with id <tt>aUser.getId()</tt> in order to execute the <tt>saveUser(User u)</tt>
     * method&quot;.
     *
     * <p>Likewise, another <tt>namePath</tt> example that could be specified:</p>
     * <pre>&#64;PermissionsRequired(
     *     type=my.pkg.security.PostalAddressPermission.class,
     *     namePath=[2].parent.postalAddress.id
     *     actions="update,delete"
     * )
     * void foo( String aString, int anInt, Child aChild, Address aBoolean) { ... }</pre>
     *
     * <p>This example <tt>namePath</tt> will use the
     * <tt>aChild.getParent().getPostalAddress().getId().toString()</tt> as the
     * <tt>my.pkg.security.PostalAddressPermission</tt> instance <tt>name</tt> because
     * 'aChild' is the 3rd method argument (index 2 in the zero-based method argument list).</p>
     *
     * This second example annotation therefore is interpreted as
     * <p>&quot;the current executor must have permission to update <em>and</em> delete the
     * PostalAddress object with id <tt>aChild.getParent().getPostalAddress().getId()</tt>
     * in order to execute the foo(...) method&quot;
     *
     * <p>Granted, this second example is a little far reaching, but it shows the power behind
     * instance-level access control in conjunction with annotations.  Practically any object
     * can be checked via the path structure to determine how to construct the <tt>Permission</tt>
     * instance.
     *
     * <p>If defined, this property overrides any {@link #name} value that may have been specified.
     */
    String namePath() default "";

    /**
     * The actions that the user must able to perform on the related name in order for the
     * authorization to succeed.
     *
     * <p>This is an optional attribute.  If left unspecified, no actions will be used to construct
     * the Permission
     */
    String actions() default "";
}

