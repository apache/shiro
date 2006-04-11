package org.jsecurity.authz.annotation;

/**
 * <p>
 * Requires the current executor to have one or more specified roles in order to execute the
 * annotated method.  If the executor's associated
 * {@link org.jsecurity.authz.AuthorizationContext AuthorizationContext} determines that the
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
 * @see org.jsecurity.authz.AuthorizationContext#hasRole(String)
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
