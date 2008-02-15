package org.jsecurity.authz.permission;

import org.jsecurity.authz.Permission;

/**
 * <p>Interface used to resolve a {@link org.jsecurity.authz.Permission} object from a String representation.
 * A <tt>PermissionResolver</tt> will typically be configured into the {@link SecurityManager} implementation
 * used by the application.</p>
 *
 * <p>For most purposes, the default {@link org.jsecurity.authz.permission.WildcardPermissionResolver} should be
 * suitable for most purposes, which constructs {@link org.jsecurity.authz.permission.WildcardPermission} objects.
 * However, any resolver may be configured if an application wishes to use a different
 * {@link org.jsecurity.authz.Permission} implementation(s).</p>
 *
 * <p>The <tt>PermissionResolver</tt> is used by many components in JSecurity, such as annotations, property file
 * configuration, URL configuration, etc.  It is useful whenever a String representation of a permission is used.</p>
 */
public interface PermissionResolver {

    /**
     * Resolves a Permission based on the given String representation.
     * @param permissionString the String representation of a permission.
     * @return A Permission object that can be used internally to determine a subject's permissions.
     * @throws InvalidPermissionStringException if the permission string is not valid for this resolver.
     */
    Permission resolvePermission( String permissionString );

}
