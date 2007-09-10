package org.jsecurity.authz;

import java.util.Collection;
import java.util.List;

/**
 * <p>An interface that must be returned by many {@link org.jsecurity.realm.Realm} implementations and is used to
 * represent the roles and permissions that a user account has in a framework independent way.
 *
 * <p>Used internally by any realm that extends from
 * {@link org.jsecurity.realm.support.AuthorizingRealm}, which
 * uses this object to encapsulate the cached information.</p>
 *
 * <p>Most realms will use {@link org.jsecurity.authz.support.SimpleAuthorizationInfo} as the implementation of this interface, but are free
 * to create their own implementation.</p>
 *
 * @since 0.1
 * @author Jeremy Haile
 * @see org.jsecurity.authz.support.SimpleAuthorizationInfo
 */
public interface AuthorizationInfo {
    
    /**
     * @see org.jsecurity.context.SecurityContext#hasRole(String)
     */
    boolean hasRole(String roleIdentifier);

    /**
     * @see org.jsecurity.context.SecurityContext#hasRoles(java.util.List)
     */
    boolean[] hasRoles(List<String> roleIdentifiers);

    /**
     * @see org.jsecurity.context.SecurityContext#hasAllRoles(java.util.Collection)
     */
    boolean hasAllRoles(Collection<String> roleIdentifiers);

    /**
     * @see org.jsecurity.context.SecurityContext#isPermitted(Permission)
     */
    boolean isPermitted(Permission permission);

    /**
     * @see org.jsecurity.context.SecurityContext#isPermitted(java.util.List)
     */
    boolean[] isPermitted(List<Permission> permissions);

    /**
     * @see org.jsecurity.context.SecurityContext#isPermittedAll(java.util.Collection)
     */
    boolean isPermittedAll(Collection<Permission> permissions);

    /**
     * @see org.jsecurity.context.SecurityContext#checkPermission(Permission)
     */
    void checkPermission(Permission permission) throws AuthorizationException;

    /**
     * @see org.jsecurity.context.SecurityContext#checkPermissions(java.util.Collection)
     */
    void checkPermissions(Collection<Permission> permissions) throws AuthorizationException;

    /**
     * @see org.jsecurity.context.SecurityContext#checkRole(String)
     */
    void checkRole(String role);

    /**
     * @see org.jsecurity.context.SecurityContext#checkRoles
     */
    void checkRoles(Collection<String> roles);
}
