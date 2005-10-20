package org.jsecurity.ri.authz;

import org.jsecurity.authz.AuthorizationException;

import java.util.List;
import java.util.Collection;
import java.security.Permission;
import java.io.Serializable;

/**
 * A <tt>Realm</tt> is a security component that can access application-specific security entities
 * such as users, roles, and permissions to determine authorization behavior.
 *
 * <p>Because every application is different, security data such as users and roles can be
 * represented in any number of ways.  Because the JSecurity Reference Implementation tries to
 * maintain a non-intrusive development philosophy whenever possible, it does not require you to
 * implement or extend any <tt>User</tt>, <tt>Group</tt> or <tt>Role</tt> interfaces or classes.
 *
 * <p>Instead, the JSecurity RI allows applications to implement this interface to access
 * environment-specific components and data model objects.  The implementation can then be
 * plugged in to the application's JSecurity RI configuration.  This modular technique abstracts
 * away any environment/modeling details and allows the JSecurity RI to be deployed in
 * practically any application environment.
 */
public interface Realm {

    /**
     * Returns <tt>true</tt> if the subject with the id of <tt>subjectIdentifier</tt> has the role
     * with the id of <tt>roleIdentifier</tt>, <tt>false</tt> otherwise.
     *
     * <p>In most systems, the <tt>subjectIdentifier</tt> is usually a <tt>User</tt> database primary
     * key or a String username, and the <tt>roleIdentifier</tt> is usually a <tt>Role</tt> entity's
     * primary key or a String role name.
     *
     * <p>The runtime values of the method arguments are specific to the application and
     * determined by the application's JSecurity RI configuration.
     *
     * @param subjectIdentifier the application-specific identifier for the subject to check for
     * role association (usually a user id or username).
     * @param roleIdentifier the application-specific identifier of the role to check for
     * association with a subject (usually a role id or role name ).
     * @return <tt>true</tt> if the subject with the id of <tt>subjectIdentifier</tt> has the role
     * with the id of <tt>roleIdentifier</tt>, <tt>false</tt> otherwise.
     */
    boolean hasRole( Serializable subjectIdentifier, Serializable roleIdentifier );

    /**
     * Checks to see if the roles with the given identifiers are associated with the subject (user)
     * with the given identifier and returns a boolean array indicating which
     * roles are associated with the given subject.
     *
     * <p>This is primarily a performance-enhancing method to help reduce the number of
     * {@link #hasRole} invocations over the wire in client/server systems.
     *
     * <p>In most systems, the <tt>subjectIdentifier</tt> is usually a <tt>User</tt> database primary
     * key or a String username, and <tt>roleIdentifiers</tt> is usually a List of <tt>Role</tt>
     * entity primary keys or a String role names.
     *
     * <p>The runtime values of the method arguments are specific to the application and
     * determined by the application's JSecurity RI configuration.
     *
     * @param subjectIdentifier the identity of the subject to check for role association
     * @param roleIdentifiers the identifiers of the roles to check for.
     * @return an array of booleans whose indices correspond to the index of the
     * roles in the given identifiers.  A true value indicates the user has the
     * role at that index.  False indicates the user does not have the role.
     */
    boolean[] hasRoles( Serializable subjectIdentifier, List<String> roleIdentifiers );

    /**
     * Returns <tt>true</tt> if the subject with the given <tt>subjectIdentifier</tt> has all the
     * roles with the given identifiers, <tt>false</tt> otherwise.
     *
     * <p>In most systems, the <tt>subjectIdentifier</tt> is usually a <tt>User</tt> database primary
     * key or a String username, and <tt>roleIdentifiers</tt> is usually a List of <tt>Role</tt>
     * entity primary keys or a String role names.
     *
     * <p>The runtime values of the method arguments are specific to the application and
     * determined by the application's JSecurity RI configuration.
     *
     * @param subjectIdentifier the id of the subject to check for role associations
     * @param roleIdentifiers the roles to be checked.
     * @return true if the user has all roles, false otherwise.
     */
    boolean hasAllRoles( Serializable subjectIdentifier, Collection<String> roleIdentifiers );

    /**
     * Returns <tt>true</tt> if the subject with the given <tt>subjectIdentifier</tt> is
     * permitted to perform an action or access a resource summarized by the specified permission.
     *
     * <p>More specifically, this method should determine if any <tt>Permission</tt>s associated
     * with the subject {@link Permission#implies(java.security.Permission) imply} the
     * specified permission.
     *
     * <p>In most systems, the <tt>subjectIdentifier</tt> is usually a <tt>User</tt> database primary
     * key or a String username.  The runtime value of the <tt>subjectIdentifier</tt>
     * is specific to the application and
     * determined by the application's JSecurity RI configuration.
     *
     * @param subjectIdentifier the id of the subject to check
     * @param permission the permission that is being checked.
     * @return true if the user associated with this context has the permission, false otherwise.
     */
    boolean isPermitted( Serializable subjectIdentifier, Permission permission );

    /**
     * Checks a collection of permissions to see if they are associated with the subject with
     * the given <tt>subjectIdentifier</tt> and and returns a boolean array indicating which
     * permissions are associated with the subject.
     *
     * <p>More specifically, this method should determine if each <tt>Permission</tt> in
     * the array is {@link Permission#implies(java.security.Permission) implied by} permissions
     * already associated with the subject.
     *
     * <p>This is primarily a performance-enhancing method to help reduce the number of
     * {@link #isPermitted} invocations over the wire in client/server systems.
     *
     * <p>In most systems, the <tt>subjectIdentifier</tt> is usually a <tt>User</tt> database primary
     * key or a String username.  The runtime value of the <tt>subjectIdentifier</tt>
     * is specific to the application and
     * determined by the application's JSecurity RI configuration.
     *
     * @param subjectIdentifier the id of the subject to check
     * @param permissions the permissions to check for.
     * @return an array of booleans whose indices correspond to the index of the
     * permissions in the given list.  A true value indicates the user has the
     * permission at that index.  False indicates the user does not have the role.
     */
    boolean[] isPermitted( Serializable subjectIdentifier, List<Permission> permissions );

    /**
     * Checks if the the subject with the given <tt>subjectIdentifier</tt> implies all the
     * specified permissions.
     *
     * <p>More specifically, this method should determine if <em>all</em> of the given
     * <tt>Permission</tt>s are {@link Permission#implies(java.security.Permission) implied by}
     * permissions already associated with the subject.
     *
     * <p>In most systems, the <tt>subjectIdentifier</tt> is usually a <tt>User</tt> database primary
     * key or a String username.  The runtime value of the <tt>subjectIdentifier</tt>
     * is specific to the application and
     * determined by the application's JSecurity RI configuration.
     * @param subjectIdentifier the id of the subject to check
     * @param permissions the permissions to be checked.
     * @return true if the user has all permissions, false otherwise.
     */
    boolean isPermittedAll( Serializable subjectIdentifier, Collection<Permission> permissions );


    /**
     * A convenience method to ensure a subject (and/or user)
     * {@link Permission#implies(java.security.Permission) implies} the specified <tt>Permission</tt>.
     * If the subject's exisiting associated permissions do not
     * {@link Permission#implies(java.security.Permission) imply} the given permission,
     * an {@link org.jsecurity.authz.AuthorizationException} will be thrown.
     *
     * <p>In most systems, the <tt>subjectIdentifier</tt> is usually a <tt>User</tt> database primary
     * key or a String username.  The runtime value of the <tt>subjectIdentifier</tt>
     * is specific to the application and
     * determined by the application's JSecurity RI configuration.
     *
     * @param subjectIdentifier the id of the subject to check
     * @param permission the permission to check.
     * @throws org.jsecurity.authz.AuthorizationException if the user does not have the permission.
     */
    void checkPermission( Serializable subjectIdentifier, Permission permission ) throws AuthorizationException;


    /**
     * A convenience method to ensure a subject (and/or user)
     * {@link Permission#implies(java.security.Permission) implies} <em>all</em> of the
     * specified <tt>Permission</tt>s.
     * If the subject's exisiting associated permissions do not
     * {@link Permission#implies(java.security.Permission) imply} <em>all</em> of the given permissions,
     * an {@link org.jsecurity.authz.AuthorizationException} will be thrown.
     * @param subjectIdentifier the id of the subject to check
     * @param permissions the permissions to check.
     * @throws AuthorizationException if the user does not have all of the given
     * permissions.
     */
    void checkPermissions( Serializable subjectIdentifier, Collection<Permission> permissions ) throws AuthorizationException;

}
