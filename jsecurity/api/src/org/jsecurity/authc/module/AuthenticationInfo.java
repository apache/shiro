/*
 * Copyright (C) 2005 Jeremy C. Haile, Les Hazlewood
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

package org.jsecurity.authc.module;

import java.security.Permission;
import java.security.Principal;
import java.util.Collection;
import java.util.List;

/**
 * An <tt>AuthenticationInfo</tt> implementation represents system-specific account/user information
 * in a framework-independent manner.  Instead of forcing a JSecurity user to
 * implement <tt>User</tt> or <tt>Role</tt> interfaces and being invasive on an application's
 * data model, the application must instead only implement this interface to represent such
 * data.  This enables a cleaner pluggable implementation and abstracts an application's
 * core classes away from JSecurity.
 *
 * @since 0.1
 * @author Jeremy Haile
 * @author Les Hazlewood
 */
public interface AuthenticationInfo {

    /**
     * Returns the primary principal associated with this authentication info.
     * @return the primary principal associated with this authentication info.
     */
    Principal getPrincipal();


    /**
     * The principals that identify of the authenticated subject.  These principal are often
     * a representation of a user's primary key id or username.  The first principal in this list
     * will be interpreted as the primary principal.
     *
     * @return the identifying principal of the authenticated subject.
     */
    List<Principal> getPrincipals();

    /**
     * The subject's credential as stored in the system associated with the
     * {@link #getPrincipals() subject identifier}, such as a password char array or
     * public key.
     *
     * <p>It could be encrypted in which case an
     * {@link org.jsecurity.authc.module.AuthenticationModule AuthenticationModule}
     * must be aware of the fact (e.g. via configuration) in order to interpret and compare
     * the credentials value.
     *
     * @return the subject's credential verifying the {@link #getPrincipals() identifier}
     */
    Object getCredentials();

    /**
     * A collection of role identifiers that represent the roles that this
     * user is a member of.  These roles will be used to determine the
     * authorization privileges of the user being authenticated.
     * @return a collection of role identifiers (typically <tt>String</tt>
     * names of roles)
     */
    Collection<String> getRoles();

    /**
     * A collection of permissions that represent the permission that this
     * user is authorized for.  These permissions will be used to determine the
     * authorization privileges of the user being authenticated.  It is legal
     * for this collection to be empty if the underlying DAO does not support
     * looking up permission (for example, in applications that simply use
     * role-based authorization.
     * @return a collection of {@link Permission} objects.
     */
    Collection<Permission> getPermissions();

    /**
     * Determines if the user's account is locked, meaning that the user is
     * not allowed to log in due to a manual or automatic lockout.
     * @return true if the user's account is locked and the user should be
     * denied authorization, false otherwise.
     */
    boolean isAccountLocked();


    /**
     * Determines if the user's credentials (password) has expired and must be
     * changed before login is allowed.
     * @return true if the user's credentials are expired and the user should
     * be denied authentication, false otherwise.
     */
    boolean isCredentialsExpired();


    /**
     * Determines if the user is allowed to concurrently login from two
     * unique sessions.  For example, if Joe needs the ability to leave
     * an account logged in at home and still log in from work, then
     * concurrent logins should be enabled.  This feature is mainly intended
     * to prevent account sharing where a user distributes his password to
     * others who log in concurrently.
     * @return true if the user should be allowed to login concurrently,
     * false otherwise.
     */
    boolean isConcurrentLoginsAllowed();

}