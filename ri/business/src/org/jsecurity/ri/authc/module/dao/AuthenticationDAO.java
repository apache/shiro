/*
 * Copyright (C) 2005 Jeremy C. Haile
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

package org.jsecurity.ri.authc.module.dao;

import org.jsecurity.authc.module.AuthenticationInfo;

import java.security.Principal;

/**
 * <p>Interface used by the {@link DAOAuthenticationModule} to retrieve information
 * required to authenticate and determine authorization information for a particular
 * user identity.  Several existing implementations of this interface are provided with
 * the JSecurity RI.</p>
 *
 * <p>Applications adopting JSecurity that already store user
 * principals (usernames), credentials (passwords), and authorization information
 * in the data store should implement this interface on their own to
 * retrieve the user's authentication info (e.g. using JDBC, Hibernate, etc).</p>
 *
 * @see MemoryAuthenticationDAO
 *
 * @deprecated New implementations should subclass the AbstractAuthenticationModule or 
 * one of its children instead of implementing this interface.
 *
 * @since 0.1
 * @author Jeremy Haile
 */
public interface AuthenticationDAO {

    /**
     * Retrieves authentication information from a data store for the
     * given account identity.
     *
     * @param subjectIdentity the primary identifying attribute of the account being authenticated.
     * This is usually a Principal representing a user id or user name.
     * @return a {@link org.jsecurity.authc.module.AuthenticationInfo} object containing the information
     * necessary to authenticate the identity and build an
     * {@link org.jsecurity.authz.AuthorizationContext}
     */
    public AuthenticationInfo getAuthenticationInfo( Principal subjectIdentity ) throws Exception;

}