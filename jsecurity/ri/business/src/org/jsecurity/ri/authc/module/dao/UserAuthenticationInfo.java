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

import java.io.Serializable;
import java.util.Collection;

/**
 * An interface containing the information required by the {@link org.jsecurity.ri.authc.module.dao.DAOAuthenticationModule}
 * to authenticate a user and construct a {@link org.jsecurity.authz.AuthorizationContext} for the user.
 *
 * @see org.jsecurity.ri.authc.module.dao.DAOAuthenticationModule
 *
 * @since 0.1
 * @author Jeremy Haile
 */
public interface UserAuthenticationInfo {

    public String getUsername();

    public String getPassword();

    public Collection<Serializable> getRoles();

    public boolean isAccountLocked();

    public boolean isCredentialsExpired();

    public boolean isUserLoggedIn();

}