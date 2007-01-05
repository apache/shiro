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

package org.jsecurity.authz.module;


/**
 * Enumeration representing the possible votes that can be returned from an
 * {@link AuthorizationModule} instance to vote on whether or not a user
 * should be authorized to perform a particular {@link org.jsecurity.authz.AuthorizedAction}.
 *
 * @see AuthorizationModule
 *
 * @since 0.1
 * @author Jeremy Haile
 * @author Les Hazlewood
 */
public enum AuthorizationVote {

    /**
     * Vote that indicates that a module abstains from voting on whether
     * or not a user should be granted authorization.
     */
    abstain,

    /**
     * Vote that indicates that a module grants authorization to the user.
     */
    grant,

    /**
     * Vote that indicates that a module denies authorization to the user.
     */
    deny

}