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

package org.jsecurity.ri.authc.module;

import org.jsecurity.authc.module.AuthenticationModule;

import java.util.Set;

/**
 * A <tt>PluggableAuthenticator</tt> is an {@link org.jsecurity.authc.Authenticator Authenticator}
 * that delgates authentication duties to a pluggable collection
 * {@link AuthenticationModule AuthenticationModule}s.
 *
 * <p>Using this Authenticator allows you to &quot;plug-in&quot; your own
 * <tt>AuthenticationModule</tt>s as you see fit.
 *
 * @since 0.1
 * @author Jeremy Haile
 * @author Les Hazlewood
 */
public class PluggableAuthenticator {

    /*--------------------------------------------
    |             C O N S T A N T S             |
    ============================================*/

    /*--------------------------------------------
    |    I N S T A N C E   V A R I A B L E S    |
    ============================================*/
    private Set<AuthenticationModule> modules;

    /*--------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*/

    /*--------------------------------------------
    |  A C C E S S O R S / M O D I F I E R S    |
    ============================================*/

    /*--------------------------------------------
    |               M E T H O D S               |
    ============================================*/
}