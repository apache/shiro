/*
 * Copyright (C) 2005 Jeremy Haile
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

package org.jsecurity.ri.authc.password;

/**
 * Description of class.
 *
 * @since 0.1
 * @author Jeremy Haile
 */
public class PlainTextPasswordMatcher implements PasswordMatcher {


    public boolean doPasswordsMatch(char[] providedPassword, char[] storedPassword) {
        if( providedPassword.length != storedPassword.length ) {
            return false;
        }

        for( int i = 0; i < providedPassword.length; i++ ) {
            if( providedPassword[i] != storedPassword[i] ) {
                return false;
            }
        }
        return true;
    }
}