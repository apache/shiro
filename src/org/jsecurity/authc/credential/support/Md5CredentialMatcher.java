/*
 * Copyright (C) 2005-2008 Les Hazlewood
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
package org.jsecurity.authc.credential.support;

import org.jsecurity.crypto.Hash;
import org.jsecurity.crypto.support.AbstractHash;
import org.jsecurity.crypto.support.Md5Hash;

/**
 * @author Les Hazlewood
 * @since 1.0
 */
public class Md5CredentialMatcher extends HashedCredentialMatcher {

    protected AbstractHash newHashInstance() {
        return new Md5Hash();
    }

    protected Hash getProvidedCredentialsHash(Object credential) {
        return new Md5Hash( toBytes( credential ) );
    }

    public static void main( String[] args ) {
        char[] password = "foobar".toCharArray();

        Md5Hash hash = new Md5Hash( password );
        String hashString = hash.toString();

        Md5CredentialMatcher matcher = new Md5CredentialMatcher();

        if ( matcher.doCredentialsMatch( password, hashString ) ) {
            System.out.println("Passwords match.");
        } else {
            System.out.println("Passwords do not match!" );
        }
    }
}
