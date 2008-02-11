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

import org.jsecurity.authc.Account;
import org.jsecurity.authc.AuthenticationToken;
import org.jsecurity.authc.UsernamePasswordToken;
import org.jsecurity.authc.credential.CredentialsMatcher;
import org.jsecurity.authc.support.SimpleAccount;
import org.jsecurity.codec.CodecSupport;

import java.util.Arrays;

/**
 * Simple CredentialsMatcher implementation.  Supports direct comparison for credentials of type
 * byte[], char[], and Strings.  This includes plain text matching.
 *
 * @author Les Hazlewood
 * @since 1.0
 */
public class SimpleCredentialsMatcher extends CodecSupport implements CredentialsMatcher {

    protected Object getCredentials( AuthenticationToken token ) {
        return token.getCredentials();
    }

    protected Object getCredentials( Account account ) {
        return account.getCredentials();
    }

    protected boolean equals( Object tokenCredentials, Object accountCredentials ) {
        if ( tokenCredentials.getClass().isArray() || accountCredentials.getClass().isArray() ) {
            try {
                byte[] tokenBytes = toBytes( tokenCredentials );
                byte[] accountBytes = toBytes( accountCredentials );
                return Arrays.equals( tokenBytes, accountBytes );
            } catch (Exception e) {
                if ( log.isWarnEnabled() ) {
                    log.warn( "token credentials or account credentials could not be properly converted into " +
                            "a byte array (byte[]) before equals comparison.", e);
                }
            }
        }
        return tokenCredentials.equals(accountCredentials);
    }

    public boolean doCredentialsMatch(AuthenticationToken token, Account account) {
        Object tokenCredentials = getCredentials( token );
        Object accountCredentials = getCredentials( account );
        return equals( tokenCredentials, accountCredentials );
    }

    public static void main( String[] args ) {
        SimpleCredentialsMatcher matcher = new SimpleCredentialsMatcher();
        AuthenticationToken token = new UsernamePasswordToken( "user1", "blah" );
        Account account = new SimpleAccount( "user1", toBytes("blah") );
        boolean matches = matcher.doCredentialsMatch(token, account);
        System.out.println("Principals match? " + matches );
    }


}
