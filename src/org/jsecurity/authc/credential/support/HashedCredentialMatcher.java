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

import org.jsecurity.authc.credential.CredentialMatcher;
import org.jsecurity.crypto.Hash;
import org.jsecurity.util.EncodingSupport;

/**
 * @author Les Hazlewood
 * @since 1.0
 */
public abstract class HashedCredentialMatcher extends EncodingSupport implements CredentialMatcher {

    protected byte[] toBytes( Object o ) {
        if ( o instanceof byte[] ) {
            return (byte[])o;
        } else if ( o instanceof char[] ) {
            return toBytes( (char[])o );
        } else if ( o instanceof String ) {
            return toBytes( (String)o );
        } else {
            String msg = "The " + getClass().getName() + " implementation only supports " +
                "credentials of type byte[], char[] or String.";
            throw new IllegalArgumentException( msg );
        }
    }

    public boolean doCredentialsMatch(Object providedCredential, Object storedCredential) {
        Hash provided = getProvidedCredentialHash( providedCredential );
        Hash stored = getStoredCredentialHash( storedCredential );
        return stored.equals( provided );
    }

    protected abstract Hash getStoredCredentialHash( Object credential );
    protected abstract Hash getProvidedCredentialHash( Object credential );
}
