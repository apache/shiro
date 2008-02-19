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
package org.jsecurity.crypto.hash;

import org.jsecurity.codec.Base64;
import org.jsecurity.codec.Hex;

/**
 * Generates an SHA-512 Hash from a given input <tt>source</tt> with an optional <tt>salt</tt> and hash iterations.
 *
 * <p>See the {@link AbstractHash AbstractHash} parent class JavaDoc for a detailed explanation of Hashing
 * techniques and how the overloaded constructors function.
 *
 * <p><b>JDK Version Note</b> - Attempting to instantiate this class on JREs prior to version 1.4.0 will throw
 * an {@link IllegalStateException IllegalStateException} 
 *
 * @author Les Hazlewood
 * @since 1.0
 */
public class Sha512Hash extends AbstractHash {

    public static final String ALGORITHM_NAME = "SHA-512";

    public Sha512Hash() {
    }

    public Sha512Hash(Object source) {
        super(source);
    }

    public Sha512Hash(Object source, Object salt) {
        super(source, salt);
    }

    public Sha512Hash(Object source, Object salt, int hashIterations) {
        super(source, salt, hashIterations);
    }

    protected String getAlgorithmName() {
        return ALGORITHM_NAME;
    }

    public static Sha512Hash fromHexString(String hex) {
        Sha512Hash hash = new Sha512Hash();
        hash.setBytes(Hex.decode(hex));
        return hash;
    }

    public static Sha512Hash fromBase64String(String base64) {
        Sha512Hash hash = new Sha512Hash();
        hash.setBytes(Base64.decodeBase64(base64));
        return hash;
    }



}

