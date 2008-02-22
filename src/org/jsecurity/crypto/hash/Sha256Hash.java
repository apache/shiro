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
 * Generates an SHA-256 Hash from a given input <tt>source</tt> with an optional <tt>salt</tt> and hash iterations.
 *
 * <p>See the {@link AbstractHash AbstractHash} parent class JavaDoc for a detailed explanation of Hashing
 * techniques and how the overloaded constructors function.
 *
 * <p><b>JDK Version Note</b> - Attempting to instantiate this class on JREs prior to version 1.4.0 will throw
 * an {@link IllegalStateException IllegalStateException}
 *
 * @author Les Hazlewood
 * @since 0.9
 */
public class Sha256Hash extends AbstractHash {

    public static final String ALGORITHM_NAME = "SHA-256";

    public Sha256Hash() {
    }

    public Sha256Hash(Object source) {
        super(source);
    }

    public Sha256Hash(Object source, Object salt) {
        super(source, salt);
    }

    public Sha256Hash(Object source, Object salt, int hashIterations) {
        super(source, salt, hashIterations);
    }

    protected String getAlgorithmName() {
        return ALGORITHM_NAME;
    }

    public static Sha256Hash fromHexString(String hex) {
        Sha256Hash hash = new Sha256Hash();
        hash.setBytes(Hex.decode(hex));
        return hash;
    }

    public static Sha256Hash fromBase64String(String base64) {
        Sha256Hash hash = new Sha256Hash();
        hash.setBytes(Base64.decodeBase64(base64));
        return hash;
    }



}
