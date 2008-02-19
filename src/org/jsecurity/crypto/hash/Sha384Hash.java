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
 * Generates an SHA-384 Hash from a given input <tt>source</tt> with an optional <tt>salt</tt> and hash iterations.
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
public class Sha384Hash extends AbstractHash {

    public static final String ALGORITHM_NAME = "SHA-384";

    public Sha384Hash() {
    }

    public Sha384Hash(Object source) {
        super(source);
    }

    public Sha384Hash(Object source, Object salt) {
        super(source, salt);
    }

    public Sha384Hash(Object source, Object salt, int hashIterations) {
        super(source, salt, hashIterations);
    }

    protected String getAlgorithmName() {
        return ALGORITHM_NAME;
    }

    public static Sha384Hash fromHexString(String hex) {
        Sha384Hash hash = new Sha384Hash();
        hash.setBytes(Hex.decode(hex));
        return hash;
    }

    public static Sha384Hash fromBase64String(String base64) {
        Sha384Hash hash = new Sha384Hash();
        hash.setBytes(Base64.decodeBase64(base64));
        return hash;
    }



}
