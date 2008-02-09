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
 * @author Les Hazlewood
 * @since 1.0
 */
public class ShaHash extends AbstractHash {

    public static final String ALGORITHM_NAME = "SHA";

    public ShaHash() {
    }

    public ShaHash(Object source) {
        super( source );
    }

    public ShaHash(Object source, Object salt) {
        super(source, salt);
    }

    public ShaHash(Object source, Object salt, int hashIterations) {
        super(source, salt, hashIterations);
    }

    public String getAlgorithmName() {
        return ALGORITHM_NAME;
    }

    public static ShaHash fromHexString( String hex ) {
        ShaHash hash = new ShaHash();
        hash.setBytes( Hex.decode( hex ) );
        return hash;
    }

    public static ShaHash fromBase64String( String base64 ) {
        ShaHash hash = new ShaHash();
        hash.setBytes( Base64.decodeBase64( base64 ) );
        return hash;
    }
}
