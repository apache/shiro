/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.shiro.crypto.hash.format;

import org.apache.shiro.crypto.hash.AbstractCryptHash;
import org.apache.shiro.crypto.hash.Hash;
import org.apache.shiro.crypto.hash.HashProvider;
import org.apache.shiro.crypto.hash.HashSpi;
import org.apache.shiro.crypto.hash.SimpleHash;

import static java.util.Objects.requireNonNull;

/**
 * The {@code Shiro1CryptFormat} is a fully reversible
 * <a href="http://packages.python.org/passlib/modular_crypt_format.html">Modular Crypt Format</a> (MCF). It is based
 * on the posix format for storing KDF-hashed passwords in {@code /etc/shadow} files on linux and unix-alike systems.
 * <h2>Format</h2>
 * <p>Hash instances formatted with this implementation will result in a String with the following dollar-sign ($)
 * delimited format:</p>
 * <pre>
 * <b>$</b>mcfFormatId<b>$</b>algorithmName<b>$</b>algorithm-specific-data.
 * </pre>
 * <p>Each token is defined as follows:</p>
 * <table>
 *     <tr>
 *         <th>Position</th>
 *         <th>Token</th>
 *         <th>Description</th>
 *         <th>Required?</th>
 *     </tr>
 *     <tr>
 *         <td>1</td>
 *         <td>{@code mcfFormatId}</td>
 *         <td>The Modular Crypt Format identifier for this implementation, equal to <b>{@code shiro2}</b>.
 *             ( This implies that all {@code shiro2} MCF-formatted strings will always begin with the prefix
 *             {@code $shiro2$} ).</td>
 *         <td>true</td>
 *     </tr>
 *     <tr>
 *         <td>2</td>
 *         <td>{@code algorithmName}</td>
 *         <td>The name of the hash algorithm used to perform the hash. Either a hash class exists, or
 *         otherwise a {@link UnsupportedOperationException} will be thrown.
 *         <td>true</td>
 *     </tr>
 *     <tr>
 *         <td>3</td>
 *         <td>{@code algorithm-specific-data}</td>
 *         <td>In contrast to the previous {@code shiro1} format, the shiro2 format does not make any assumptions
 *         about how an algorithm stores its data. Therefore, everything beyond the first token is handled over
 *         to the Hash implementation.</td>
 *     </tr>
 * </table>
 *
 * @see ModularCryptFormat
 * @see ParsableHashFormat
 * @since 2.0.0
 */
public class Shiro2CryptFormat implements ModularCryptFormat, ParsableHashFormat {

    public static final String ID = "shiro2";
    public static final String MCF_PREFIX = TOKEN_DELIMITER + ID + TOKEN_DELIMITER;

    public Shiro2CryptFormat() {
    }

    @Override
    public String getId() {
        return ID;
    }

    /**
     * Converts a Hash-extending class to a string understood by the hash class. Usually this string will follow
     * posix standards for passwords stored in {@code /etc/passwd}.
     *
     * <p>This method should only delegate to the corresponding formatter and prepend {@code $shiro2$}.</p>
     *
     * @param hash the hash instance to format into a String.
     * @return a string representing the hash.
     */
    @Override
    public String format(final Hash hash) {
        requireNonNull(hash, "hash in Shiro2CryptFormat.format(Hash hash)");

        // backwards compatibility until Shiro 2.1.0.
        if (hash instanceof SimpleHash) {
            return new Shiro1CryptFormat().format(hash);
        }

        if (!(hash instanceof AbstractCryptHash)) {
            throw new UnsupportedOperationException("Shiro2CryptFormat can only format classes extending AbstractCryptHash.");
        }

        AbstractCryptHash cryptHash = (AbstractCryptHash) hash;
        return TOKEN_DELIMITER + ID + cryptHash.formatToCryptString();
    }

    @Override
    public Hash parse(final String formatted) {
        requireNonNull(formatted, "formatted in Shiro2CryptFormat.parse(String formatted)");

        // backwards compatibility until Shiro 2.1.0.
        if (formatted.startsWith(Shiro1CryptFormat.MCF_PREFIX)) {
            return new Shiro1CryptFormat().parse(formatted);
        }

        if (!formatted.startsWith(MCF_PREFIX)) {
            final String msg = "The argument is not a valid '" + ID + "' formatted hash.";
            throw new IllegalArgumentException(msg);
        }

        final String suffix = formatted.substring(MCF_PREFIX.length());
        final String[] parts = suffix.split("\\$");
        final String algorithmName = parts[0];

        HashSpi kdfHash = HashProvider.getByAlgorithmName(algorithmName)
                .orElseThrow(() -> new UnsupportedOperationException("Algorithm " + algorithmName + " is not implemented."));
        return kdfHash.fromString("$" + suffix);
    }

}
