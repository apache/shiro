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

import org.apache.shiro.crypto.hash.BCryptHash;
import org.apache.shiro.crypto.hash.Hash;
import org.apache.shiro.lang.codec.OpenBSDBase64;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Optional;
import java.util.StringJoiner;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static java.util.Objects.requireNonNull;

public class UnixCryptFormat implements ModularCryptFormat<BCryptHash>, ParsableHashFormat<BCryptHash> {

    private static final String ID = "unixcrypt";
    private static final List<String> BCRYPT_IDS = Arrays.asList("2", "2a", "2b", "2y");
    private static final List<String> BCRYPT_PREFIXES = createPrefixes();

    private static final String DELIMITER_CHAR = "$";
    private static final Pattern DELIMITER = Pattern.compile("\\" + DELIMITER_CHAR);

    private static List<String> createPrefixes() {
        final List<String> prefixes = BCRYPT_IDS.stream()
                .map(id -> TOKEN_DELIMITER + id + TOKEN_DELIMITER)
                .collect(Collectors.toList());

        return Collections.unmodifiableList(prefixes);
    }

    @Override
    public String getId() {
        return ID;
    }


    @Override
    public String format(final BCryptHash hash) {
        return "$" + ID + this.getCanonicalFormat(hash);

    }

    protected String getCanonicalFormat(final Hash hash) {
        final String algorithmName = requireNonNull(hash).getAlgorithmName();

        if (!BCRYPT_IDS.contains(algorithmName)) {
            final String msg = "AlgorithmName [" + algorithmName + "] is not a valid bcrypt algorithm."
                    + "Allowed values: [" + BCRYPT_IDS + "].";
            throw new IllegalArgumentException(msg);
        }

        final OpenBSDBase64.Default bcryptBase64 = new OpenBSDBase64.Default();
        final String saltHex = new String(bcryptBase64.encode(hash.getSalt().getBytes()), StandardCharsets.ISO_8859_1);
        final byte[] bytes = hash.getBytes();
        final String byteHex = new String(bcryptBase64.encode(bytes), StandardCharsets.ISO_8859_1)
                .replace('+', '.');

        return new StringJoiner(DELIMITER_CHAR, DELIMITER_CHAR, "")
                .add(algorithmName)
                .add("" + hash.getIterations())
                .add(saltHex + byteHex)
                .toString();
    }

    @Override
    public Hash parse(final String formatted) {
        requireNonNull(formatted);
        if (!formatted.startsWith("$" + ID + "$")) {
            final String msg = "The argument is not a valid bcrypt formatted hash. "
                    + "Expected to start with $" + ID + "$ but was " + formatted + ".";
            throw new IllegalArgumentException(msg);
        }

        final String canonicalFormat = formatted.substring(formatted.indexOf("$", 1));

        final Optional<String> matchedPrefix = BCRYPT_PREFIXES.stream()
                .filter(canonicalFormat::startsWith)
                .findAny();
        if (!matchedPrefix.isPresent()) {
            final String msg = "The argument is not a valid bcrypt formatted hash. "
                    + "Expected canconical form to start with any of " + BCRYPT_IDS
                    + ", but found " + canonicalFormat + ".";
            throw new IllegalArgumentException(msg);
        }

        final String prefix = matchedPrefix.orElseThrow(NoSuchElementException::new);
        final String id = prefix.substring(1, prefix.length() - 1);
        final String suffix = canonicalFormat.substring(canonicalFormat.indexOf(DELIMITER_CHAR, 1) + 1);
        final String[] parts = DELIMITER.split(suffix);

        final String costString = parts[0];
        final String saltHashBase64String = parts[1];

        // The first 22 characters decode to a 16-byte value for the salt.
        final OpenBSDBase64.Default bcryptBase64 = new OpenBSDBase64.Default();
        final byte[] salt = bcryptBase64.decode(saltHashBase64String.substring(0, 22).getBytes(StandardCharsets.ISO_8859_1));
        // The remaining characters are cipher text to be compared for authentication.
        final String hashString = saltHashBase64String.substring(22).trim();
        final byte[] hash = bcryptBase64.decode(hashString.getBytes(StandardCharsets.ISO_8859_1));

        return new BCryptHash(id, salt, hash, Integer.parseInt(costString, 10));
    }
}
