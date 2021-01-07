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
import org.apache.shiro.crypto.hash.Argon2Hash;
import org.apache.shiro.crypto.hash.BCryptHash;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.StringJoiner;
import java.util.function.Function;

import static java.util.Collections.unmodifiableList;

/**
 * Hashes used by the Shiro2CryptFormat class.
 */
public enum ProvidedKdfHashes {
    ARGON2(
            new String[]{"argon2id", "argon2i", "argon2d"},
            Argon2Hash::fromString
    ),
    BCRYPT(
            new String[]{"2", "2y", "2a", "2b"},
            BCryptHash::fromString
    );

    private final List<String> recognizedAlgorithms;

    private final Function<String, AbstractCryptHash> fromStringMethod;

    ProvidedKdfHashes(String[] recognizedAlgorithms, Function<String, AbstractCryptHash> fromStringMethod) {
        this.recognizedAlgorithms = unmodifiableList(Arrays.asList(recognizedAlgorithms));
        this.fromStringMethod = fromStringMethod;
    }

    public static Optional<ProvidedKdfHashes> getByAlgorithmName(String algorithmName) {
        return Arrays.stream(values())
                .filter(val -> val.getRecognizedAlgorithms().contains(algorithmName))
                .findAny();
    }

    public List<String> getRecognizedAlgorithms() {
        return recognizedAlgorithms;
    }

    public Function<String, AbstractCryptHash> getFromStringMethod() {
        return fromStringMethod;
    }

    public AbstractCryptHash fromString(String input) {
        return getFromStringMethod().apply(input);
    }

    @Override
    public String toString() {
        return new StringJoiner(", ", ProvidedKdfHashes.class.getSimpleName() + "[", "]")
                .add("super=" + super.toString())
                .add("recognizedAlgorithms=" + recognizedAlgorithms)
                .add("fromStringMethod=" + fromStringMethod)
                .toString();
    }
}
