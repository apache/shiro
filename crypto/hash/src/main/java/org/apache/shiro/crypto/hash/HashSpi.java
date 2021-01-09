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

package org.apache.shiro.crypto.hash;

import java.util.Random;
import java.util.Set;

/**
 * @since 2.0.0
 */
public interface HashSpi<T extends Hash> {

    Class<T> getImplementationClass();

    Set<String> getImplementedAlgorithms();

    T fromString(String format);

    /**
     * A factory class for the hash of the type {@code <T>}.
     *
     * <p>Implementations are highly encouraged to use the given random parameter as
     * source of random bytes (e.g. for seeds).</p>
     *
     * @param random a source of {@link Random}, usually {@code SecureRandom}.
     * @return a factory class for creating instances of {@code <T>}.
     */
    HashFactory<T> newHashFactory(Random random);

    interface HashFactory<T extends Hash> {

        T generate(HashRequest hashRequest);
    }
}
