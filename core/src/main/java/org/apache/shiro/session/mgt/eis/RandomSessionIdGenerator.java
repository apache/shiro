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
package org.apache.shiro.session.mgt.eis;

import org.apache.shiro.session.Session;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Serializable;
import java.util.Random;

/**
 * Generates session IDs by using a {@link Random} instance to generate random IDs. The default {@code Random}
 * implementation is a {@link java.security.SecureRandom SecureRandom} with the {@code SHA1PRNG} algorithm.
 *
 * @since 1.0
 */
public class RandomSessionIdGenerator implements SessionIdGenerator {

    private static final Logger log = LoggerFactory.getLogger(RandomSessionIdGenerator.class);

    private static final String RANDOM_NUM_GENERATOR_ALGORITHM_NAME = "SHA1PRNG";
    private Random random;

    public RandomSessionIdGenerator() {
        try {
            this.random = java.security.SecureRandom.getInstance(RANDOM_NUM_GENERATOR_ALGORITHM_NAME);
        } catch (java.security.NoSuchAlgorithmException e) {
            log.debug("The SecureRandom SHA1PRNG algorithm is not available on the current platform.  Using the " +
                    "platform's default SecureRandom algorithm.", e);
            this.random = new java.security.SecureRandom();
        }
    }

    public Random getRandom() {
        return this.random;
    }

    public void setRandom(Random random) {
        this.random = random;
    }

    /**
     * Returns the String value of the configured {@link Random}'s {@link Random#nextLong() nextLong()} invocation.
     *
     * @param session the {@link Session} instance to which the ID will be applied.
     * @return the String value of the configured {@link Random}'s {@link Random#nextLong()} invocation.
     */
    public Serializable generateId(Session session) {
        //ignore the argument - just call the Random:
        return Long.toString(getRandom().nextLong());
    }
}
