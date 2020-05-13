/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.shiro.crypto.hash;

import org.apache.shiro.lang.util.ByteSource;

/**
 * A {@code HashRequest} is composed of data that will be used by a {@link HashService} to compute a hash (aka
 * 'digest').  While you can instantiate a concrete {@code HashRequest} class directly, most will find using the
 * {@link HashRequest.Builder} more convenient.
 *
 * @see HashRequest.Builder
 * @since 1.2
 */
public interface HashRequest {

    /**
     * Returns the source data that will be hashed by a {@link HashService}. For example, this might be a
     * {@code ByteSource} representation of a password, or file, etc.
     *
     * @return the source data that will be hashed by a {@link HashService}.
     */
    ByteSource getSource();

    /**
     * Returns a salt to be used by the {@link HashService} during hash computation, or {@code null} if no salt is
     * provided as part of the request.
     * <p/>
     * Note that a {@code null} value does not necessarily mean a salt won't be used at all - it just
     * means that the request didn't include one.  The servicing {@link HashService} is free to provide a salting
     * strategy for a request, even if the request did not specify one.
     *
     * @return a salt to be used by the {@link HashService} during hash computation, or {@code null} if no salt is
     *         provided as part of the request.
     */
    ByteSource getSalt();

    /**
     * Returns the number of requested hash iterations to be performed when computing the final {@code Hash} result.
     * A non-positive (0 or less) indicates that the {@code HashService}'s default iteration configuration should
     * be used.  A positive value overrides the {@code HashService}'s configuration for a single request.
     * <p/>
     * Note that a {@code HashService} is free to ignore this number if it determines the number is not sufficient
     * to meet a desired level of security.
     *
     * @return the number of requested hash iterations to be performed when computing the final {@code Hash} result.
     */
    int getIterations();

    /**
     * Returns the name of the hash algorithm the {@code HashService} should use when computing the {@link Hash}, or
     * {@code null} if the default algorithm configuration of the {@code HashService} should be used.  A non-null value
     * overrides the {@code HashService}'s configuration for a single request.
     * <p/>
     * Note that a {@code HashService} is free to ignore this value if it determines that the algorithm is not
     * sufficient to meet a desired level of security.
     *
     * @return the name of the hash algorithm the {@code HashService} should use when computing the {@link Hash}, or
     *         {@code null} if the default algorithm configuration of the {@code HashService} should be used.
     */
    String getAlgorithmName();

    /**
     * A Builder class representing the Builder design pattern for constructing {@link HashRequest} instances.
     *
     * @see SimpleHashRequest
     * @since 1.2
     */
    public static class Builder {

        private ByteSource source;
        private ByteSource salt;
        private int iterations;
        private String algorithmName;

        /**
         * Default no-arg constructor.
         */
        public Builder() {
            this.iterations = 0;
        }

        /**
         * Sets the source data that will be hashed by a {@link HashService}. For example, this might be a
         * {@code ByteSource} representation of a password, or file, etc.
         *
         * @param source the source data that will be hashed by a {@link HashService}.
         * @return this {@code Builder} instance for method chaining.
         * @see HashRequest#getSource()
         * @see #setSource(Object)
         */
        public Builder setSource(ByteSource source) {
            this.source = source;
            return this;
        }

        /**
         * Sets the source data that will be hashed by a {@link HashService}.
         * <p/>
         * This is a convenience alternative to {@link #setSource(ByteSource)}: it will attempt to convert the
         * argument into a {@link ByteSource} instance using Shiro's default conversion heuristics
         * (as defined by {@link ByteSource.Util#isCompatible(Object) ByteSource.Util.isCompatible}.  If the object
         * cannot be heuristically converted to a {@code ByteSource}, an {@code IllegalArgumentException} will be
         * thrown.
         *
         * @param source the byte-backed source data that will be hashed by a {@link HashService}.
         * @return this {@code Builder} instance for method chaining.
         * @throws IllegalArgumentException if the argument cannot be heuristically converted to a {@link ByteSource}
         *                                  instance.
         * @see HashRequest#getSource()
         * @see #setSource(ByteSource)
         */
        public Builder setSource(Object source) throws IllegalArgumentException {
            this.source = ByteSource.Util.bytes(source);
            return this;
        }

        /**
         * Sets a salt to be used by the {@link HashService} during hash computation.
         * <p/>
         * <b>NOTE</b>: not calling this method does not necessarily mean a salt won't be used at all - it just
         * means that the request didn't include a salt.  The servicing {@link HashService} is free to provide a salting
         * strategy for a request, even if the request did not specify one.  You can always check the result
         * {@code Hash} {@link Hash#getSalt() getSalt()} method to see what the actual
         * salt was (if any), which may or may not match this request salt.
         *
         * @param salt a salt to be used by the {@link HashService} during hash computation
         * @return this {@code Builder} instance for method chaining.
         * @see HashRequest#getSalt()
         */
        public Builder setSalt(ByteSource salt) {
            this.salt = salt;
            return this;
        }

        /**
         * Sets a salt to be used by the {@link HashService} during hash computation.
         * <p/>
         * This is a convenience alternative to {@link #setSalt(ByteSource)}: it will attempt to convert the
         * argument into a {@link ByteSource} instance using Shiro's default conversion heuristics
         * (as defined by {@link ByteSource.Util#isCompatible(Object) ByteSource.Util.isCompatible}.  If the object
         * cannot be heuristically converted to a {@code ByteSource}, an {@code IllegalArgumentException} will be
         * thrown.
         *
         * @param salt a salt to be used by the {@link HashService} during hash computation.
         * @return this {@code Builder} instance for method chaining.
         * @throws IllegalArgumentException if the argument cannot be heuristically converted to a {@link ByteSource}
         *                                  instance.
         * @see #setSalt(ByteSource)
         * @see HashRequest#getSalt()
         */
        public Builder setSalt(Object salt) throws IllegalArgumentException {
            this.salt = ByteSource.Util.bytes(salt);
            return this;
        }

        /**
         * Sets the number of requested hash iterations to be performed when computing the final {@code Hash} result.
         * Not calling this method or setting a non-positive value (0 or less) indicates that the {@code HashService}'s
         * default iteration configuration should be used.  A positive value overrides the {@code HashService}'s
         * configuration for a single request.
         * <p/>
         * Note that a {@code HashService} is free to ignore this number if it determines the number is not sufficient
         * to meet a desired level of security. You can always check the result
         * {@code Hash} {@link Hash#getIterations() getIterations()} method to see what the actual
         * number of iterations was, which may or may not match this request salt.
         *
         * @param iterations the number of requested hash iterations to be performed when computing the final
         *                   {@code Hash} result.
         * @return this {@code Builder} instance for method chaining.
         * @see HashRequest#getIterations()
         */
        public Builder setIterations(int iterations) {
            this.iterations = iterations;
            return this;
        }

        /**
         * Sets the name of the hash algorithm the {@code HashService} should use when computing the {@link Hash}.
         * Not calling this method or setting it to {@code null} indicates the the default algorithm configuration of
         * the {@code HashService} should be used.  A non-null value
         * overrides the {@code HashService}'s configuration for a single request.
         * <p/>
         * Note that a {@code HashService} is free to ignore this value if it determines that the algorithm is not
         * sufficient to meet a desired level of security. You can always check the result
         * {@code Hash} {@link Hash#getAlgorithmName() getAlgorithmName()} method to see what the actual
         * algorithm was, which may or may not match this request salt.
         *
         * @param algorithmName the name of the hash algorithm the {@code HashService} should use when computing the
         *                      {@link Hash}, or {@code null} if the default algorithm configuration of the
         *                      {@code HashService} should be used.
         * @return this {@code Builder} instance for method chaining.
         * @see HashRequest#getAlgorithmName()
         */
        public Builder setAlgorithmName(String algorithmName) {
            this.algorithmName = algorithmName;
            return this;
        }

        /**
         * Builds a {@link HashRequest} instance reflecting the specified configuration.
         *
         * @return a {@link HashRequest} instance reflecting the specified configuration.
         */
        public HashRequest build() {
            return new SimpleHashRequest(this.algorithmName, this.source, this.salt, this.iterations);
        }
    }
}
