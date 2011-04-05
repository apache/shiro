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

import org.apache.shiro.util.ByteSource;

/**
 * A {@code HashRequest} is composed of data that will be used to create a hash by a {@link Hasher}.
 *
 * @see SimpleHashRequest
 * @since 1.2
 */
public interface HashRequest {

    /**
     * Returns the source data that will be hashed by a {@link Hasher}.
     *
     * @return the source data that will be hashed by a {@link Hasher}.
     */
    ByteSource getSource();

    /**
     * Returns a salt to be used by the {@link Hasher} during hash computation, or {@code null} if no salt is provided
     * as part of the request.
     * <p/>
     * Note that a {@code null} return value does not necessarily mean a salt won't be used at all - it just
     * means that the request didn't include one.  The servicing {@link Hasher} is free to provide a salting
     * strategy for a request, even if the request did not specify one.
     * <p/>
     * <b>NOTE:</b> if
     *
     * @return a salt to be used by the {@link Hasher} during hash computation, or {@code null} if no salt is provided
     *         as part of the request.
     */

    ByteSource getSalt();
}
