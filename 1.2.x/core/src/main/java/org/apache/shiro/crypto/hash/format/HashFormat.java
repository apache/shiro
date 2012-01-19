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

import org.apache.shiro.crypto.hash.Hash;

/**
 * A {@code HashFormat} is able to format a {@link Hash} instance into a well-defined formatted String.
 * <p/>
 * Note that not all HashFormat algorithms are reversible.  That is, they can't be parsed and reconstituted to the
 * original Hash instance.  The traditional <a href="http://en.wikipedia.org/wiki/Crypt_(Unix)">
 * Unix crypt(3)</a> is one such format.
 * <p/>
 * The formats that <em>are</em> reversible however will be represented as {@link ParsableHashFormat} instances.
 *
 * @see ParsableHashFormat
 *
 * @since 1.2
 */
public interface HashFormat {

    /**
     * Returns a formatted string representing the specified Hash instance.
     *
     * @param hash the hash instance to format into a String.
     * @return a formatted string representing the specified Hash instance.
     */
    String format(Hash hash);
}
