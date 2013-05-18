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

/**
 * A {@code HashFormat} that supports
 * <a href="http://packages.python.org/passlib/modular_crypt_format.html">Modular Crypt Format</a> token rules.
 *
 * @see <a href="http://en.wikipedia.org/wiki/Crypt_(Unix)">Crypt (unix)</a>
 * @see <a href="http://www.tummy.com/journals/entries/jafo_20110117_054918">MCF Journal Entry</a>
 * @since 1.2
 */
public interface ModularCryptFormat extends HashFormat {

    public static final String TOKEN_DELIMITER = "$";

    /**
     * Returns the Modular Crypt Format identifier that indicates how the formatted String should be parsed.  This id
     * is always in the MCF-formatted string's first token.
     * <p/>
     * Example values are {@code md5}, {@code 1}, {@code 2}, {@code apr1}, etc.
     *
     * @return the Modular Crypt Format identifier that indicates how the formatted String should be parsed.
     */
    String getId();
}
