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
 * A {@code ParsableHashFormat} is able to parse a formatted string and convert it into a {@link Hash} instance.
 * <p/>
 * This interface exists to represent {@code HashFormat}s that can offer two-way conversion
 * (Hash -&gt; String, String -&gt; Hash) capabilities.  Some HashFormats, such as many {@link ModularCryptFormat}s
 * (like Unix Crypt(3)) only support one way conversion and therefore wouldn't implement this interface.
 *
 * @see Shiro1CryptFormat
 *
 * @since 1.2
 */
public interface ParsableHashFormat extends HashFormat {

    /**
     * Parses the specified formatted string and returns the corresponding Hash instance.
     *
     * @param formatted the formatted string representing a Hash.
     * @return the corresponding Hash instance.
     */
    Hash parse(String formatted);
}
