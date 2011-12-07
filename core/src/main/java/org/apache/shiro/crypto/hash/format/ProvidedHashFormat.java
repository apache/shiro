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
 * An enum representing Shiro's default provided {@link HashFormat} implementations.
 */
public enum ProvidedHashFormat {

    /**
     * Value representing the {@link HexFormat} implementation.
     */
    HEX(HexFormat.class),

    /**
     * Value representing the {@link Base64Format} implementation.
     */
    BASE64(Base64Format.class),

    /**
     * Value representing the {@link Shiro1CryptFormat} implementation.
     */
    SHIRO1(Shiro1CryptFormat.class);

    private final Class<? extends HashFormat> clazz;

    private ProvidedHashFormat(Class<? extends HashFormat> clazz) {
        this.clazz = clazz;
    }

    Class<? extends HashFormat> getHashFormatClass() {
        return this.clazz;
    }

    public static ProvidedHashFormat byId(String id) {
        if (id == null) {
            return null;
        }
        try {
            return valueOf(id.toUpperCase());
        } catch (IllegalArgumentException ignored) {
            return null;
        }
    }

}
