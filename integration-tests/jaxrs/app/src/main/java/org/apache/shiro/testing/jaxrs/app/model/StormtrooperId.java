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

package org.apache.shiro.testing.jaxrs.app.model;

import java.util.Objects;
import java.util.StringJoiner;
import java.util.UUID;

import static java.util.Objects.requireNonNull;

public class StormtrooperId implements Comparable<StormtrooperId> {

    private final String value;

    public StormtrooperId(String value) {
        this.value = requireNonNull(value, "value in new UserId(String value)!");
    }

    public static StormtrooperId createFresh() {
        return new StormtrooperId(UUID.randomUUID().toString());
    }

    public String getValue() {
        return this.value;
    }

    // can be suppressed, this is a jax-rs standard (static T fromString(String value)).
    @SuppressWarnings("unused")
    public static StormtrooperId fromString(String value) {
        return new StormtrooperId(value);
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (other == null || getClass() != other.getClass()) {
            return false;
        }
        StormtrooperId stormtrooperId = (StormtrooperId) other;
        return value.equals(stormtrooperId.value);
    }

    @Override
    public int hashCode() {
        return Objects.hash(value);
    }

    @Override
    public int compareTo(StormtrooperId other) {
        return value.compareTo(other.value);
    }

    @Override
    public String toString() {
        return new StringJoiner(", ", StormtrooperId.class.getSimpleName() + "[", "]")
                .add("value='" + value + "'")
                .toString();
    }
}
