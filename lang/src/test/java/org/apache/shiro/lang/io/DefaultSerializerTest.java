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
package org.apache.shiro.lang.io;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InvalidClassException;
import java.io.ObjectInputFilter;
import java.io.ObjectInputStream;
import java.io.Serializable;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Test cases for {@link DefaultSerializer}, in particular its optional
 * <a href="https://openjdk.org/jeps/290">JEP-290</a> {@link ObjectInputFilter} support.
 */
class DefaultSerializerTest {

    /**
     * Stand-in for an attacker-controlled "gadget" class. It is not itself a gadget chain - it simply proves,
     * via a side effect in {@code readObject}, whether the JVM fully constructed an arbitrary Serializable
     * class reachable on the classpath. A real gadget chain (e.g. from a library on the classpath) would
     * trigger through the exact same {@link DefaultSerializer#deserialize(byte[])} sink.
     */
    public static class GadgetMarker implements Serializable {
        private static final long serialVersionUID = 1L;

        private transient boolean fired;

        private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
            in.defaultReadObject();
            fired = true;
        }

        boolean isFired() {
            return fired;
        }
    }

    @Test
    void testDeserializeWithNoFilterConfiguredIsUnchanged() {
        // Default behavior (no ObjectInputFilter configured) must remain exactly as before this feature
        // was added: any Serializable class on the classpath is deserialized without restriction.
        DefaultSerializer<GadgetMarker> serializer = new DefaultSerializer<>();
        assertThat(serializer.getObjectInputFilter()).isNull();

        byte[] bytes = serializer.serialize(new GadgetMarker());
        GadgetMarker result = serializer.deserialize(bytes);

        assertThat(result.isFired()).isTrue();
    }

    @Test
    void testDeserializeWithAllowListFilterRejectsDisallowedClass() {
        // A strict class allow-list filter must reject GadgetMarker before it is constructed.
        ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(
                "org.apache.shiro.lang.io.DefaultSerializerTest$AllowedPayload;java.lang.String;!*");

        DefaultSerializer<Object> serializer = new DefaultSerializer<>();
        serializer.setObjectInputFilter(filter);
        assertThat(serializer.getObjectInputFilter()).isSameAs(filter);

        byte[] bytes = serializer.serialize(new GadgetMarker());

        assertThatThrownBy(() -> serializer.deserialize(bytes))
                .isInstanceOf(SerializationException.class)
                .hasCauseInstanceOf(InvalidClassException.class);
    }

    @Test
    void testDeserializeWithAllowListFilterPermitsAllowedClass() {
        // The same filter must still allow round-tripping of the class(es) it permits.
        ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(
                "org.apache.shiro.lang.io.DefaultSerializerTest$AllowedPayload;java.lang.String;!*");

        DefaultSerializer<AllowedPayload> serializer = new DefaultSerializer<>();
        serializer.setObjectInputFilter(filter);

        AllowedPayload original = new AllowedPayload("shiro");
        byte[] bytes = serializer.serialize(original);
        AllowedPayload result = serializer.deserialize(bytes);

        assertThat(result.value).isEqualTo("shiro");
    }

    @Test
    void testSetObjectInputFilterNullRestoresUnfilteredBehavior() {
        DefaultSerializer<GadgetMarker> serializer = new DefaultSerializer<>();
        serializer.setObjectInputFilter(ObjectInputFilter.Config.createFilter("!*"));
        serializer.setObjectInputFilter(null);

        assertThat(serializer.getObjectInputFilter()).isNull();

        byte[] bytes = serializer.serialize(new GadgetMarker());
        GadgetMarker result = serializer.deserialize(bytes);

        assertThat(result.isFired()).isTrue();
    }

    public static class AllowedPayload implements Serializable {
        private static final long serialVersionUID = 1L;
        final String value;

        AllowedPayload(String value) {
            this.value = value;
        }
    }
}
