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
package org.apache.shiro.mgt;

import org.apache.shiro.lang.io.Serializer;
import org.apache.shiro.subject.ImmutablePrincipalCollection;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.subject.SubjectContext;
import org.apache.shiro.subject.support.DefaultSubjectContext;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InvalidClassException;
import java.io.ObjectInputFilter;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serial;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Test cases proving {@link AbstractRememberMeManager}'s RememberMe cookie deserialization path is
 * protected by a <a href="https://openjdk.org/jeps/290">JEP-290</a> {@link ObjectInputFilter} by default,
 * without breaking legitimate {@link PrincipalCollection} round-tripping.
 */
class AbstractRememberMeManagerObjectInputFilterTest {

    /** Deeper than the default filter's {@code maxdepth=30}, to trigger a resource-limit rejection. */
    private static final int DEEP_CHAIN_LENGTH = 60;

    @Test
    void testLegitimatePrincipalsRoundTripUnderDefaultFilter() {
        InMemoryRememberMeManager rmm = new InMemoryRememberMeManager();
        PrincipalCollection principals = ImmutablePrincipalCollection.ofSinglePrincipal("joecool", "myRealm");

        rmm.rememberIdentity(null, principals);
        PrincipalCollection remembered = rmm.getRememberedPrincipals(new DefaultSubjectContext());

        assertThat(remembered).isNotNull();
        assertThat(remembered.getPrimaryPrincipal()).isEqualTo("joecool");
    }

    @Test
    void testDefaultFilterRejectsOversizedPayloadBeforeFullConstruction() {
        // The default filter (see AbstractRememberMeManager.DEFAULT_OBJECT_INPUT_FILTER_PATTERN) bounds the
        // object graph depth/array size/reference count/byte count of the deserialized payload. This is
        // denial-of-service-shaped-payload hardening: it does not restrict classes and does not stop RCE
        // gadget chains (which are shallow and small). Feed an oversized/deeply nested payload that exceeds
        // maxdepth, encrypted the way a real RememberMe cookie is, and confirm getRememberedPrincipals() fails
        // closed with a JEP-290 filter rejection (InvalidClassException) before the graph is materialized. The
        // InvalidClassException cause is the discriminating assertion: without the filter this same payload
        // deserializes fully and fails only later with an unrelated ClassCastException, so asserting the cause
        // is what proves the filter itself fired.
        InMemoryRememberMeManager rmm = new InMemoryRememberMeManager();

        List<Object> deepChain = new ArrayList<>();
        List<Object> cursor = deepChain;
        for (int i = 0; i < DEEP_CHAIN_LENGTH; i++) {
            List<Object> next = new ArrayList<>();
            cursor.add(next);
            cursor = next;
        }

        byte[] serialized = plainJdkSerialize(deepChain);
        byte[] encrypted = rmm.encryptForTest(serialized);
        rmm.injectRawSerializedIdentity(encrypted);

        assertThatThrownBy(() -> rmm.getRememberedPrincipals(new DefaultSubjectContext()))
                .isInstanceOf(RuntimeException.class)
                .hasCauseInstanceOf(InvalidClassException.class);
        // onRememberedPrincipalFailure must have run its "forget" cleanup path.
        assertThat(rmm.forgetCount).isEqualTo(1);
    }

    @Test
    void testCustomStricterAllowListFilterCanBeConfigured() {
        // Documented override path (see AbstractRememberMeManager#getSerializer javadoc): replace the default
        // serializer's filter with a strict class allow-list. Only ImmutablePrincipalCollection,
        // AbstractRememberMeManager.RememberedIdentity, and JDK collection/primitive/java.time plumbing are let
        // through. Note: java.time types (e.g. Instant) don't serialize themselves directly - they writeReplace()
        // to an internal java.time serialization proxy class, which is what actually appears in the stream.
        InMemoryRememberMeManager rmm = new InMemoryRememberMeManager();
        rmm.getSerializer()
                .setObjectInputFilter(ObjectInputFilter.Config.createFilter(
                        "org.apache.shiro.subject.ImmutablePrincipalCollection;"
                                + "org.apache.shiro.mgt.AbstractRememberMeManager$RememberedIdentity;"
                                + "java.time.*;java.util.*;java.lang.*;!*"));

        PrincipalCollection principals = ImmutablePrincipalCollection.ofSinglePrincipal("joecool", "myRealm");
        rmm.rememberIdentity(null, principals);
        PrincipalCollection remembered = rmm.getRememberedPrincipals(new DefaultSubjectContext());
        assertThat(remembered.getPrimaryPrincipal()).isEqualTo("joecool");

        // A disallowed class must now be rejected outright (not merely resource-limited).
        byte[] disallowed = plainJdkSerialize(new NotAllowlisted());
        rmm.injectRawSerializedIdentity(rmm.encryptForTest(disallowed));

        assertThatThrownBy(() -> rmm.getRememberedPrincipals(new DefaultSubjectContext()))
                .isInstanceOf(RuntimeException.class)
                .hasCauseInstanceOf(InvalidClassException.class);
        assertThat(rmm.forgetCount).isEqualTo(1);
    }

    @Test
    void testCustomSerializerIsUnaffectedByDefaultFilterMachinery() {
        // A caller-supplied Serializer implementation (not a DefaultSerializer) must keep working exactly as
        // before this feature existed - AbstractRememberMeManager only touches the filter on its own default
        // DefaultSerializer instance, never on a replaced Serializer.
        var rmm = new InMemoryRememberMeManager();
        rmm.setSerializer(new Serializer<>() {
            @Override
            public byte[] serialize(AbstractRememberMeManager.RememberedIdentity o) {
                return plainJdkSerialize(o);
            }

            @Override
            public AbstractRememberMeManager.RememberedIdentity deserialize(byte[] serialized) {
                try (var ois = new ObjectInputStream(new ByteArrayInputStream(serialized))) {
                    return (AbstractRememberMeManager.RememberedIdentity) ois.readObject();
                } catch (IOException | ClassNotFoundException e) {
                    throw new RuntimeException(e);
                }
            }
        });

        PrincipalCollection principals = ImmutablePrincipalCollection.ofSinglePrincipal("joecool", "myRealm");
        rmm.rememberIdentity(null, principals);
        PrincipalCollection remembered = rmm.getRememberedPrincipals(new DefaultSubjectContext());

        assertThat(remembered.getPrimaryPrincipal()).isEqualTo("joecool");
    }

    private static byte[] plainJdkSerialize(Object o) {
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            try (ObjectOutputStream oos = new ObjectOutputStream(baos)) {
                oos.writeObject(o);
            }
            return baos.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static class NotAllowlisted implements Serializable {
        @Serial
        private static final long serialVersionUID = 1L;
    }

    /**
     * Minimal in-memory RememberMeManager test double: stores the "persisted" (encrypted+serialized) bytes
     * in a field instead of a cookie, and tracks how many times identity was forgotten.
     */
    private static final class InMemoryRememberMeManager extends AbstractRememberMeManager {
        private byte[] stored;
        private int forgetCount;

        @Override
        protected void forgetIdentity(Subject subject) {
            stored = null;
            forgetCount++;
        }

        public void forgetIdentity(SubjectContext subjectContext) {
            stored = null;
            forgetCount++;
        }

        @Override
        protected void rememberSerializedIdentity(Subject subject, byte[] serialized) {
            this.stored = serialized;
        }

        @Override
        protected byte[] getRememberedSerializedIdentity(SubjectContext subjectContext) {
            return stored;
        }

        void injectRawSerializedIdentity(byte[] raw) {
            this.stored = raw;
        }

        byte[] encryptForTest(byte[] plain) {
            return encrypt(plain);
        }
    }
}
