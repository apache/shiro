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
package org.apache.shiro.subject;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;

public class ImmutablePrincipalCollectionTest {

    private static final String MY_REALM = "myRealm";
    private static final String OTHER_REALM = "otherRealm";

    private static final String MY_PRINCIPAL = "myPrincipal";
    private static final String OTHER_PRINCIPAL = "otherPrincipal";
    private static final String THIRD_PRINCIPAL = "thirdPrincipal";

    private void testEmptyHelper(PrincipalCollection c) {
        assertNull(c.getPrimaryPrincipal());
        assertNull(c.oneByType(Object.class));
        assertNull(c.oneByType(String.class));
        assertNull(c.oneByType(Integer.class));
        assertTrue(c.byType(Object.class).isEmpty());
        assertTrue(c.asSet().isEmpty());
        assertTrue(c.asList().isEmpty());
        assertTrue(c.fromRealm(MY_REALM).isEmpty());
        assertTrue(c.getRealmNames().isEmpty());
        assertTrue(c.isEmpty());
    }

    @Test
    void testSharedEmpty() {
        testEmptyHelper(ImmutablePrincipalCollection.EMPTY);
    }

    @Test
    void testNewEmpty() {
        testEmptyHelper(ImmutablePrincipalCollection.empty());
    }

    @Test
    void testNewEmptyFromBuilder() {
        testEmptyHelper(new ImmutablePrincipalCollection.Builder().build());
    }

    private void testSinglePrincipalHelper(PrincipalCollection c) {
        assertEquals(MY_PRINCIPAL, c.getPrimaryPrincipal());

        assertEquals(MY_PRINCIPAL, c.oneByType(Object.class));
        assertEquals(MY_PRINCIPAL, c.oneByType(String.class));
        assertNull(c.oneByType(Integer.class));

        assertEquals(Set.of(MY_PRINCIPAL), c.byType(Object.class));
        assertEquals(Set.of(MY_PRINCIPAL), c.byType(String.class));
        assertEquals(Set.of(), c.byType(Integer.class));

        assertEquals(Set.of(MY_PRINCIPAL), c.asSet());
        assertEquals(List.of(MY_PRINCIPAL), c.asList());

        assertEquals(Set.of(MY_PRINCIPAL), c.fromRealm(MY_REALM));
        assertTrue(c.fromRealm(OTHER_REALM).isEmpty());

        assertEquals(Set.of(MY_REALM), c.getRealmNames());
        assertFalse(c.isEmpty());
    }

    @Test
    void testNewSinglePrincipal() {
        testSinglePrincipalHelper(ImmutablePrincipalCollection.ofSinglePrincipal(MY_PRINCIPAL, MY_REALM));
    }

    @Test
    void testNewSinglePrincipalUsingCollection() {
        testSinglePrincipalHelper(ImmutablePrincipalCollection.ofSingleRealm(List.of(MY_PRINCIPAL), MY_REALM));
    }

    @Test
    void testNewSinglePrincipalUsingBuilder() {
        ImmutablePrincipalCollection collection = new ImmutablePrincipalCollection.Builder()
                .addPrincipal(MY_PRINCIPAL, MY_REALM)
                .build();
        testSinglePrincipalHelper(collection);
    }

    @Test
    void testNewSinglePrincipalUsingBuilderAndCollection() {
        ImmutablePrincipalCollection collection = new ImmutablePrincipalCollection.Builder()
                .addPrincipals(List.of(MY_PRINCIPAL), MY_REALM)
                .build();
        testSinglePrincipalHelper(collection);
    }

    private void testSingleRealmMultiplePrincipalsHelper(PrincipalCollection c) {
        assertEquals(MY_PRINCIPAL, c.getPrimaryPrincipal());

        assertEquals(MY_PRINCIPAL, c.oneByType(Object.class));
        assertEquals(MY_PRINCIPAL, c.oneByType(String.class));
        assertNull(c.oneByType(Integer.class));

        assertEquals(Set.of(MY_PRINCIPAL, OTHER_PRINCIPAL), c.byType(Object.class));
        assertEquals(Set.of(MY_PRINCIPAL, OTHER_PRINCIPAL), c.byType(String.class));
        assertEquals(Set.of(), c.byType(Integer.class));

        assertEquals(Set.of(MY_PRINCIPAL, OTHER_PRINCIPAL), c.asSet());
        assertEquals(List.of(MY_PRINCIPAL, OTHER_PRINCIPAL), c.asList());

        assertEquals(Set.of(MY_PRINCIPAL, OTHER_PRINCIPAL), c.fromRealm(MY_REALM));
        assertTrue(c.fromRealm(OTHER_REALM).isEmpty());

        assertEquals(Set.of(MY_REALM), c.getRealmNames());
        assertFalse(c.isEmpty());
    }

    @Test
    void testNewSingleRealmMultiplePrincipalsUsingCollection() {
        testSingleRealmMultiplePrincipalsHelper(
                ImmutablePrincipalCollection.ofSingleRealm(List.of(MY_PRINCIPAL, OTHER_PRINCIPAL), MY_REALM));
    }

    @Test
    void testNewSingleRealmMultiplePrincipalsUsingBuilderAndCollection() {
        ImmutablePrincipalCollection collection = new ImmutablePrincipalCollection.Builder()
                .addPrincipals(List.of(MY_PRINCIPAL, OTHER_PRINCIPAL), MY_REALM)
                .build();
        testSingleRealmMultiplePrincipalsHelper(collection);
    }

    @Test
    void testNewSingleRealmMultiplePrincipalsUsingBuilderAndMultipleCalls() {
        ImmutablePrincipalCollection collection = new ImmutablePrincipalCollection.Builder()
                .addPrincipal(MY_PRINCIPAL, MY_REALM)
                .addPrincipal(OTHER_PRINCIPAL, MY_REALM)
                .build();
        testSingleRealmMultiplePrincipalsHelper(collection);
    }

    private void testMultipleRealmsSinglePrincipalEachHelper(PrincipalCollection c) {
        assertEquals(MY_PRINCIPAL, c.getPrimaryPrincipal());

        assertEquals(MY_PRINCIPAL, c.oneByType(Object.class));
        assertEquals(MY_PRINCIPAL, c.oneByType(String.class));
        assertNull(c.oneByType(Integer.class));

        assertEquals(Set.of(MY_PRINCIPAL, OTHER_PRINCIPAL), c.byType(Object.class));
        assertEquals(Set.of(MY_PRINCIPAL, OTHER_PRINCIPAL), c.byType(String.class));
        assertEquals(Set.of(), c.byType(Integer.class));

        assertEquals(Set.of(MY_PRINCIPAL, OTHER_PRINCIPAL), c.asSet());
        assertEquals(List.of(MY_PRINCIPAL, OTHER_PRINCIPAL), c.asList());

        assertEquals(Set.of(MY_PRINCIPAL), c.fromRealm(MY_REALM));
        assertEquals(Set.of(OTHER_PRINCIPAL), c.fromRealm(OTHER_REALM));

        assertEquals(Set.of(MY_REALM, OTHER_REALM), c.getRealmNames());
        assertFalse(c.isEmpty());
    }

    @Test
    void testNewMultipleRealmsSinglePrincipalEachUsingBuilder() {
        ImmutablePrincipalCollection collection = new ImmutablePrincipalCollection.Builder()
                .addPrincipal(MY_PRINCIPAL, MY_REALM)
                .addPrincipal(OTHER_PRINCIPAL, OTHER_REALM)
                .build();
        testMultipleRealmsSinglePrincipalEachHelper(collection);
    }

    @Test
    void testNewMultipleRealmsSinglePrincipalEachUsingBuilderAndMultipleCalls() {
        ImmutablePrincipalCollection collection = new ImmutablePrincipalCollection.Builder()
                .addPrincipals(List.of(MY_PRINCIPAL), MY_REALM)
                .addPrincipals(List.of(OTHER_PRINCIPAL), OTHER_REALM)
                .build();
        testMultipleRealmsSinglePrincipalEachHelper(collection);
    }

    @Test
    void testComplexScenario() {
        ImmutablePrincipalCollection c = new ImmutablePrincipalCollection.Builder()
                .addPrincipal(MY_PRINCIPAL, MY_REALM)
                .addPrincipal(OTHER_PRINCIPAL, OTHER_REALM)
                .addPrincipal(THIRD_PRINCIPAL, MY_REALM)
                .build();

        assertEquals(MY_PRINCIPAL, c.getPrimaryPrincipal());

        assertEquals(MY_PRINCIPAL, c.oneByType(Object.class));
        assertEquals(MY_PRINCIPAL, c.oneByType(String.class));
        assertNull(c.oneByType(Integer.class));

        assertEquals(Set.of(MY_PRINCIPAL, OTHER_PRINCIPAL, THIRD_PRINCIPAL), c.byType(Object.class));
        assertEquals(Set.of(MY_PRINCIPAL, OTHER_PRINCIPAL, THIRD_PRINCIPAL), c.byType(String.class));
        assertEquals(Set.of(), c.byType(Integer.class));

        assertEquals(Set.of(MY_PRINCIPAL, OTHER_PRINCIPAL, THIRD_PRINCIPAL), c.asSet());

        // principals are returned sorted by realm, then within each realm by insertion order
        assertEquals(List.of(MY_PRINCIPAL, THIRD_PRINCIPAL, OTHER_PRINCIPAL), c.asList());

        assertEquals(Set.of(MY_PRINCIPAL, THIRD_PRINCIPAL), c.fromRealm(MY_REALM));
        assertEquals(Set.of(OTHER_PRINCIPAL), c.fromRealm(OTHER_REALM));

        assertEquals(Set.of(MY_REALM, OTHER_REALM), c.getRealmNames());
        assertFalse(c.isEmpty());
    }

}
