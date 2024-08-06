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
import static org.assertj.core.api.Assertions.assertThat;

public class ImmutablePrincipalCollectionTest {

    private static final String MY_REALM = "myRealm";
    private static final String OTHER_REALM = "otherRealm";

    private static final String MY_PRINCIPAL = "myPrincipal";
    private static final String OTHER_PRINCIPAL = "otherPrincipal";
    private static final String THIRD_PRINCIPAL = "thirdPrincipal";

    private void testEmptyHelper(PrincipalCollection c) {
        assertThat(c.getPrimaryPrincipal()).isNull();
        assertThat(c.oneByType(Object.class)).isNull();
        assertThat(c.oneByType(String.class)).isNull();
        assertThat(c.oneByType(Integer.class)).isNull();
        assertThat(c.byType(Object.class).isEmpty()).isTrue();
        assertThat(c.asSet().isEmpty()).isTrue();
        assertThat(c.asList().isEmpty()).isTrue();
        assertThat(c.fromRealm(MY_REALM).isEmpty()).isTrue();
        assertThat(c.getRealmNames().isEmpty()).isTrue();
        assertThat(c.isEmpty()).isTrue();
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
        assertThat(c.getPrimaryPrincipal()).isEqualTo(MY_PRINCIPAL);

        assertThat(c.oneByType(Object.class)).isEqualTo(MY_PRINCIPAL);
        assertThat(c.oneByType(String.class)).isEqualTo(MY_PRINCIPAL);
        assertThat(c.oneByType(Integer.class)).isNull();

        assertThat(c.byType(Object.class)).isEqualTo(Set.of(MY_PRINCIPAL));
        assertThat(c.byType(String.class)).isEqualTo(Set.of(MY_PRINCIPAL));
        assertThat(c.byType(Integer.class)).isEqualTo(Set.of());

        assertThat(c.asSet()).isEqualTo(Set.of(MY_PRINCIPAL));
        assertThat(c.asList()).isEqualTo(List.of(MY_PRINCIPAL));

        assertThat(c.fromRealm(MY_REALM)).isEqualTo(Set.of(MY_PRINCIPAL));
        assertThat(c.fromRealm(OTHER_REALM)).isEmpty();

        assertThat(c.getRealmNames()).isEqualTo(Set.of(MY_REALM));
        assertThat(c).isNotEmpty();
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
        assertThat(c.getPrimaryPrincipal()).isEqualTo(MY_PRINCIPAL);

        assertThat(c.oneByType(Object.class)).isEqualTo(MY_PRINCIPAL);
        assertThat(c.oneByType(String.class)).isEqualTo(MY_PRINCIPAL);
        assertThat(c.oneByType(Integer.class)).isNull();

        assertThat(c.byType(Object.class)).isEqualTo(Set.of(MY_PRINCIPAL, OTHER_PRINCIPAL));
        assertThat(c.byType(String.class)).isEqualTo(Set.of(MY_PRINCIPAL, OTHER_PRINCIPAL));
        assertThat(c.byType(Integer.class)).isEqualTo(Set.of());

        assertThat(c.asSet()).isEqualTo(Set.of(MY_PRINCIPAL, OTHER_PRINCIPAL));
        assertThat(c.asList()).isEqualTo(List.of(MY_PRINCIPAL, OTHER_PRINCIPAL));

        assertThat(c.fromRealm(MY_REALM)).isEqualTo(Set.of(MY_PRINCIPAL, OTHER_PRINCIPAL));
        assertThat(c.fromRealm(OTHER_REALM)).isEmpty();

        assertThat(c.getRealmNames()).isEqualTo(Set.of(MY_REALM));
        assertThat(c).isNotEmpty();
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
        assertThat(c.getPrimaryPrincipal()).isEqualTo(MY_PRINCIPAL);

        assertThat(c.oneByType(Object.class)).isEqualTo(MY_PRINCIPAL);
        assertThat(c.oneByType(String.class)).isEqualTo(MY_PRINCIPAL);
        assertThat(c.oneByType(Integer.class)).isNull();

        assertThat(c.byType(Object.class)).isEqualTo(Set.of(MY_PRINCIPAL, OTHER_PRINCIPAL));
        assertThat(c.byType(String.class)).isEqualTo(Set.of(MY_PRINCIPAL, OTHER_PRINCIPAL));
        assertThat(c.byType(Integer.class)).isEqualTo(Set.of());

        assertThat(c.asSet()).isEqualTo(Set.of(MY_PRINCIPAL, OTHER_PRINCIPAL));
        assertThat(c.asList()).isEqualTo(List.of(MY_PRINCIPAL, OTHER_PRINCIPAL));

        assertThat(c.fromRealm(MY_REALM)).isEqualTo(Set.of(MY_PRINCIPAL));
        assertThat(c.fromRealm(OTHER_REALM)).isEqualTo(Set.of(OTHER_PRINCIPAL));

        assertThat(c.getRealmNames()).isEqualTo(Set.of(MY_REALM, OTHER_REALM));
        assertThat(c).isNotEmpty();
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

        assertThat(c.getPrimaryPrincipal()).isEqualTo(MY_PRINCIPAL);

        assertThat(c.oneByType(Object.class)).isEqualTo(MY_PRINCIPAL);
        assertThat(c.oneByType(String.class)).isEqualTo(MY_PRINCIPAL);
        assertThat(c.oneByType(Integer.class)).isNull();

        assertThat(c.byType(Object.class)).isEqualTo(Set.of(MY_PRINCIPAL, OTHER_PRINCIPAL, THIRD_PRINCIPAL));
        assertThat(c.byType(String.class)).isEqualTo(Set.of(MY_PRINCIPAL, OTHER_PRINCIPAL, THIRD_PRINCIPAL));
        assertThat(c.byType(Integer.class)).isEqualTo(Set.of());

        assertThat(c.asSet()).isEqualTo(Set.of(MY_PRINCIPAL, OTHER_PRINCIPAL, THIRD_PRINCIPAL));

        // principals are returned sorted by realm, then within each realm by insertion order
        assertThat(c.asList()).isEqualTo(List.of(MY_PRINCIPAL, THIRD_PRINCIPAL, OTHER_PRINCIPAL));

        assertThat(c.fromRealm(MY_REALM)).isEqualTo(Set.of(MY_PRINCIPAL, THIRD_PRINCIPAL));
        assertThat(c.fromRealm(OTHER_REALM)).isEqualTo(Set.of(OTHER_PRINCIPAL));

        assertThat(c.getRealmNames()).isEqualTo(Set.of(MY_REALM, OTHER_REALM));
        assertThat(c).isNotEmpty();
    }
}
