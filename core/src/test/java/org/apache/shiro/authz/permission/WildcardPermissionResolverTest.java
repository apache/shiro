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
package org.apache.shiro.authz.permission;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class WildcardPermissionResolverTest {

    @Test
    void testDefaultIsNonCaseSensitive() {
        WildcardPermissionResolver resolver = new WildcardPermissionResolver();
        assertThat(resolver.isCaseSensitive()).as("Default sensitivity should be false").isFalse();
        /* this is a round-about test as permissions don't store case sensitivity just lower case
        the string. */
        WildcardPermission permission = (WildcardPermission) resolver.resolvePermission("Foo:*");
        assertThat(permission.toString()).as("string should be lowercase").isEqualTo("foo:*");
    }

    @Test
    void testCaseSensitive() {
        WildcardPermissionResolver resolver = new WildcardPermissionResolver(true);
        assertThat(resolver.isCaseSensitive()).as("Sensitivity should be true").isTrue();
        /* this is a round-about test as permissions don't store case sensitivity just lower case
        the string. */
        WildcardPermission permission = (WildcardPermission) resolver.resolvePermission("Foo:*");
        assertThat(permission.toString()).as("string should be mixed case").isEqualTo("Foo:*");
    }

    @Test
    void testCaseInsensitive() {
        WildcardPermissionResolver resolver = new WildcardPermissionResolver(false);
        assertThat(resolver.isCaseSensitive()).as("Sensitivity should be false").isFalse();
        /* this is a round-about test as permissions don't store case sensitivity just lower case
        the string. */
        WildcardPermission permission = (WildcardPermission) resolver.resolvePermission("Foo:*");
        assertThat(permission.toString()).as("string should be lowercase").isEqualTo("foo:*");
    }

    @Test
    void testCaseSensitiveToggle() {
        WildcardPermissionResolver resolver = new WildcardPermissionResolver();
        assertThat(resolver.isCaseSensitive()).as("Default sensitivity should be false").isFalse();
        resolver.setCaseSensitive(true);
        assertThat(resolver.isCaseSensitive()).as("Sensitivity should be true").isTrue();
        resolver.setCaseSensitive(false);
        assertThat(resolver.isCaseSensitive()).as("Sensitivity should be false").isFalse();
    }

}
