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
import org.junit.jupiter.api.parallel.Isolated;

import java.util.Locale;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Permission matching must not depend on the JVM default locale: under a Turkish default locale
 * {@code "ADMIN".toLowerCase()} is {@code "admın"} (dotless i) while {@code "admin"} stays {@code "admin"}.
 * The class changes the default locale, so it runs isolated from the (parallel) test execution.
 */
@Isolated
public class PermissionDefaultLocaleTest {

    @Test
    void wildcardPermissionIsCaseInsensitiveRegardlessOfDefaultLocale() {
        Locale defaultLocale = Locale.getDefault();
        Locale.setDefault(Locale.forLanguageTag("tr-TR"));
        try {
            assertThat(new WildcardPermission("ADMIN:*").implies(new WildcardPermission("admin:read"))).isTrue();
            assertThat(new WildcardPermission("admin:*").implies(new WildcardPermission("ADMIN:read"))).isTrue();
        } finally {
            Locale.setDefault(defaultLocale);
        }
    }

    @Test
    void domainPermissionDerivesDomainRegardlessOfDefaultLocale() {
        Locale defaultLocale = Locale.getDefault();
        Locale.setDefault(Locale.forLanguageTag("tr-TR"));
        try {
            assertThat(new InvoicePermission().getDomain()).isEqualTo("invoice");
            assertThat(new WildcardPermission("invoice:*").implies(new InvoicePermission())).isTrue();
        } finally {
            Locale.setDefault(defaultLocale);
        }
    }

    private static final class InvoicePermission extends DomainPermission {
    }
}
