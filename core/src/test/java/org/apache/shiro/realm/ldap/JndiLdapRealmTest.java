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
package org.apache.shiro.realm.ldap;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Tests for the {@link JndiLdapRealm} class.
 *
 * @since 1.1
 * @deprecated Replaced by {@link DefaultLdapRealmTest}
 */
@SuppressWarnings({"ThrowableInstanceNeverThrown", "deprecation"})
@Deprecated
public class JndiLdapRealmTest extends DefaultLdapRealmTest {

    protected DefaultLdapRealm getNewRealmUnderTest() {
        return new JndiLdapRealm();
    }

    @Test
    public void testGetUserDnWithOutPrefixAndSuffix() {
        JndiLdapRealm realm = new JndiLdapRealm() {
            @Override
            protected String getUserDnPrefix() {
                return null;
            }

            @Override
            protected String getUserDnSuffix() {
                return null;
            }
        };
        String principal = "foo";
        String userDn = realm.getUserDn(principal);
        assertEquals(principal, userDn);
    }
}
