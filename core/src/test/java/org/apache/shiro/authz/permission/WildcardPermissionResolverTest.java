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

import static org.junit.jupiter.api.Assertions.*;

public class WildcardPermissionResolverTest {

    @Test
    void testDefaultIsNonCaseSensitive()
    {
        WildcardPermissionResolver resolver = new WildcardPermissionResolver();
        assertFalse( resolver.isCaseSensitive(), "Default sensitivity should be false");
        /* this is a round-about test as permissions don't store case sensitivity just lower case 
        the string. */
        WildcardPermission permission = (WildcardPermission) resolver.resolvePermission( "Foo:*" );
        assertEquals( "foo:*", permission.toString(), "string should be lowercase");
    }

    @Test
    void testCaseSensitive()
    {
        WildcardPermissionResolver resolver = new WildcardPermissionResolver(true);
        assertTrue( resolver.isCaseSensitive(), "Sensitivity should be true");
        /* this is a round-about test as permissions don't store case sensitivity just lower case 
        the string. */
        WildcardPermission permission = (WildcardPermission) resolver.resolvePermission( "Foo:*" );
        assertEquals( "Foo:*", permission.toString(), "string should be mixed case");
    }

    @Test
    void testCaseInsensitive()
    {
        WildcardPermissionResolver resolver = new WildcardPermissionResolver(false);
        assertFalse( resolver.isCaseSensitive(), "Sensitivity should be false");
        /* this is a round-about test as permissions don't store case sensitivity just lower case 
        the string. */
        WildcardPermission permission = (WildcardPermission) resolver.resolvePermission( "Foo:*" );
        assertEquals( "foo:*", permission.toString(), "string should be lowercase");
    }

    @Test
    void testCaseSensitiveToggle()
    {
        WildcardPermissionResolver resolver = new WildcardPermissionResolver();
        assertFalse( resolver.isCaseSensitive(), "Default sensitivity should be false");
        resolver.setCaseSensitive( true );
        assertTrue( resolver.isCaseSensitive(), "Sensitivity should be true");
        resolver.setCaseSensitive( false );
        assertFalse( resolver.isCaseSensitive(), "Sensitivity should be false");
    }

}
