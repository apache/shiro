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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertFalse;

/**
 * @since 0.9
 */
public class WildcardPermissionTest {

    @Test
    void testNull() {
        assertThrows(IllegalArgumentException.class, () -> {
            new WildcardPermission(null);
        });
    }

    @Test
    void testEmpty() {
        assertThrows(IllegalArgumentException.class, () -> {
            new WildcardPermission("");
        });
    }

    @Test
    void testBlank() {
        assertThrows(IllegalArgumentException.class, () -> {
            new WildcardPermission("   ");
        });
    }

    @Test
    void testOnlyDelimiters() {
        assertThrows(IllegalArgumentException.class, () -> {
            new WildcardPermission("::,,::,:");
        });
    }

    @SuppressWarnings("checkstyle:MultipleVariableDeclarations")
    @Test
    void testNamed() {
        WildcardPermission p1, p2;

        // Case insensitive, same
        p1 = new WildcardPermission("something");
        p2 = new WildcardPermission("something");
        assertTrue(p1.implies(p2));
        assertTrue(p2.implies(p1));

        // Case insensitive, different case
        p1 = new WildcardPermission("something");
        p2 = new WildcardPermission("SOMETHING");
        assertTrue(p1.implies(p2));
        assertTrue(p2.implies(p1));

        // Case insensitive, different word
        p1 = new WildcardPermission("something");
        p2 = new WildcardPermission("else");
        assertFalse(p1.implies(p2));
        assertFalse(p2.implies(p1));

        // Case sensitive same
        p1 = new WildcardPermission("BLAHBLAH", false);
        p2 = new WildcardPermission("BLAHBLAH", false);
        assertTrue(p1.implies(p2));
        assertTrue(p2.implies(p1));

        // Case sensitive, different case
        p1 = new WildcardPermission("BLAHBLAH", false);
        p2 = new WildcardPermission("bLAHBLAH", false);
        assertTrue(p1.implies(p2));
        assertTrue(p2.implies(p1));

        // Case sensitive, different word
        p1 = new WildcardPermission("BLAHBLAH", false);
        p2 = new WildcardPermission("whatwhat", false);
        assertFalse(p1.implies(p2));
        assertFalse(p2.implies(p1));

    }

    @SuppressWarnings("checkstyle:MultipleVariableDeclarations")
    @Test
    void testLists() {
        WildcardPermission p1, p2, p3;

        p1 = new WildcardPermission("one,two");
        p2 = new WildcardPermission("one");
        assertTrue(p1.implies(p2));
        assertFalse(p2.implies(p1));

        p1 = new WildcardPermission("one,two,three");
        p2 = new WildcardPermission("one,three");
        assertTrue(p1.implies(p2));
        assertFalse(p2.implies(p1));

        p1 = new WildcardPermission("one,two:one,two,three");
        p2 = new WildcardPermission("one:three");
        p3 = new WildcardPermission("one:two,three");
        assertTrue(p1.implies(p2));
        assertFalse(p2.implies(p1));
        assertTrue(p1.implies(p3));
        assertFalse(p2.implies(p3));
        assertTrue(p3.implies(p2));

        p1 = new WildcardPermission("one,two,three:one,two,three:one,two");
        p2 = new WildcardPermission("one:three:two");
        assertTrue(p1.implies(p2));
        assertFalse(p2.implies(p1));

        p1 = new WildcardPermission("one");
        p2 = new WildcardPermission("one:two,three,four");
        p3 = new WildcardPermission("one:two,three,four:five:six:seven");
        assertTrue(p1.implies(p2));
        assertTrue(p1.implies(p3));
        assertFalse(p2.implies(p1));
        assertFalse(p3.implies(p1));
        assertTrue(p2.implies(p3));
    }

    /**
     * Validates WildcardPermissions with that contain the same list parts are equal.
     */
    @Test
    void testListDifferentOrder() {

        WildcardPermission p6 = new WildcardPermission("one,two:three,four");
        WildcardPermission p6DiffOrder = new WildcardPermission("two,one:four,three");
        assertEquals(p6, p6DiffOrder);
    }

    @SuppressWarnings({"checkstyle:MultipleVariableDeclarations", "checkstyle:MethodLength"})
    @Test
    void testWildcards() {
        WildcardPermission p1, p2, p3, p4, p5, p6, p7, p8, p9;

        p1 = new WildcardPermission("*");
        p2 = new WildcardPermission("one");
        p3 = new WildcardPermission("one:two");
        p4 = new WildcardPermission("one,two:three,four");
        p5 = new WildcardPermission("one,two:three,four,five:six:seven,eight");
        assertTrue(p1.implies(p2));
        assertTrue(p1.implies(p3));
        assertTrue(p1.implies(p4));
        assertTrue(p1.implies(p5));

        p1 = new WildcardPermission("newsletter:*");
        p2 = new WildcardPermission("newsletter:read");
        p3 = new WildcardPermission("newsletter:read,write");
        p4 = new WildcardPermission("newsletter:*");
        p5 = new WildcardPermission("newsletter:*:*");
        p6 = new WildcardPermission("newsletter:*:read");
        p7 = new WildcardPermission("newsletter:write:*");
        p8 = new WildcardPermission("newsletter:read,write:*");
        p9 = new WildcardPermission("newsletter");
        assertTrue(p1.implies(p2));
        assertTrue(p1.implies(p3));
        assertTrue(p1.implies(p4));
        assertTrue(p1.implies(p5));
        assertTrue(p1.implies(p6));
        assertTrue(p1.implies(p7));
        assertTrue(p1.implies(p8));
        assertTrue(p1.implies(p9));


        p1 = new WildcardPermission("newsletter:*:*");
        assertTrue(p1.implies(p2));
        assertTrue(p1.implies(p3));
        assertTrue(p1.implies(p4));
        assertTrue(p1.implies(p5));
        assertTrue(p1.implies(p6));
        assertTrue(p1.implies(p7));
        assertTrue(p1.implies(p8));
        assertTrue(p1.implies(p9));

        p1 = new WildcardPermission("newsletter:*:*:*");
        assertTrue(p1.implies(p2));
        assertTrue(p1.implies(p3));
        assertTrue(p1.implies(p4));
        assertTrue(p1.implies(p5));
        assertTrue(p1.implies(p6));
        assertTrue(p1.implies(p7));
        assertTrue(p1.implies(p8));
        assertTrue(p1.implies(p9));

        p1 = new WildcardPermission("newsletter");
        assertTrue(p1.implies(p2));
        assertTrue(p1.implies(p3));
        assertTrue(p1.implies(p4));
        assertTrue(p1.implies(p5));
        assertTrue(p1.implies(p6));
        assertTrue(p1.implies(p7));
        assertTrue(p1.implies(p8));
        assertTrue(p1.implies(p9));

        p1 = new WildcardPermission("newsletter:*:read");
        p2 = new WildcardPermission("newsletter:123:read");
        p3 = new WildcardPermission("newsletter:123,456:read,write");
        p4 = new WildcardPermission("newsletter:read");
        p5 = new WildcardPermission("newsletter:read,write");
        p6 = new WildcardPermission("newsletter:123:read:write");
        assertTrue(p1.implies(p2));
        assertFalse(p1.implies(p3));
        assertFalse(p1.implies(p4));
        assertFalse(p1.implies(p5));
        assertTrue(p1.implies(p6));

        p1 = new WildcardPermission("newsletter:*:read:*");
        assertTrue(p1.implies(p2));
        assertTrue(p1.implies(p6));

    }

    @Test
    void testToString() {
        WildcardPermission p1 = new WildcardPermission("*");
        WildcardPermission p2 = new WildcardPermission("one");
        WildcardPermission p3 = new WildcardPermission("one:two");
        WildcardPermission p4 = new WildcardPermission("one,two:three,four");
        WildcardPermission p5 = new WildcardPermission("one,two:three,four,five:six:seven,eight");

        assertEquals("*", p1.toString());
        assertEquals(p1, new WildcardPermission(p1.toString()));
        assertEquals("one", p2.toString());
        assertEquals(p2, new WildcardPermission(p2.toString()));
        assertEquals("one:two", p3.toString());
        assertEquals(p3, new WildcardPermission(p3.toString()));
        assertEquals("one,two:three,four", p4.toString());
        assertEquals(p4, new WildcardPermission(p4.toString()));
        assertEquals("one,two:three,four,five:six:seven,eight", p5.toString());
        assertEquals(p5, new WildcardPermission(p5.toString()));
    }

    @SuppressWarnings("checkstyle:MultipleVariableDeclarations")
    @Test
    void testWildcardLeftTermination() {
        WildcardPermission p1, p2, p3, p4;

        p1 = new WildcardPermission("one");
        p2 = new WildcardPermission("one:*");
        p3 = new WildcardPermission("one:*:*");
        p4 = new WildcardPermission("one:read");

        assertTrue(p1.implies(p2));
        assertTrue(p1.implies(p3));
        assertTrue(p1.implies(p4));

        assertTrue(p2.implies(p1));
        assertTrue(p2.implies(p3));
        assertTrue(p2.implies(p4));

        assertTrue(p3.implies(p1));
        assertTrue(p3.implies(p2));
        assertTrue(p3.implies(p4));

        assertFalse(p4.implies(p1));
        assertFalse(p4.implies(p2));
        assertFalse(p4.implies(p3));
    }
}
