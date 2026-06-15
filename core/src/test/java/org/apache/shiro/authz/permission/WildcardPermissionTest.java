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
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;

/**
 * @since 0.9
 */
public class WildcardPermissionTest {

    @Test
    void testNull() {
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> {
            new WildcardPermission(null);
        });
    }

    @Test
    void testEmpty() {
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> {
            new WildcardPermission("");
        });
    }

    @Test
    void testBlank() {
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> {
            new WildcardPermission("   ");
        });
    }

    @Test
    void testOnlyDelimiters() {
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> {
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
        assertThat(p1.implies(p2)).isTrue();
        assertThat(p2.implies(p1)).isTrue();

        // Case insensitive, different case
        p1 = new WildcardPermission("something");
        p2 = new WildcardPermission("SOMETHING");
        assertThat(p1.implies(p2)).isTrue();
        assertThat(p2.implies(p1)).isTrue();

        // Case insensitive, different word
        p1 = new WildcardPermission("something");
        p2 = new WildcardPermission("else");
        assertThat(p1.implies(p2)).isFalse();
        assertThat(p2.implies(p1)).isFalse();

        // Case sensitive same
        p1 = new WildcardPermission("BLAHBLAH", false);
        p2 = new WildcardPermission("BLAHBLAH", false);
        assertThat(p1.implies(p2)).isTrue();
        assertThat(p2.implies(p1)).isTrue();

        // Case sensitive, different case
        p1 = new WildcardPermission("BLAHBLAH", false);
        p2 = new WildcardPermission("bLAHBLAH", false);
        assertThat(p1.implies(p2)).isTrue();
        assertThat(p2.implies(p1)).isTrue();

        // Case sensitive, different word
        p1 = new WildcardPermission("BLAHBLAH", false);
        p2 = new WildcardPermission("whatwhat", false);
        assertThat(p1.implies(p2)).isFalse();
        assertThat(p2.implies(p1)).isFalse();

    }

    @SuppressWarnings("checkstyle:MultipleVariableDeclarations")
    @Test
    void testLists() {
        WildcardPermission p1, p2, p3;

        p1 = new WildcardPermission("one,two");
        p2 = new WildcardPermission("one");
        assertThat(p1.implies(p2)).isTrue();
        assertThat(p2.implies(p1)).isFalse();

        p1 = new WildcardPermission("one,two,three");
        p2 = new WildcardPermission("one,three");
        assertThat(p1.implies(p2)).isTrue();
        assertThat(p2.implies(p1)).isFalse();

        p1 = new WildcardPermission("one,two:one,two,three");
        p2 = new WildcardPermission("one:three");
        p3 = new WildcardPermission("one:two,three");
        assertThat(p1.implies(p2)).isTrue();
        assertThat(p2.implies(p1)).isFalse();
        assertThat(p1.implies(p3)).isTrue();
        assertThat(p2.implies(p3)).isFalse();
        assertThat(p3.implies(p2)).isTrue();

        p1 = new WildcardPermission("one,two,three:one,two,three:one,two");
        p2 = new WildcardPermission("one:three:two");
        assertThat(p1.implies(p2)).isTrue();
        assertThat(p2.implies(p1)).isFalse();

        p1 = new WildcardPermission("one");
        p2 = new WildcardPermission("one:two,three,four");
        p3 = new WildcardPermission("one:two,three,four:five:six:seven");
        assertThat(p1.implies(p2)).isTrue();
        assertThat(p1.implies(p3)).isTrue();
        assertThat(p2.implies(p1)).isFalse();
        assertThat(p3.implies(p1)).isFalse();
        assertThat(p2.implies(p3)).isTrue();
    }

    /**
     * Validates WildcardPermissions with that contain the same list parts are equal.
     */
    @Test
    void testListDifferentOrder() {

        WildcardPermission p6 = new WildcardPermission("one,two:three,four");
        WildcardPermission p6DiffOrder = new WildcardPermission("two,one:four,three");
        assertThat(p6DiffOrder).isEqualTo(p6);
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
        assertThat(p1.implies(p2)).isTrue();
        assertThat(p1.implies(p3)).isTrue();
        assertThat(p1.implies(p4)).isTrue();
        assertThat(p1.implies(p5)).isTrue();

        p1 = new WildcardPermission("newsletter:*");
        p2 = new WildcardPermission("newsletter:read");
        p3 = new WildcardPermission("newsletter:read,write");
        p4 = new WildcardPermission("newsletter:*");
        p5 = new WildcardPermission("newsletter:*:*");
        p6 = new WildcardPermission("newsletter:*:read");
        p7 = new WildcardPermission("newsletter:write:*");
        p8 = new WildcardPermission("newsletter:read,write:*");
        p9 = new WildcardPermission("newsletter");
        assertThat(p1.implies(p2)).isTrue();
        assertThat(p1.implies(p3)).isTrue();
        assertThat(p1.implies(p4)).isTrue();
        assertThat(p1.implies(p5)).isTrue();
        assertThat(p1.implies(p6)).isTrue();
        assertThat(p1.implies(p7)).isTrue();
        assertThat(p1.implies(p8)).isTrue();
        assertThat(p1.implies(p9)).isTrue();


        p1 = new WildcardPermission("newsletter:*:*");
        assertThat(p1.implies(p2)).isTrue();
        assertThat(p1.implies(p3)).isTrue();
        assertThat(p1.implies(p4)).isTrue();
        assertThat(p1.implies(p5)).isTrue();
        assertThat(p1.implies(p6)).isTrue();
        assertThat(p1.implies(p7)).isTrue();
        assertThat(p1.implies(p8)).isTrue();
        assertThat(p1.implies(p9)).isTrue();

        p1 = new WildcardPermission("newsletter:*:*:*");
        assertThat(p1.implies(p2)).isTrue();
        assertThat(p1.implies(p3)).isTrue();
        assertThat(p1.implies(p4)).isTrue();
        assertThat(p1.implies(p5)).isTrue();
        assertThat(p1.implies(p6)).isTrue();
        assertThat(p1.implies(p7)).isTrue();
        assertThat(p1.implies(p8)).isTrue();
        assertThat(p1.implies(p9)).isTrue();

        p1 = new WildcardPermission("newsletter");
        assertThat(p1.implies(p2)).isTrue();
        assertThat(p1.implies(p3)).isTrue();
        assertThat(p1.implies(p4)).isTrue();
        assertThat(p1.implies(p5)).isTrue();
        assertThat(p1.implies(p6)).isTrue();
        assertThat(p1.implies(p7)).isTrue();
        assertThat(p1.implies(p8)).isTrue();
        assertThat(p1.implies(p9)).isTrue();

        p1 = new WildcardPermission("newsletter:*:read");
        p2 = new WildcardPermission("newsletter:123:read");
        p3 = new WildcardPermission("newsletter:123,456:read,write");
        p4 = new WildcardPermission("newsletter:read");
        p5 = new WildcardPermission("newsletter:read,write");
        p6 = new WildcardPermission("newsletter:123:read:write");
        assertThat(p1.implies(p2)).isTrue();
        assertThat(p1.implies(p3)).isFalse();
        assertThat(p1.implies(p4)).isFalse();
        assertThat(p1.implies(p5)).isFalse();
        assertThat(p1.implies(p6)).isTrue();

        p1 = new WildcardPermission("newsletter:*:read:*");
        assertThat(p1.implies(p2)).isTrue();
        assertThat(p1.implies(p6)).isTrue();

    }

    @Test
    void testToString() {
        WildcardPermission p1 = new WildcardPermission("*");
        WildcardPermission p2 = new WildcardPermission("one");
        WildcardPermission p3 = new WildcardPermission("one:two");
        WildcardPermission p4 = new WildcardPermission("one,two:three,four");
        WildcardPermission p5 = new WildcardPermission("one,two:three,four,five:six:seven,eight");

        assertThat(p1.toString()).isEqualTo("*");
        assertThat(new WildcardPermission(p1.toString())).isEqualTo(p1);
        assertThat(p2.toString()).isEqualTo("one");
        assertThat(new WildcardPermission(p2.toString())).isEqualTo(p2);
        assertThat(p3.toString()).isEqualTo("one:two");
        assertThat(new WildcardPermission(p3.toString())).isEqualTo(p3);
        assertThat(p4.toString()).isEqualTo("one,two:three,four");
        assertThat(new WildcardPermission(p4.toString())).isEqualTo(p4);
        assertThat(p5.toString()).isEqualTo("one,two:three,four,five:six:seven,eight");
        assertThat(new WildcardPermission(p5.toString())).isEqualTo(p5);
    }

    @SuppressWarnings("checkstyle:MultipleVariableDeclarations")
    @Test
    void testWildcardLeftTermination() {
        WildcardPermission p1, p2, p3, p4;

        p1 = new WildcardPermission("one");
        p2 = new WildcardPermission("one:*");
        p3 = new WildcardPermission("one:*:*");
        p4 = new WildcardPermission("one:read");

        assertThat(p1.implies(p2)).isTrue();
        assertThat(p1.implies(p3)).isTrue();
        assertThat(p1.implies(p4)).isTrue();

        assertThat(p2.implies(p1)).isTrue();
        assertThat(p2.implies(p3)).isTrue();
        assertThat(p2.implies(p4)).isTrue();

        assertThat(p3.implies(p1)).isTrue();
        assertThat(p3.implies(p2)).isTrue();
        assertThat(p3.implies(p4)).isTrue();

        assertThat(p4.implies(p1)).isFalse();
        assertThat(p4.implies(p2)).isFalse();
        assertThat(p4.implies(p3)).isFalse();
    }
}
