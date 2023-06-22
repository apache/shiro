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
package org.apache.shiro.util;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for the {@link RegExPatternMatcher}.
 *
 * @since 1.0
 */
public class RegExPatternMatcherTest {

    @Test
    void testSimplePattern() {
        assertPatternMatch("a*b", "aaaaaaab");
    }

    @Test
    void testMatchesWithCarriageReturn() {
        assertPatternMatch(".*", "/blah\n");
    }

    @Test
    void testMatchesWithLineFeed() {
        assertPatternMatch(".*", "/blah\r");
    }

    @Test
    void testCaseInsensitive() {
        RegExPatternMatcher pm = new RegExPatternMatcher();
        pm.setCaseInsensitive(true);
        assertPatternMatch("/blah", "/BlaH", pm);
    }

    @Test
    void testCaseSensitive() {
        assertPatternNotMatch("/blah", "/BlaH");
    }

    private void assertPatternMatch(String pattern, String path) {
        assertPatternMatch(pattern, path, new RegExPatternMatcher());
    }

    private void assertPatternMatch(String pattern, String path, PatternMatcher pm) {
        assertTrue(pm.matches(pattern, path), "Expected path '" + path + "' to match pattern '" + pattern + "'" );
    }

    private void assertPatternNotMatch(String pattern, String path) {
        assertPatternNotMatch(pattern, path, new RegExPatternMatcher());
    }

    private void assertPatternNotMatch(String pattern, String path, PatternMatcher pm) {
        assertFalse(pm.matches(pattern, path), "Expected path '" + path + "' to NOT match pattern '" + pattern + "'" );
    }
}
