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

import static org.assertj.core.api.Assertions.assertThat;

@SuppressWarnings("checkstyle:LineLength")
/**
 * Unit tests for {@link AntPathMatcher}.
 * <p>
 * Adapted from
 * <a href="https://github.com/spring-projects/spring-framework/blob/b92d249f450920e48e640af6bbd0bd509e7d707d/spring-core/src/test/java/org/springframework/util/AntPathMatcherTests.java"/>
 * Spring Framework's similar AntPathMatcherTests</a>
 */
public class AntPathMatcherTests {

    private final AntPathMatcher pathMatcher = new AntPathMatcher();

    @SuppressWarnings("checkstyle:MethodLength")
    @Test
    void match() {
        // test exact matching
        assertThat(pathMatcher.match("test", "test")).isTrue();
        assertThat(pathMatcher.match("/test", "/test")).isTrue();
        assertThat(pathMatcher.match("https://example.org", "https://example.org")).isTrue();
        assertThat(pathMatcher.match("/test.jpg", "test.jpg")).isFalse();
        assertThat(pathMatcher.match("test", "/test")).isFalse();
        assertThat(pathMatcher.match("/test", "test")).isFalse();

        // test matching with ?'s
        assertThat(pathMatcher.match("t?st", "test")).isTrue();
        assertThat(pathMatcher.match("??st", "test")).isTrue();
        assertThat(pathMatcher.match("tes?", "test")).isTrue();
        assertThat(pathMatcher.match("te??", "test")).isTrue();
        assertThat(pathMatcher.match("?es?", "test")).isTrue();
        assertThat(pathMatcher.match("tes?", "tes")).isFalse();
        assertThat(pathMatcher.match("tes?", "testt")).isFalse();
        assertThat(pathMatcher.match("tes?", "tsst")).isFalse();

        // test matching with *'s
        assertThat(pathMatcher.match("*", "test")).isTrue();
        assertThat(pathMatcher.match("test*", "test")).isTrue();
        assertThat(pathMatcher.match("test*", "testTest")).isTrue();
        assertThat(pathMatcher.match("test/*", "test/Test")).isTrue();
        assertThat(pathMatcher.match("test/*", "test/t")).isTrue();
        assertThat(pathMatcher.match("test/*", "test/")).isTrue();
        assertThat(pathMatcher.match("*test*", "AnothertestTest")).isTrue();
        assertThat(pathMatcher.match("*test", "Anothertest")).isTrue();
        assertThat(pathMatcher.match("*.*", "test.")).isTrue();
        assertThat(pathMatcher.match("*.*", "test.test")).isTrue();
        assertThat(pathMatcher.match("*.*", "test.test.test")).isTrue();
        assertThat(pathMatcher.match("test*aaa", "testblaaaa")).isTrue();
        assertThat(pathMatcher.match("test*", "tst")).isFalse();
        assertThat(pathMatcher.match("test*", "tsttest")).isFalse();
        assertThat(pathMatcher.match("test*", "test/")).isFalse();
        assertThat(pathMatcher.match("test*", "test/t")).isFalse();
        assertThat(pathMatcher.match("test/*", "test")).isFalse();
        assertThat(pathMatcher.match("*test*", "tsttst")).isFalse();
        assertThat(pathMatcher.match("*test", "tsttst")).isFalse();
        assertThat(pathMatcher.match("*.*", "tsttst")).isFalse();
        assertThat(pathMatcher.match("test*aaa", "test")).isFalse();
        assertThat(pathMatcher.match("test*aaa", "testblaaab")).isFalse();

        // test matching with ?'s and /'s
        assertThat(pathMatcher.match("/?", "/a")).isTrue();
        assertThat(pathMatcher.match("/?/a", "/a/a")).isTrue();
        assertThat(pathMatcher.match("/a/?", "/a/b")).isTrue();
        assertThat(pathMatcher.match("/??/a", "/aa/a")).isTrue();
        assertThat(pathMatcher.match("/a/??", "/a/bb")).isTrue();
        assertThat(pathMatcher.match("/?", "/a")).isTrue();

        // test matching with **'s
        assertThat(pathMatcher.match("/**", "/testing/testing")).isTrue();
        assertThat(pathMatcher.match("/*/**", "/testing/testing")).isTrue();
        assertThat(pathMatcher.match("/**/*", "/testing/testing")).isTrue();
        assertThat(pathMatcher.match("/bla/**/bla", "/bla/testing/testing/bla")).isTrue();
        assertThat(pathMatcher.match("/bla/**/bla", "/bla/testing/testing/bla/bla")).isTrue();
        assertThat(pathMatcher.match("/**/test", "/bla/bla/test")).isTrue();
        assertThat(pathMatcher.match("/bla/**/**/bla", "/bla/bla/bla/bla/bla/bla")).isTrue();
        assertThat(pathMatcher.match("/bla*bla/test", "/blaXXXbla/test")).isTrue();
        assertThat(pathMatcher.match("/*bla/test", "/XXXbla/test")).isTrue();
        assertThat(pathMatcher.match("/bla*bla/test", "/blaXXXbl/test")).isFalse();
        assertThat(pathMatcher.match("/*bla/test", "XXXblab/test")).isFalse();
        assertThat(pathMatcher.match("/*bla/test", "XXXbl/test")).isFalse();

        assertThat(pathMatcher.match("/????", "/bala/bla")).isFalse();
        assertThat(pathMatcher.match("/**/*bla", "/bla/bla/bla/bbb")).isFalse();

        assertThat(pathMatcher.match("/*bla*/**/bla/**", "/XXXblaXXXX/testing/testing/bla/testing/testing/")).isTrue();
        assertThat(pathMatcher.match("/*bla*/**/bla/*", "/XXXblaXXXX/testing/testing/bla/testing")).isTrue();
        assertThat(pathMatcher.match("/*bla*/**/bla/**", "/XXXblaXXXX/testing/testing/bla/testing/testing")).isTrue();
        assertThat(pathMatcher.match("/*bla*/**/bla/**", "/XXXblaXXXX/testing/testing/bla/testing/testing.jpg")).isTrue();

        assertThat(pathMatcher.match("*bla*/**/bla/**", "XXXblaXXXX/testing/testing/bla/testing/testing/")).isTrue();
        assertThat(pathMatcher.match("*bla*/**/bla/*", "XXXblaXXXX/testing/testing/bla/testing")).isTrue();
        assertThat(pathMatcher.match("*bla*/**/bla/**", "XXXblaXXXX/testing/testing/bla/testing/testing")).isTrue();
        assertThat(pathMatcher.match("*bla*/**/bla/*", "XXXblaXXXX/testing/testing/bla/testing/testing")).isFalse();

        assertThat(pathMatcher.match("/x/x/**/bla", "/x/x/x/")).isFalse();

        assertThat(pathMatcher.match("/foo/bar/**", "/foo/bar")).isTrue();

        assertThat(pathMatcher.match("", "")).isTrue();
    }

    @Test
    void matchWithNullPath() {
        assertThat(pathMatcher.match("/test", null)).isFalse();
        assertThat(pathMatcher.match("/", null)).isFalse();
        assertThat(pathMatcher.match(null, null)).isFalse();
    }

    @SuppressWarnings("checkstyle:MethodLength")
    @Test
    void matchStart() {
        // test exact matching
        assertThat(pathMatcher.matchStart("test", "test")).isTrue();
        assertThat(pathMatcher.matchStart("/test", "/test")).isTrue();
        assertThat(pathMatcher.matchStart("/test.jpg", "test.jpg")).isFalse();
        assertThat(pathMatcher.matchStart("test", "/test")).isFalse();
        assertThat(pathMatcher.matchStart("/test", "test")).isFalse();

        // test matching with ?'s
        assertThat(pathMatcher.matchStart("t?st", "test")).isTrue();
        assertThat(pathMatcher.matchStart("??st", "test")).isTrue();
        assertThat(pathMatcher.matchStart("tes?", "test")).isTrue();
        assertThat(pathMatcher.matchStart("te??", "test")).isTrue();
        assertThat(pathMatcher.matchStart("?es?", "test")).isTrue();
        assertThat(pathMatcher.matchStart("tes?", "tes")).isFalse();
        assertThat(pathMatcher.matchStart("tes?", "testt")).isFalse();
        assertThat(pathMatcher.matchStart("tes?", "tsst")).isFalse();

        // test matching with *'s
        assertThat(pathMatcher.matchStart("*", "test")).isTrue();
        assertThat(pathMatcher.matchStart("test*", "test")).isTrue();
        assertThat(pathMatcher.matchStart("test*", "testTest")).isTrue();
        assertThat(pathMatcher.matchStart("test/*", "test/Test")).isTrue();
        assertThat(pathMatcher.matchStart("test/*", "test/t")).isTrue();
        assertThat(pathMatcher.matchStart("test/*", "test/")).isTrue();
        assertThat(pathMatcher.matchStart("*test*", "AnothertestTest")).isTrue();
        assertThat(pathMatcher.matchStart("*test", "Anothertest")).isTrue();
        assertThat(pathMatcher.matchStart("*.*", "test.")).isTrue();
        assertThat(pathMatcher.matchStart("*.*", "test.test")).isTrue();
        assertThat(pathMatcher.matchStart("*.*", "test.test.test")).isTrue();
        assertThat(pathMatcher.matchStart("test*aaa", "testblaaaa")).isTrue();
        assertThat(pathMatcher.matchStart("test*", "tst")).isFalse();
        assertThat(pathMatcher.matchStart("test*", "test/")).isFalse();
        assertThat(pathMatcher.matchStart("test*", "tsttest")).isFalse();
        assertThat(pathMatcher.matchStart("test*", "test/")).isFalse();
        assertThat(pathMatcher.matchStart("test*", "test/t")).isFalse();
        assertThat(pathMatcher.matchStart("test/*", "test")).isTrue();
        assertThat(pathMatcher.matchStart("test/t*.txt", "test")).isTrue();
        assertThat(pathMatcher.matchStart("*test*", "tsttst")).isFalse();
        assertThat(pathMatcher.matchStart("*test", "tsttst")).isFalse();
        assertThat(pathMatcher.matchStart("*.*", "tsttst")).isFalse();
        assertThat(pathMatcher.matchStart("test*aaa", "test")).isFalse();
        assertThat(pathMatcher.matchStart("test*aaa", "testblaaab")).isFalse();

        // test matching with ?'s and /'s
        assertThat(pathMatcher.matchStart("/?", "/a")).isTrue();
        assertThat(pathMatcher.matchStart("/?/a", "/a/a")).isTrue();
        assertThat(pathMatcher.matchStart("/a/?", "/a/b")).isTrue();
        assertThat(pathMatcher.matchStart("/??/a", "/aa/a")).isTrue();
        assertThat(pathMatcher.matchStart("/a/??", "/a/bb")).isTrue();
        assertThat(pathMatcher.matchStart("/?", "/a")).isTrue();

        // test matching with **'s
        assertThat(pathMatcher.matchStart("/**", "/testing/testing")).isTrue();
        assertThat(pathMatcher.matchStart("/*/**", "/testing/testing")).isTrue();
        assertThat(pathMatcher.matchStart("/**/*", "/testing/testing")).isTrue();
        assertThat(pathMatcher.matchStart("test*/**", "test/")).isTrue();
        assertThat(pathMatcher.matchStart("test*/**", "test/t")).isTrue();
        assertThat(pathMatcher.matchStart("/bla/**/bla", "/bla/testing/testing/bla")).isTrue();
        assertThat(pathMatcher.matchStart("/bla/**/bla", "/bla/testing/testing/bla/bla")).isTrue();
        assertThat(pathMatcher.matchStart("/**/test", "/bla/bla/test")).isTrue();
        assertThat(pathMatcher.matchStart("/bla/**/**/bla", "/bla/bla/bla/bla/bla/bla")).isTrue();
        assertThat(pathMatcher.matchStart("/bla*bla/test", "/blaXXXbla/test")).isTrue();
        assertThat(pathMatcher.matchStart("/*bla/test", "/XXXbla/test")).isTrue();
        assertThat(pathMatcher.matchStart("/bla*bla/test", "/blaXXXbl/test")).isFalse();
        assertThat(pathMatcher.matchStart("/*bla/test", "XXXblab/test")).isFalse();
        assertThat(pathMatcher.matchStart("/*bla/test", "XXXbl/test")).isFalse();

        assertThat(pathMatcher.matchStart("/????", "/bala/bla")).isFalse();
        assertThat(pathMatcher.matchStart("/**/*bla", "/bla/bla/bla/bbb")).isTrue();

        assertThat(pathMatcher.matchStart("/*bla*/**/bla/**", "/XXXblaXXXX/testing/testing/bla/testing/testing/")).isTrue();
        assertThat(pathMatcher.matchStart("/*bla*/**/bla/*", "/XXXblaXXXX/testing/testing/bla/testing")).isTrue();
        assertThat(pathMatcher.matchStart("/*bla*/**/bla/**", "/XXXblaXXXX/testing/testing/bla/testing/testing")).isTrue();
        assertThat(pathMatcher.matchStart("/*bla*/**/bla/**", "/XXXblaXXXX/testing/testing/bla/testing/testing.jpg")).isTrue();

        assertThat(pathMatcher.matchStart("*bla*/**/bla/**", "XXXblaXXXX/testing/testing/bla/testing/testing/")).isTrue();
        assertThat(pathMatcher.matchStart("*bla*/**/bla/*", "XXXblaXXXX/testing/testing/bla/testing")).isTrue();
        assertThat(pathMatcher.matchStart("*bla*/**/bla/**", "XXXblaXXXX/testing/testing/bla/testing/testing")).isTrue();
        assertThat(pathMatcher.matchStart("*bla*/**/bla/*", "XXXblaXXXX/testing/testing/bla/testing/testing")).isTrue();

        assertThat(pathMatcher.matchStart("/x/x/**/bla", "/x/x/x/")).isTrue();

        assertThat(pathMatcher.matchStart("", "")).isTrue();
    }

    @Test
    void uniqueDelimiter() {
        pathMatcher.setPathSeparator(".");

        // test exact matching
        assertThat(pathMatcher.match("test", "test")).isTrue();
        assertThat(pathMatcher.match(".test", ".test")).isTrue();
        assertThat(pathMatcher.match(".test/jpg", "test/jpg")).isFalse();
        assertThat(pathMatcher.match("test", ".test")).isFalse();
        assertThat(pathMatcher.match(".test", "test")).isFalse();

        // test matching with ?'s
        assertThat(pathMatcher.match("t?st", "test")).isTrue();
        assertThat(pathMatcher.match("??st", "test")).isTrue();
        assertThat(pathMatcher.match("tes?", "test")).isTrue();
        assertThat(pathMatcher.match("te??", "test")).isTrue();
        assertThat(pathMatcher.match("?es?", "test")).isTrue();
        assertThat(pathMatcher.match("tes?", "tes")).isFalse();
        assertThat(pathMatcher.match("tes?", "testt")).isFalse();
        assertThat(pathMatcher.match("tes?", "tsst")).isFalse();

        // test matching with *'s
        assertThat(pathMatcher.match("*", "test")).isTrue();
        assertThat(pathMatcher.match("test*", "test")).isTrue();
        assertThat(pathMatcher.match("test*", "testTest")).isTrue();
        assertThat(pathMatcher.match("*test*", "AnothertestTest")).isTrue();
        assertThat(pathMatcher.match("*test", "Anothertest")).isTrue();
        assertThat(pathMatcher.match("*/*", "test/")).isTrue();
        assertThat(pathMatcher.match("*/*", "test/test")).isTrue();
        assertThat(pathMatcher.match("*/*", "test/test/test")).isTrue();
        assertThat(pathMatcher.match("test*aaa", "testblaaaa")).isTrue();
        assertThat(pathMatcher.match("test*", "tst")).isFalse();
        assertThat(pathMatcher.match("test*", "tsttest")).isFalse();
        assertThat(pathMatcher.match("*test*", "tsttst")).isFalse();
        assertThat(pathMatcher.match("*test", "tsttst")).isFalse();
        assertThat(pathMatcher.match("*/*", "tsttst")).isFalse();
        assertThat(pathMatcher.match("test*aaa", "test")).isFalse();
        assertThat(pathMatcher.match("test*aaa", "testblaaab")).isFalse();

        // test matching with ?'s and .'s
        assertThat(pathMatcher.match(".?", ".a")).isTrue();
        assertThat(pathMatcher.match(".?.a", ".a.a")).isTrue();
        assertThat(pathMatcher.match(".a.?", ".a.b")).isTrue();
        assertThat(pathMatcher.match(".??.a", ".aa.a")).isTrue();
        assertThat(pathMatcher.match(".a.??", ".a.bb")).isTrue();
        assertThat(pathMatcher.match(".?", ".a")).isTrue();

        // test matching with **'s
        assertThat(pathMatcher.match(".**", ".testing.testing")).isTrue();
        assertThat(pathMatcher.match(".*.**", ".testing.testing")).isTrue();
        assertThat(pathMatcher.match(".**.*", ".testing.testing")).isTrue();
        assertThat(pathMatcher.match(".bla.**.bla", ".bla.testing.testing.bla")).isTrue();
        assertThat(pathMatcher.match(".bla.**.bla", ".bla.testing.testing.bla.bla")).isTrue();
        assertThat(pathMatcher.match(".**.test", ".bla.bla.test")).isTrue();
        assertThat(pathMatcher.match(".bla.**.**.bla", ".bla.bla.bla.bla.bla.bla")).isTrue();
        assertThat(pathMatcher.match(".bla*bla.test", ".blaXXXbla.test")).isTrue();
        assertThat(pathMatcher.match(".*bla.test", ".XXXbla.test")).isTrue();
        assertThat(pathMatcher.match(".bla*bla.test", ".blaXXXbl.test")).isFalse();
        assertThat(pathMatcher.match(".*bla.test", "XXXblab.test")).isFalse();
        assertThat(pathMatcher.match(".*bla.test", "XXXbl.test")).isFalse();
    }

    @Test
    void extractPathWithinPattern() throws Exception {
        assertThat(pathMatcher.extractPathWithinPattern("/docs/commit.html", "/docs/commit.html")).isEqualTo("");

        assertThat(pathMatcher.extractPathWithinPattern("/docs/*", "/docs/cvs/commit")).isEqualTo("cvs/commit");
        assertThat(pathMatcher.extractPathWithinPattern("/docs/cvs/*.html", "/docs/cvs/commit.html")).isEqualTo("commit.html");
        assertThat(pathMatcher.extractPathWithinPattern("/docs/**", "/docs/cvs/commit")).isEqualTo("cvs/commit");
        assertThat(pathMatcher.extractPathWithinPattern("/docs/**/*.html", "/docs/cvs/commit.html")).isEqualTo("cvs/commit.html");
        assertThat(pathMatcher.extractPathWithinPattern("/docs/**/*.html", "/docs/commit.html")).isEqualTo("commit.html");
        assertThat(pathMatcher.extractPathWithinPattern("/*.html", "/commit.html")).isEqualTo("commit.html");
        assertThat(pathMatcher.extractPathWithinPattern("/*.html", "/docs/commit.html")).isEqualTo("docs/commit.html");
        assertThat(pathMatcher.extractPathWithinPattern("*.html", "/commit.html")).isEqualTo("/commit.html");
        assertThat(pathMatcher.extractPathWithinPattern("*.html", "/docs/commit.html")).isEqualTo("/docs/commit.html");
        assertThat(pathMatcher.extractPathWithinPattern("**/*.*", "/docs/commit.html")).isEqualTo("/docs/commit.html");
        assertThat(pathMatcher.extractPathWithinPattern("*", "/docs/commit.html")).isEqualTo("/docs/commit.html");
        assertThat(pathMatcher.extractPathWithinPattern("**/commit.html", "/docs/cvs/other/commit.html")).isEqualTo("/docs/cvs/other/commit.html");
        assertThat(pathMatcher.extractPathWithinPattern("/docs/**/commit.html", "/docs/cvs/other/commit.html")).isEqualTo("cvs/other/commit.html");
        assertThat(pathMatcher.extractPathWithinPattern("/docs/**/**/**/**", "/docs/cvs/other/commit.html")).isEqualTo("cvs/other/commit.html");

        assertThat(pathMatcher.extractPathWithinPattern("/d?cs/*", "/docs/cvs/commit")).isEqualTo("docs/cvs/commit");
        assertThat(pathMatcher.extractPathWithinPattern("/docs/c?s/*.html", "/docs/cvs/commit.html")).isEqualTo("cvs/commit.html");
        assertThat(pathMatcher.extractPathWithinPattern("/d?cs/**", "/docs/cvs/commit")).isEqualTo("docs/cvs/commit");
        assertThat(pathMatcher.extractPathWithinPattern("/d?cs/**/*.html", "/docs/cvs/commit.html")).isEqualTo("docs/cvs/commit.html");
    }

    @Test
    void spaceInTokens() {
        assertThat(pathMatcher.match("/group/sales/members", "/group/sales/members")).isTrue();
        assertThat(pathMatcher.match("/group/sales/members", "/Group/  sales/Members")).isFalse();
    }

    @Test
    void isPattern() {
        assertThat(pathMatcher.isPattern("/test/*")).isTrue();
        assertThat(pathMatcher.isPattern("/test/**/name")).isTrue();
        assertThat(pathMatcher.isPattern("/test?")).isTrue();

        assertThat(pathMatcher.isPattern("/test/{name}")).isFalse();
        assertThat(pathMatcher.isPattern("/test/name")).isFalse();
        assertThat(pathMatcher.isPattern("/test/foo{bar")).isFalse();
    }

    @Test
    void matches() {
        assertThat(pathMatcher.matches("/foo/*", "/foo/")).isTrue();
    }

    @Test
    void isPatternWithNullPath() {
        assertThat(pathMatcher.isPattern(null)).isFalse();
    }
}
