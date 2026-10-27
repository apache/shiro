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
package org.apache.shiro.spring.web;

import org.junit.jupiter.api.Test;
import org.springframework.web.util.pattern.PathPatternParser;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalStateException;

class SpringPathPatternMatcherTest {

    @Test
    void matchesSpringPatterns() {
        SpringPathPatternMatcher matcher = new SpringPathPatternMatcher();
        PathPatternParser parser = new PathPatternParser();
        parser.setCaseSensitive(false);
        for (String pattern : new String[]{"/users/{id}", "/users/{id:[0-9]+}", "/users/*", "/users/**", "/users/{*rest}"}) {
            for (String path : new String[]{"/users", "/users/42", "/users/42/", "/users/42/profile", "/Users/42"}) {
                assertThat(matcher.matches(pattern, path))
                        .as("%s against %s", pattern, path)
                        .isEqualTo(parser.parse(pattern).matches(
                                org.springframework.http.server.PathContainer.parsePath(path)));
            }
        }
    }

    @Test
    void defaultsToCaseInsensitiveRegardlessOfMvcSetting() {
        assertThat(new SpringPathPatternMatcher().isCaseInsensitive()).isTrue();
        PathPatternParser parser = new PathPatternParser();
        assertThat(parser.isCaseSensitive()).isTrue();
        SpringPathPatternMatcher matcher = new SpringPathPatternMatcher(parser);
        assertThat(matcher.matches("/files/private/**", "/files/PRIVATE/report.pdf")).isTrue();
        assertThat(parser.isCaseSensitive()).isTrue();
    }

    @Test
    void doesNotDecodeServletPathsTwice() {
        SpringPathPatternMatcher matcher = new SpringPathPatternMatcher();
        assertThat(matcher.matches("/users/admin", "/users/%61dmin")).isFalse();
        assertThat(matcher.matches("/users/{id}", "/users/Jane Doe")).isTrue();
    }

    @Test
    void configuresCaseSensitivityBeforeParsing() {
        SpringPathPatternMatcher matcher = new SpringPathPatternMatcher();
        matcher.setCaseInsensitive(false);
        assertThat(matcher.matches("/users/{id}", "/Users/42")).isFalse();
        matcher.setCaseInsensitive(false);
        assertThat(matcher.matches("/users/{id}", "/Users/42")).isFalse();
    }

    @Test
    void rejectsChangingCaseSensitivityAfterMatching() {
        SpringPathPatternMatcher matcher = new SpringPathPatternMatcher();
        assertThat(matcher.matches("/users/{id}", "/Users/42")).isTrue();
        assertThatIllegalStateException().isThrownBy(() -> matcher.setCaseInsensitive(false));
        matcher.setCaseInsensitive(true);
        assertThat(matcher.matches("/users/{id}", "/Users/42")).isTrue();
    }

    @Test
    void rejectsChangingCaseSensitivityAfterValidation() {
        SpringPathPatternMatcher matcher = new SpringPathPatternMatcher();
        matcher.setCaseInsensitive(true);
        matcher.validatePattern("/users/{id}");
        assertThatIllegalStateException().isThrownBy(() -> matcher.setCaseInsensitive(false));
        matcher.setCaseInsensitive(true);
        assertThat(matcher.matches("/users/{id}", "/Users/42")).isTrue();
    }
}
