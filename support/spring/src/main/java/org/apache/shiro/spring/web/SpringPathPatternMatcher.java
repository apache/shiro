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

import org.apache.shiro.util.PatternMatcher;
import org.springframework.http.server.PathContainer;
import org.springframework.http.server.PathContainer.Options;
import org.springframework.web.util.pattern.PathPattern;
import org.springframework.web.util.pattern.PathPatternParser;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Matches Shiro's decoded application paths using Spring's parsed path patterns.
 * Matching is case-insensitive by default, consistent with Shiro's Ant matcher.
 */
public class SpringPathPatternMatcher implements PatternMatcher {
    private final PathPatternParser parser;
    private final ConcurrentMap<String, PathPattern> patterns = new ConcurrentHashMap<>();

    public SpringPathPatternMatcher() {
        this(new PathPatternParser());
    }

    public SpringPathPatternMatcher(PathPatternParser mvcParser) {
        parser = new PathPatternParser();
        parser.setCaseSensitive(false);
        parser.setPathOptions(mvcParser.getPathOptions());
    }

    /**
     * Parses and caches a configured pattern, rejecting invalid patterns at startup.
     * @param pattern the configured pattern
     * @return the parsed pattern
     */
    public PathPattern validatePattern(String pattern) {
        return patterns.computeIfAbsent(pattern, parser::parse);
    }

    @Override
    public boolean matches(String pattern, String source) {
        // Servlet paths have already been decoded; do not decode percent sequences a second time.
        return validatePattern(pattern).matches(PathContainer.parsePath(source,
                Options.create('/', false)));
    }

    @Override
    public boolean isCaseInsensitive() {
        return !parser.isCaseSensitive();
    }

    /**
     * Configures case sensitivity before any patterns have been parsed.
     * Reapplying the current setting is allowed.
     * @param caseInsensitive whether matching should ignore case
     * @throws IllegalStateException if changing the setting after a pattern has been parsed
     */
    @Override
    public void setCaseInsensitive(boolean caseInsensitive) {
        if (isCaseInsensitive() != caseInsensitive) {
            if (!patterns.isEmpty()) {
                throw new IllegalStateException("Cannot change case sensitivity after path patterns have been parsed.");
            }
            parser.setCaseSensitive(!caseInsensitive);
        }
    }
}
