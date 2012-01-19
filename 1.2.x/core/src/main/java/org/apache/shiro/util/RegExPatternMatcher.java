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

import java.util.regex.Pattern;
import java.util.regex.Matcher;

/**
 * {@code PatternMatcher} implementation that uses standard {@link java.util.regex} objects.
 *
 * @see Pattern
 * @since 1.0
 */
public class RegExPatternMatcher implements PatternMatcher {

    /**
     * Simple implementation that merely uses the default pattern comparison logic provided by the
     * JDK.
     * <p/>This implementation essentially executes the following:
     * <pre>
     * Pattern p = Pattern.compile(pattern);
     * Matcher m = p.matcher(source);
     * return m.matches();</pre>
     * @param pattern the pattern to match against
     * @param source  the source to match
     * @return {@code true} if the source matches the required pattern, {@code false} otherwise.
     */
    public boolean matches(String pattern, String source) {
        if (pattern == null) {
            throw new IllegalArgumentException("pattern argument cannot be null.");
        }
        Pattern p = Pattern.compile(pattern);
        Matcher m = p.matcher(source);
        return m.matches();
    }
}
