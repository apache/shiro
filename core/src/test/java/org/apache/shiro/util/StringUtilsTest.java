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

import org.apache.shiro.lang.util.StringUtils;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @since 0.9
 */
public class StringUtilsTest {

    @Test
    void splitWithNullInput() {
        String line = null;
        String[] split = StringUtils.split(line);
        assertThat(split).isNull();
    }

    @Test
    void splitWithCommas() {
        String line = "shall,we,play,a,game?";
        String[] split = StringUtils.split(line);
        assertThat(split).isNotNull();
        assertThat(split.length).isEqualTo(5);
        assertThat(split[0]).isEqualTo("shall");
        assertThat(split[1]).isEqualTo("we");
        assertThat(split[2]).isEqualTo("play");
        assertThat(split[3]).isEqualTo("a");
        assertThat(split[4]).isEqualTo("game?");
    }

    @Test
    void splitWithCommasAndSpaces() {
        String line = "shall,we ,    play, a,game?";
        String[] split = StringUtils.split(line);
        assertThat(split).isNotNull();
        assertThat(split.length).isEqualTo(5);
        assertThat(split[0]).isEqualTo("shall");
        assertThat(split[1]).isEqualTo("we");
        assertThat(split[2]).isEqualTo("play");
        assertThat(split[3]).isEqualTo("a");
        assertThat(split[4]).isEqualTo("game?");
    }

    @Test
    void splitWithQuotedCommasAndSpaces() {
        String line = "shall, \"we, play\", a, game?";
        String[] split = StringUtils.split(line);
        assertThat(split).isNotNull();
        assertThat(split.length).isEqualTo(4);
        assertThat(split[0]).isEqualTo("shall");
        assertThat(split[1]).isEqualTo("we, play");
        assertThat(split[2]).isEqualTo("a");
        assertThat(split[3]).isEqualTo("game?");
    }

    @Test
    void splitWithQuotedCommasAndSpacesAndDifferentQuoteChars() {
        String line = "authc, test[blah], test[1,2,3], test[]";
        String[] split = StringUtils.split(line, ',', '[', ']', false, true);
        assertThat(split).isNotNull();
        assertThat(split.length).isEqualTo(4);
        assertThat(split[0]).isEqualTo("authc");
        assertThat(split[1]).isEqualTo("testblah");
        assertThat(split[2]).isEqualTo("test1,2,3");
        assertThat(split[3]).isEqualTo("test");
    }

    @Test
    void splitWithQuotedCommasAndSpacesAndDifferentQuoteCharsWhileRetainingQuotes() {
        String line = "authc, test[blah], test[1,2,3], test[]";
        String[] split = StringUtils.split(line, ',', '[', ']', true, true);
        assertThat(split).isNotNull();
        assertThat(split.length).isEqualTo(4);
        assertThat(split[0]).isEqualTo("authc");
        assertThat(split[1]).isEqualTo("test[blah]");
        assertThat(split[2]).isEqualTo("test[1,2,3]");
        assertThat(split[3]).isEqualTo("test[]");
    }

    @Test
    void splitTestWithQuotedCommas() {
        String line = "authc, test[blah], test[\"1,2,3\"], test[]";
        String[] split = StringUtils.split(line);
        assertThat(split).isNotNull();
        assertThat(split.length).isEqualTo(4);
        assertThat(split[0]).isEqualTo("authc");
        assertThat(split[1]).isEqualTo("test[blah]");
        assertThat(split[2]).isEqualTo("test[1,2,3]");
        assertThat(split[3]).isEqualTo("test[]");
    }

    @Test
    void splitWithQuotedCommasAndSpacesAndEscapedQuotes() {
        String line = "shall, \"\"\"we, play\", a, \"\"\"game?";
        String[] split = StringUtils.split(line);
        assertThat(split).isNotNull();
        assertThat(split.length).isEqualTo(4);
        assertThat(split[0]).isEqualTo("shall");
        assertThat(split[1]).isEqualTo("\"we, play");
        assertThat(split[2]).isEqualTo("a");
        assertThat(split[3]).isEqualTo("\"game?");
    }

}
