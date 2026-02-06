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
package org.apache.shiro.guice;

import com.google.inject.TypeLiteral;
import com.google.inject.matcher.Matcher;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.easymock.EasyMock.createMock;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;

class ShiroMatchersTest {
    @Test
    @SuppressWarnings("rawtypes")
    void testTypeLiteral() throws Exception {
        Matcher<Class> classMatcher = createMock(Matcher.class);
        expect(classMatcher.matches(MatchingClass.class)).andReturn(true);
        expect(classMatcher.matches(NotMatchingClass.class)).andReturn(false);

        replay(classMatcher);

        Matcher<TypeLiteral> underTest = ShiroMatchers.typeLiteral(classMatcher);

        assertThat(underTest.matches(TypeLiteral.get(MatchingClass.class))).isTrue();
        assertThat(underTest.matches(TypeLiteral.get(NotMatchingClass.class))).isFalse();

        verify(classMatcher);
    }


    static class MatchingClass {
    }

    static class NotMatchingClass {
    }
}
