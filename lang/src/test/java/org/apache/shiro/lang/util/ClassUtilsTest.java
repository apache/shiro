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
package org.apache.shiro.lang.util;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ClassUtilsTest {

    @Test
    void testGetPrimitiveClasses() throws UnknownClassException {

        assertThat(ClassUtils.forName("boolean")).isEqualTo(boolean.class);
        assertThat(ClassUtils.forName("byte")).isEqualTo(byte.class);
        assertThat(ClassUtils.forName("char")).isEqualTo(char.class);
        assertThat(ClassUtils.forName("short")).isEqualTo(short.class);
        assertThat(ClassUtils.forName("int")).isEqualTo(int.class);
        assertThat(ClassUtils.forName("long")).isEqualTo(long.class);
        assertThat(ClassUtils.forName("float")).isEqualTo(float.class);
        assertThat(ClassUtils.forName("double")).isEqualTo(double.class);
        assertThat(ClassUtils.forName("void")).isEqualTo(void.class);

        assertThat(ClassUtils.forName(boolean.class.getName())).isEqualTo(boolean.class);
        assertThat(ClassUtils.forName(byte.class.getName())).isEqualTo(byte.class);
        assertThat(ClassUtils.forName(char.class.getName())).isEqualTo(char.class);
        assertThat(ClassUtils.forName(short.class.getName())).isEqualTo(short.class);
        assertThat(ClassUtils.forName(int.class.getName())).isEqualTo(int.class);
        assertThat(ClassUtils.forName(long.class.getName())).isEqualTo(long.class);
        assertThat(ClassUtils.forName(float.class.getName())).isEqualTo(float.class);
        assertThat(ClassUtils.forName(double.class.getName())).isEqualTo(double.class);
        assertThat(ClassUtils.forName(void.class.getName())).isEqualTo(void.class);

    }

    @Test
    void testGetPrimitiveArrays() throws UnknownClassException {

        assertThat(ClassUtils.forName("[Z")).isEqualTo(boolean[].class);
        assertThat(ClassUtils.forName("[B")).isEqualTo(byte[].class);
        assertThat(ClassUtils.forName("[C")).isEqualTo(char[].class);
        assertThat(ClassUtils.forName("[S")).isEqualTo(short[].class);
        assertThat(ClassUtils.forName("[I")).isEqualTo(int[].class);
        assertThat(ClassUtils.forName("[J")).isEqualTo(long[].class);
        assertThat(ClassUtils.forName("[F")).isEqualTo(float[].class);
        assertThat(ClassUtils.forName("[D")).isEqualTo(double[].class);


        assertThat(ClassUtils.forName(boolean[].class.getName())).isEqualTo(boolean[].class);
        assertThat(ClassUtils.forName(byte[].class.getName())).isEqualTo(byte[].class);
        assertThat(ClassUtils.forName(char[].class.getName())).isEqualTo(char[].class);
        assertThat(ClassUtils.forName(short[].class.getName())).isEqualTo(short[].class);
        assertThat(ClassUtils.forName(int[].class.getName())).isEqualTo(int[].class);
        assertThat(ClassUtils.forName(long[].class.getName())).isEqualTo(long[].class);
        assertThat(ClassUtils.forName(float[].class.getName())).isEqualTo(float[].class);
        assertThat(ClassUtils.forName(double[].class.getName())).isEqualTo(double[].class);
    }

    @Test
    void testGetClass() {
        assertThat(ClassUtils.forName("java.lang.String")).isEqualTo(String.class);
        assertThat(ClassUtils.forName("[Ljava.lang.String;")).isEqualTo(String[].class);
        assertThat(ClassUtils.forName(String.class.getName())).isEqualTo(String.class);
        assertThat(ClassUtils.forName(String[].class.getName())).isEqualTo(String[].class);

        assertThat(ClassUtils.forName("org.apache.shiro.lang.util.ClassUtilsTest")).isEqualTo(ClassUtilsTest.class);
        assertThat(ClassUtils.forName("[Lorg.apache.shiro.lang.util.ClassUtilsTest;")).isEqualTo(ClassUtilsTest[].class);
        assertThat(ClassUtils.forName(ClassUtilsTest.class.getName())).isEqualTo(ClassUtilsTest.class);
        assertThat(ClassUtils.forName(ClassUtilsTest[].class.getName())).isEqualTo(ClassUtilsTest[].class);
    }
}
