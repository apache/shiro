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

import static org.junit.jupiter.api.Assertions.assertEquals;


class ClassUtilsTest {

    @Test
    void testGetPrimitiveClasses() throws UnknownClassException {

        assertEquals(ClassUtils.forName("boolean"), boolean.class);
        assertEquals(ClassUtils.forName("byte"), byte.class);
        assertEquals(ClassUtils.forName("char"), char.class);
        assertEquals(ClassUtils.forName("short"), short.class);
        assertEquals(ClassUtils.forName("int"), int.class);
        assertEquals(ClassUtils.forName("long"), long.class);
        assertEquals(ClassUtils.forName("float"), float.class);
        assertEquals(ClassUtils.forName("double"), double.class);
        assertEquals(ClassUtils.forName("void"), void.class);

        assertEquals(ClassUtils.forName(boolean.class.getName()), boolean.class);
        assertEquals(ClassUtils.forName(byte.class.getName()), byte.class);
        assertEquals(ClassUtils.forName(char.class.getName()), char.class);
        assertEquals(ClassUtils.forName(short.class.getName()), short.class);
        assertEquals(ClassUtils.forName(int.class.getName()), int.class);
        assertEquals(ClassUtils.forName(long.class.getName()), long.class);
        assertEquals(ClassUtils.forName(float.class.getName()), float.class);
        assertEquals(ClassUtils.forName(double.class.getName()), double.class);
        assertEquals(ClassUtils.forName(void.class.getName()), void.class);

    }

    @Test
    void testGetPrimitiveArrays() throws UnknownClassException {

        assertEquals(ClassUtils.forName("[Z"), boolean[].class);
        assertEquals(ClassUtils.forName("[B"), byte[].class);
        assertEquals(ClassUtils.forName("[C"), char[].class);
        assertEquals(ClassUtils.forName("[S"), short[].class);
        assertEquals(ClassUtils.forName("[I"), int[].class);
        assertEquals(ClassUtils.forName("[J"), long[].class);
        assertEquals(ClassUtils.forName("[F"), float[].class);
        assertEquals(ClassUtils.forName("[D"), double[].class);


        assertEquals(ClassUtils.forName(boolean[].class.getName()), boolean[].class);
        assertEquals(ClassUtils.forName(byte[].class.getName()), byte[].class);
        assertEquals(ClassUtils.forName(char[].class.getName()), char[].class);
        assertEquals(ClassUtils.forName(short[].class.getName()), short[].class);
        assertEquals(ClassUtils.forName(int[].class.getName()), int[].class);
        assertEquals(ClassUtils.forName(long[].class.getName()), long[].class);
        assertEquals(ClassUtils.forName(float[].class.getName()), float[].class);
        assertEquals(ClassUtils.forName(double[].class.getName()), double[].class);
    }

    @Test
    void testGetClass() {
        assertEquals(ClassUtils.forName("java.lang.String"), String.class);
        assertEquals(ClassUtils.forName("[Ljava.lang.String;"), String[].class);
        assertEquals(ClassUtils.forName(String.class.getName()), String.class);
        assertEquals(ClassUtils.forName(String[].class.getName()), String[].class);

        assertEquals(ClassUtils.forName("org.apache.shiro.lang.util.ClassUtilsTest"), ClassUtilsTest.class);
        assertEquals(ClassUtils.forName("[Lorg.apache.shiro.lang.util.ClassUtilsTest;"), ClassUtilsTest[].class);
        assertEquals(ClassUtils.forName(ClassUtilsTest.class.getName()), ClassUtilsTest.class);
        assertEquals(ClassUtils.forName(ClassUtilsTest[].class.getName()), ClassUtilsTest[].class);
    }
}
