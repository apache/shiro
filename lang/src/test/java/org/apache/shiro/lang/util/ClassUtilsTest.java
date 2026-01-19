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

        assertEquals(boolean.class, ClassUtils.forName("boolean"));
        assertEquals(byte.class, ClassUtils.forName("byte"));
        assertEquals(char.class, ClassUtils.forName("char"));
        assertEquals(short.class, ClassUtils.forName("short"));
        assertEquals(int.class, ClassUtils.forName("int"));
        assertEquals(long.class, ClassUtils.forName("long"));
        assertEquals(float.class, ClassUtils.forName("float"));
        assertEquals(double.class, ClassUtils.forName("double"));
        assertEquals(void.class, ClassUtils.forName("void"));

        assertEquals(boolean.class, ClassUtils.forName(boolean.class.getName()));
        assertEquals(byte.class, ClassUtils.forName(byte.class.getName()));
        assertEquals(char.class, ClassUtils.forName(char.class.getName()));
        assertEquals(short.class, ClassUtils.forName(short.class.getName()));
        assertEquals(int.class, ClassUtils.forName(int.class.getName()));
        assertEquals(long.class, ClassUtils.forName(long.class.getName()));
        assertEquals(float.class, ClassUtils.forName(float.class.getName()));
        assertEquals(double.class, ClassUtils.forName(double.class.getName()));
        assertEquals(void.class, ClassUtils.forName(void.class.getName()));

    }

    @Test
    void testGetPrimitiveArrays() throws UnknownClassException {

        assertEquals(boolean[].class, ClassUtils.forName("[Z"));
        assertEquals(byte[].class, ClassUtils.forName("[B"));
        assertEquals(char[].class, ClassUtils.forName("[C"));
        assertEquals(short[].class, ClassUtils.forName("[S"));
        assertEquals(int[].class, ClassUtils.forName("[I"));
        assertEquals(long[].class, ClassUtils.forName("[J"));
        assertEquals(float[].class, ClassUtils.forName("[F"));
        assertEquals(double[].class, ClassUtils.forName("[D"));


        assertEquals(boolean[].class, ClassUtils.forName(boolean[].class.getName()));
        assertEquals(byte[].class, ClassUtils.forName(byte[].class.getName()));
        assertEquals(char[].class, ClassUtils.forName(char[].class.getName()));
        assertEquals(short[].class, ClassUtils.forName(short[].class.getName()));
        assertEquals(int[].class, ClassUtils.forName(int[].class.getName()));
        assertEquals(long[].class, ClassUtils.forName(long[].class.getName()));
        assertEquals(float[].class, ClassUtils.forName(float[].class.getName()));
        assertEquals(double[].class, ClassUtils.forName(double[].class.getName()));
    }

    @Test
    void testGetClass() {
        assertEquals(String.class, ClassUtils.forName("java.lang.String"));
        assertEquals(String[].class, ClassUtils.forName("[Ljava.lang.String;"));
        assertEquals(String.class, ClassUtils.forName(String.class.getName()));
        assertEquals(String[].class, ClassUtils.forName(String[].class.getName()));

        assertEquals(ClassUtilsTest.class, ClassUtils.forName("org.apache.shiro.lang.util.ClassUtilsTest"));
        assertEquals(ClassUtilsTest[].class, ClassUtils.forName("[Lorg.apache.shiro.lang.util.ClassUtilsTest;"));
        assertEquals(ClassUtilsTest.class, ClassUtils.forName(ClassUtilsTest.class.getName()));
        assertEquals(ClassUtilsTest[].class, ClassUtils.forName(ClassUtilsTest[].class.getName()));
    }
}
