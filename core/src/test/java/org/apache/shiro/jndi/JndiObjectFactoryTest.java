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
package org.apache.shiro.jndi;

import org.junit.Test;

import javax.naming.NamingException;

import static org.junit.Assert.assertEquals;

/**
 * This test makes the assumption that {@link JndiLocator} is tested elsewhere and only makes an attempt to test the
 * functionality added by {@link JndiObjectFactory}.
 */
public class JndiObjectFactoryTest {
    @Test
    public void testGetInstanceWithType() throws Exception {
        final String name = "my/jndi/resource";
        final String returnValue = "jndiString";
        JndiObjectFactory<String> underTest = new JndiObjectFactory<String>() {
            @Override
            protected Object lookup(String jndiName, Class requiredType) throws NamingException {
                assertEquals(name, jndiName);
                assertEquals(String.class, requiredType);
                return new String(returnValue);
            }
        };

        underTest.setRequiredType(String.class);
        underTest.setResourceName(name);

        assertEquals(returnValue, underTest.getInstance());
    }

    @Test
    public void testGetInstanceNoType() throws Exception {
        final String name = "my/jndi/resource";
        final String returnValue = "jndiString";
        JndiObjectFactory<String> underTest = new JndiObjectFactory<String>() {
            @Override
            protected Object lookup(String jndiName) throws NamingException {
                assertEquals(name, jndiName);
                return new String(returnValue);
            }
        };

        underTest.setResourceName(name);

        assertEquals(returnValue, underTest.getInstance());
    }

    @Test(expected = IllegalStateException.class)
    public void testJndiLookupFailsWithType() throws Exception {
        final String name = "my/jndi/resource";
        JndiObjectFactory<String> underTest = new JndiObjectFactory<String>() {
            @Override
            protected Object lookup(String jndiName, Class requiredType) throws NamingException {
                throw new NamingException("No resource named " + jndiName);
            }
        };

        underTest.setResourceName(name);
        underTest.setRequiredType(String.class);

        underTest.getInstance();
    }

    @Test(expected = IllegalStateException.class)
    public void testJndiLookupFailsNoType() throws Exception {
        final String name = "my/jndi/resource";
        JndiObjectFactory<String> underTest = new JndiObjectFactory<String>() {
            @Override
            protected Object lookup(String jndiName) throws NamingException {
                throw new NamingException("No resource named " + jndiName);
            }
        };

        underTest.setResourceName(name);

        underTest.getInstance();
    }
}
