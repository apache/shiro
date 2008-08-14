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
package org.jsecurity.config;

import static org.junit.Assert.*;
import org.junit.Test;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * @author Les Hazlewood
 * @since Aug 5, 2008 9:53:00 AM
 */
public class ReflectionBuilderTest {

    @Test
    public void testSimpleConfig() {
        Map<String, String> defs = new LinkedHashMap<String, String>();
        defs.put("testBean", "org.jsecurity.config.TestBean");
        defs.put("testBean.stringProp", "blah");
        defs.put("testBean.booleanProp", "true");
        defs.put("testBean.intProp", "42");

        ReflectionBuilder builder = new ReflectionBuilder();
        Map beans = builder.buildObjects(defs);

        TestBean testBean = (TestBean) beans.get("testBean");
        assertNotNull(testBean);
        assertEquals(testBean.getStringProp(), "blah");
        assertTrue(testBean.isBooleanProp());
        assertEquals(testBean.getIntProp(), 42);
    }

    @Test
    public void testObjectReferenceConfig() {
        Map<String, String> defs = new LinkedHashMap<String, String>();
        defs.put("otherTestBean", "org.jsecurity.config.OtherTestBean");
        defs.put("otherTestBean.intProp", "101");
        defs.put("testBean", "org.jsecurity.config.TestBean");
        defs.put("testBean.stringProp", "blah");
        defs.put("testBean.otherTestBean", "$otherTestBean");

        ReflectionBuilder builder = new ReflectionBuilder();
        Map beans = builder.buildObjects(defs);

        TestBean testBean = (TestBean) beans.get("testBean");
        assertNotNull(testBean);
        assertEquals(testBean.getStringProp(), "blah");
        OtherTestBean otherTestBean = (OtherTestBean) beans.get("otherTestBean");
        assertNotNull(otherTestBean);
        assertNotNull(testBean.getOtherTestBean());
        assertEquals(otherTestBean, testBean.getOtherTestBean());
        assertEquals(otherTestBean.getIntProp(), 101);
    }

    @Test(expected = ConfigurationException.class)
    public void testObjectReferenceConfigWithTypeMismatch() {
        Map<String, String> defs = new LinkedHashMap<String, String>();
        defs.put("otherTestBean", "org.jsecurity.config.OtherTestBean");
        defs.put("testBean", "org.jsecurity.config.TestBean");
        defs.put("testBean.otherTestBean", "otherTestBean");
        ReflectionBuilder builder = new ReflectionBuilder();
        builder.buildObjects(defs);
    }

    @Test(expected = UnresolveableReferenceException.class)
    public void testObjectReferenceConfigWithInvalidReference() {
        Map<String, String> defs = new LinkedHashMap<String, String>();
        defs.put("otherTestBean", "org.jsecurity.config.OtherTestBean");
        defs.put("testBean", "org.jsecurity.config.TestBean");
        defs.put("testBean.otherTestBean", "$foo");
        ReflectionBuilder builder = new ReflectionBuilder();
        builder.buildObjects(defs);
    }
}
