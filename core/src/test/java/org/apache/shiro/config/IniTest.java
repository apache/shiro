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
package org.apache.shiro.config;

import static org.junit.Assert.*;
import org.junit.Test;

import java.util.Scanner;

/**
 * Unit test for the {@link Ini} class.
 *
 * @since 1.0
 */
public class IniTest {

    private static final String NL = "\n";

    @Test
    public void testNoSections() {
        String test =
                "prop1 = value1" + NL +
                        "prop2 = value2";

        Ini ini = new Ini();
        ini.load(test);

        assertNotNull(ini.getSections());
        assertEquals(1, ini.getSections().size());

        Ini.Section section = ini.getSections().iterator().next();
        assertEquals(Ini.DEFAULT_SECTION_NAME, section.getName());
        assertFalse(section.isEmpty());
        assertEquals(2, section.size());
        assertEquals("value1", section.get("prop1"));
        assertEquals("value2", section.get("prop2"));
    }

    @Test
    public void testOneSection() {
        String sectionName = "main";
        String test = NL +
                "" + NL +
                "  " + NL +
                "    #  comment1 " + NL +
                " ; comment 2" + NL +
                "[" + sectionName + "]" + NL +
                "prop1 = value1" + NL +
                "  " + NL +
                "; comment " + NL +
                "prop2   value2" + NL +
                "prop3:value3" + NL +
                "prop4 : value 4" + NL +
                "prop5 some long \\" + NL +
                "      value " + NL +
                "# comment.";

        Ini ini = new Ini();
        ini.load(new Scanner(test));

        assertNotNull(ini.getSections());
        assertEquals(1, ini.getSections().size());
        Ini.Section section = ini.getSection("main");
        assertNotNull(section);
        assertEquals(sectionName, section.getName());
        assertFalse(section.isEmpty());
        assertEquals(5, section.size());
        assertEquals("value1", section.get("prop1"));
        assertEquals("value2", section.get("prop2"));
        assertEquals("value3", section.get("prop3"));
        assertEquals("value 4", section.get("prop4"));
        assertEquals("some long value", section.get("prop5"));
    }
}
