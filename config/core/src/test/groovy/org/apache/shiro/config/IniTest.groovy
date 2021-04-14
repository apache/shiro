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


import static org.hamcrest.Matchers.*;

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
    public void testIsContinued() {
        //no slashes
        String line = "prop = value ";
        assertFalse(Ini.Section.isContinued(line));

        //1 slash (odd number, but edge case):
        line = "prop = value" + Ini.ESCAPE_TOKEN;
        assertTrue(Ini.Section.isContinued(line));

        //2 slashes = even number
        line = "prop = value" + Ini.ESCAPE_TOKEN + Ini.ESCAPE_TOKEN;
        assertFalse(Ini.Section.isContinued(line));

        //3 slashes = odd number
        line = "prop = value" + Ini.ESCAPE_TOKEN + Ini.ESCAPE_TOKEN + Ini.ESCAPE_TOKEN;
        assertTrue(Ini.Section.isContinued(line));
    }

    @Test
    public void testBackslash() {
        String test = "Truth=Beauty\\\\";
        Ini ini = new Ini();
        ini.load(test);

        assertNotNull(ini.getSections());
        assertEquals(1, ini.getSections().size());

        Ini.Section section = ini.getSections().iterator().next();
        assertEquals(Ini.DEFAULT_SECTION_NAME, section.getName());
        assertFalse(section.isEmpty());
        assertEquals(1, section.size());
        assertEquals("Beauty\\\\", section.get("Truth"));
    }

    @Test
    public void testSplitKeyValue() {
        String test = "Truth Beauty";
        String[] kv = Ini.Section.splitKeyValue(test);
        assertEquals("Truth", kv[0]);
        assertEquals("Beauty", kv[1]);

        test = "Truth=Beauty";
        kv = Ini.Section.splitKeyValue(test);
        assertEquals("Truth", kv[0]);
        assertEquals("Beauty", kv[1]);

        test = "Truth:Beauty";
        kv = Ini.Section.splitKeyValue(test);
        assertEquals("Truth", kv[0]);
        assertEquals("Beauty", kv[1]);

        test = "Truth = Beauty";
        kv = Ini.Section.splitKeyValue(test);
        assertEquals("Truth", kv[0]);
        assertEquals("Beauty", kv[1]);

        test = "Truth:  Beauty";
        kv = Ini.Section.splitKeyValue(test);
        assertEquals("Truth", kv[0]);
        assertEquals("Beauty", kv[1]);

        test = "Truth  :Beauty";
        kv = Ini.Section.splitKeyValue(test);
        assertEquals("Truth", kv[0]);
        assertEquals("Beauty", kv[1]);

        test = "Truth:Beauty        ";
        kv = Ini.Section.splitKeyValue(test);
        assertEquals("Truth", kv[0]);
        assertEquals("Beauty", kv[1]);

        test = "    Truth:Beauty    ";
        kv = Ini.Section.splitKeyValue(test);
        assertEquals("Truth", kv[0]);
        assertEquals("Beauty", kv[1]);

        test = "Truth        =Beauty";
        kv = Ini.Section.splitKeyValue(test);
        assertEquals("Truth", kv[0]);
        assertEquals("Beauty", kv[1]);

        // Escape characters are to be removed from the key.
        // This is different behaviour compared to the XML config.
        test = "Tru\\th=Beauty";
        kv = Ini.Section.splitKeyValue(test);
        assertEquals("Truth", kv[0]);
        assertEquals("Beauty", kv[1]);

        // SHIRO-530: Keep backslashes in value.
        test = "Truth=Beau\\ty";
        kv = Ini.Section.splitKeyValue(test);
        assertEquals("Truth", kv[0]);
        assertEquals("Beau\\ty", kv[1]);

        // SHIRO-530: Keep backslashes in value.
        test = "Truth=Beauty\\";
        kv = Ini.Section.splitKeyValue(test);
        assertEquals("Truth", kv[0]);
        assertEquals("Beauty\\", kv[1]);

        // SHIRO-530: Keep backslashes in value.
        test = "Truth= \\ Beauty\\";
        kv = Ini.Section.splitKeyValue(test);
        assertEquals("Truth", kv[0]);
        assertEquals("\\ Beauty\\", kv[1]);

        test = "cn\\=TheSpecial_GroupName,ou\\=groups,dc\\=example,dc\\=com = *:*"
        kv = Ini.Section.splitKeyValue(test)
        assertEquals("cn=TheSpecial_GroupName,ou=groups,dc=example,dc=com", kv[0])
        assertEquals("*:*", kv[1])
    }

    @Test(expected = IllegalArgumentException.class)
    public void testSplitKeyValueNoValue() {
        String test = "  Truth  ";
        Ini.Section.splitKeyValue(test);
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

    /**
     * @since 1.4
     */
    @Test
    public void testPutAll() {

        Ini ini1 = new Ini();
        ini1.setSectionProperty("section1", "key1", "value1");

        Ini ini2 = new Ini();
        ini2.setSectionProperty("section2", "key2", "value2");

        ini1.putAll(ini2);

        assertThat(ini1.getSectionNames(), allOf(
                hasItem("section1"),
                hasItem("section2")
        ));

        // two sections each with one property
        assertThat(ini1.getSectionNames(), hasSize(2));
        assertThat(ini1.getSection("section2"), aMapWithSize(1));
        assertThat(ini1.getSection("section1"), aMapWithSize(1));

        // adding a value directly to ini2's section will update ini1
        ini2.setSectionProperty("section2", "key2.2", "value2.2");
        assertThat(ini1.getSection("section2"), aMapWithSize(2));

        Ini ini3 = new Ini();
        ini3.setSectionProperty("section1", "key1.3", "value1.3");

        // this will replace the whole section
        ini1.putAll(ini3);
        assertThat(ini1.getSection("section1"), aMapWithSize(1));

    }

    /**
     * @since 1.4
     */
    @Test
    public void testMerge() {

        Ini ini1 = new Ini();
        ini1.setSectionProperty("section1", "key1", "value1");

        Ini ini2 = new Ini();
        ini2.setSectionProperty("section2", "key2", "value2");

        ini1.merge(ini2);

        assertThat(ini1.getSectionNames(), allOf(
                hasItem("section1"),
                hasItem("section2")
        ));

        // two sections each with one property
        assertThat(ini1.getSectionNames(), hasSize(2));
        assertThat(ini1.getSection("section2"), aMapWithSize(1));
        assertThat(ini1.getSection("section1"), aMapWithSize(1));

        // updating the original ini2, will NOT effect ini1
        ini2.setSectionProperty("section2", "key2.2", "value2.2");
        assertThat(ini1.getSection("section2"), aMapWithSize(1));

        Ini ini3 = new Ini();
        ini3.setSectionProperty("section1", "key1.3", "value1.3");

        // after merging the section will contain 2 values
        ini1.merge(ini3);
        assertThat(ini1.getSection("section1"), aMapWithSize(2));
    }

    /**
     * @since 1.4
     */
    @Test
    public void testCreateWithDefaults() {

        Ini ini1 = new Ini();
        ini1.setSectionProperty("section1", "key1", "value1");

        Ini ini2 = new Ini(ini1);
        ini2.setSectionProperty("section2", "key2", "value2");

        assertThat(ini2.getSectionNames(), allOf(
                hasItem("section1"),
                hasItem("section2")
        ));

        // two sections each with one property
        assertThat(ini2.getSectionNames(), hasSize(2));
        assertThat(ini2.getSection("section2"), aMapWithSize(1));
        assertThat(ini2.getSection("section1"), aMapWithSize(1));

        // updating the original ini1, will NOT effect ini2
        ini1.setSectionProperty("section1", "key1.1", "value1.1");
        assertThat(ini2.getSection("section1"), allOf(aMapWithSize(1), hasEntry("key1", "value1")));
    }
}
