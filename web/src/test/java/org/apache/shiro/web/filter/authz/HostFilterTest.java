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
package org.apache.shiro.web.filter.authz;

import org.junit.jupiter.api.Test;

import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @since 1.0
 */
public class HostFilterTest {

    @SuppressWarnings("checkstyle:MagicNumber")
    @Test
    void testPrivateClassC() {
        Pattern p = Pattern.compile(HostFilter.PRIVATE_CLASS_C_REGEX);

        String base = "192.168.";

        for (int i = 0; i < 256; i++) {
            String ibase = base + i;
            for (int j = 0; j < 256; j++) {
                String ip = ibase + "." + j;
                assertTrue(p.matcher(ip).matches());
            }
        }
    }

    @SuppressWarnings("checkstyle:MagicNumber")
    @Test
    void testPrivateClassB() {
        Pattern p = Pattern.compile(HostFilter.PRIVATE_CLASS_B_REGEX);

        String base = "172.";

        for (int i = 16; i < 32; i++) {
            String ibase = base + i;
            for (int j = 0; j < 256; j++) {
                String jBase = ibase + "." + j;
                for (int k = 0; k < 256; k++) {
                    String ip = jBase + "." + k;
                    assertTrue(p.matcher(ip).matches());
                }
            }
        }
    }

    /* Takes a long time (20+ seconds?) - only enable when testing explicitly:
    @Test
    public void testPrivateClassA() {
        Pattern p = Pattern.compile(HostFilter.PRIVATE_CLASS_A_REGEX);

        String base = "10.";

        for (int i = 0; i < 256; i++) {
            String ibase = base + i;
            for (int j = 0; j < 256; j++) {
                String jBase = ibase + "." + j;
                for (int k = 0; k < 256; k++) {
                    String ip = jBase + "." + k;
                    assertTrue(p.matcher(ip).matches());
                }
            }
        }
    } */

}
