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
package org.apache.shiro.test.web.jakarta;

import org.apache.meecrowave.Meecrowave;
import org.junit.AfterClass;
import org.junit.BeforeClass;

import java.io.File;
import java.io.FilenameFilter;

import static org.junit.Assert.assertEquals;

public abstract class JakartaAbstractContainerIT {

    protected static Meecrowave meecrowave;

    @BeforeClass
    public static void startContainer() {
        final File root = new File(getWarDir());
        try {
            meecrowave = new Meecrowave(new Meecrowave.Builder().randomHttpPort());
            meecrowave.getConfiguration().addGlobalContextCustomizer(ctx -> ctx.setJarScanner(new org.apache.tomcat.util.scan.StandardJarScanner()));
            meecrowave.start();
            meecrowave.deployWebapp("/", root);
        } catch (final Exception e) {
            e.printStackTrace();
        }
    }

    protected static String getBaseUri() {
        return "http://localhost:" + meecrowave.getConfiguration().getHttpPort() + "/";
    }

    protected static String getWarDir() {
        File[] warFiles = new File("target").listFiles(new FilenameFilter() {
            @Override
            public boolean accept(File dir, String name) {
                return name.endsWith(".war");
            }
        });

        assertEquals("Expected only one war file in target directory, run 'mvn clean' and try again", 1, warFiles.length);

        return warFiles[0].getAbsolutePath().replaceFirst("\\.war$", "");
    }

    @AfterClass
    public static void stopContainer() {
        if (meecrowave != null) {
            meecrowave.close();
        }
    }
}
