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
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;

import java.io.File;
import java.io.FilenameFilter;

import static org.junit.jupiter.api.Assertions.assertEquals;

public abstract class JakartaAbstractContainerIT {

    protected static Meecrowave meecrowave;

    @BeforeAll
    public static void startContainer() {
        final File root = new File(getWarDir());
        try {
            meecrowave = new Meecrowave(new Meecrowave.Builder().randomHttpPort());
            meecrowave.getConfiguration().addGlobalContextCustomizer(
                    ctx -> ctx.setJarScanner(new org.apache.tomcat.util.scan.StandardJarScanner()));
            meecrowave.start();
            // v-- fails with class cast exception --V
            meecrowave.deployWebapp("/", root);
        } catch (final Exception e) {
            // todo: failures here are showing class cast exception because two separate instances of
            //  the interface org.apache.webbeans.spi.LoaderService are being loaded, one in the app
            //  classloader, and one in ParallelWebappClassLoader, and then Class.cast() is failing
            //  because the target object was loaded in a different classloader
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

        assertEquals(1, warFiles.length, "Expected only one war file in target directory, run 'mvn clean' and try again");

        return warFiles[0].getAbsolutePath().replaceFirst("\\.war$", "");
    }

    @AfterAll
    public static void stopContainer() {
        if (meecrowave != null) {
            meecrowave.close();
        }
    }
}
