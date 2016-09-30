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
package org.apache.shiro.test;

import com.gargoylesoftware.htmlunit.WebClient;

import static org.eclipse.jetty.util.resource.Resource.newResource;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import com.github.mjeanroy.junit.servers.jetty.EmbeddedJetty;
import com.github.mjeanroy.junit.servers.jetty.EmbeddedJettyConfiguration;
import org.eclipse.jetty.annotations.AnnotationConfiguration;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.util.resource.FileResource;
import org.eclipse.jetty.webapp.Configuration;
import org.eclipse.jetty.webapp.FragmentConfiguration;
import org.eclipse.jetty.webapp.JettyWebXmlConfiguration;
import org.eclipse.jetty.webapp.MetaInfConfiguration;
import org.eclipse.jetty.webapp.WebAppContext;
import org.eclipse.jetty.webapp.WebInfConfiguration;
import org.eclipse.jetty.webapp.WebXmlConfiguration;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;

import java.io.File;
import java.io.FilenameFilter;

import static com.github.mjeanroy.junit.servers.commons.Strings.isNotBlank;

public abstract class AbstractContainerIT {

    private static EmbeddedJetty jetty;

    private static int port = 0;

    protected final WebClient webClient = new WebClient();

    @BeforeClass
    public static void startContainer() throws Exception {

        File[] warFiles = new File("target").listFiles(new FilenameFilter() {
            @Override
            public boolean accept(File dir, String name) {
                return name.endsWith(".war");
            }
        });

        assertEquals("Expected only one war file in target directory, run 'mvn clean' and try again", 1, warFiles.length);

        String warDir = warFiles[0].getAbsolutePath().replaceFirst("\\.war$", "");

        EmbeddedJettyConfiguration config = EmbeddedJettyConfiguration.builder()
                .withWebapp(warDir)
                .build();

        jetty = new EmbeddedJetty(config) {

            /**
             * Overriding with contents of this pull request, to make fragment scanning work.
             * https://github.com/mjeanroy/junit-servers/pull/3
             */
            protected WebAppContext createdWebAppContext() throws Exception {
                final String path = configuration.getPath();
                final String webapp = configuration.getWebapp();
                final String classpath = configuration.getClasspath();

                WebAppContext ctx = new WebAppContext();
                ctx.setClassLoader(Thread.currentThread().getContextClassLoader());
                ctx.setContextPath(path);

                // Useful for WebXmlConfiguration
                ctx.setBaseResource(newResource(webapp));

                ctx.setConfigurations(new Configuration[]{
                        new WebInfConfiguration(),
                        new WebXmlConfiguration(),
                        new AnnotationConfiguration(),
                        new JettyWebXmlConfiguration(),
                        new MetaInfConfiguration(),
                        new FragmentConfiguration(),
                });

                if (isNotBlank(classpath)) {
                    // Fix to scan Spring WebApplicationInitializer
                    // This will add compiled classes to jetty classpath
                    // See: http://stackoverflow.com/questions/13222071/spring-3-1-webapplicationinitializer-embedded-jetty-8-annotationconfiguration
                    // And more precisely: http://stackoverflow.com/a/18449506/1215828
                    File classes = new File(classpath);
                    FileResource containerResources = new FileResource(classes.toURI());
                    ctx.getMetaData().addContainerResource(containerResources);
                }

                Server server = getDelegate();

                ctx.setParentLoaderPriority(true);
                ctx.setWar(webapp);
                ctx.setServer(server);

                // Add server context
                server.setHandler(ctx);

                return ctx;
            }
        };

        jetty.start();
        port = jetty.getPort();

        assertTrue(jetty.isStarted());
    }

    protected static String getBaseUri() {
        return "http://localhost:" + port + "/";
    }

    @Before
    public void beforeTest() {
        webClient.setThrowExceptionOnFailingStatusCode(true);
    }

    @AfterClass
    public static void stopContainer() {
        if (jetty != null) {
            jetty.stop();
        }
    }
}
