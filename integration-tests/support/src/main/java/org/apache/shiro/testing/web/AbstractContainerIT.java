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
package org.apache.shiro.testing.web;

import org.apache.shiro.lang.codec.Base64;

import com.gargoylesoftware.htmlunit.WebClient;
import com.github.mjeanroy.junit.servers.jetty.EmbeddedJetty;
import com.github.mjeanroy.junit.servers.jetty.EmbeddedJettyConfiguration;
import org.eclipse.jetty.annotations.AnnotationConfiguration;
import org.eclipse.jetty.http.HttpVersion;
import org.eclipse.jetty.server.HttpConfiguration;
import org.eclipse.jetty.server.HttpConnectionFactory;
import org.eclipse.jetty.server.SecureRequestCustomizer;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.server.SslConnectionFactory;
import org.eclipse.jetty.util.resource.FileResource;
import org.eclipse.jetty.util.ssl.SslContextFactory;
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
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.ServerSocket;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

import static com.github.mjeanroy.junit.servers.commons.Strings.isNotBlank;
import static org.eclipse.jetty.util.resource.Resource.newResource;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public abstract class AbstractContainerIT {

    protected static EmbeddedJetty jetty;

    protected static int tlsPort;

    protected final WebClient webClient = new WebClient();

    protected static final File TEST_KEYSTORE_PATH = setupKeyStore();
    protected static final String TEST_KEYSTORE_PASSWORD = "password";

    @BeforeClass
    public static void startContainer() throws Exception {

        EmbeddedJettyConfiguration config = EmbeddedJettyConfiguration.builder()
                .withWebapp(getWarDir())
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

                // web app
                ctx.setParentLoaderPriority(true);
                ctx.setWar(webapp);
                ctx.setServer(server);

                // Add server context
                server.setHandler(ctx);

                return ctx;
            }
        };

        Server server = jetty.getDelegate();

        // TLS
        tlsPort = getFreePort();

        final SslContextFactory sslContextFactory = new SslContextFactory.Server();
        sslContextFactory.setKeyStorePath(TEST_KEYSTORE_PATH.getAbsolutePath());
        sslContextFactory.setKeyStorePassword(TEST_KEYSTORE_PASSWORD);
        sslContextFactory.setKeyManagerPassword(TEST_KEYSTORE_PASSWORD);

        HttpConfiguration https = new HttpConfiguration();
        https.addCustomizer(new SecureRequestCustomizer());

        final ServerConnector httpsConnector = new ServerConnector(
                server,
                new SslConnectionFactory(sslContextFactory, HttpVersion.HTTP_1_1.asString()),
                new HttpConnectionFactory(https));
        httpsConnector.setPort(tlsPort);
        server.addConnector(httpsConnector);

        jetty.start();

        assertTrue(jetty.isStarted());
    }

    protected static String getBaseUri() {
        return "http://localhost:" + jetty.getPort() + "/";
    }

    protected static String getTlsBaseUri() {
        return "https://localhost:" + tlsPort + "/";
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

    protected static String getBasicAuthorizationHeaderValue(String username, String password) throws UnsupportedEncodingException {
        String authorizationHeader = username + ":" + password;
        byte[] valueBytes;
        valueBytes = authorizationHeader.getBytes("UTF-8");
        authorizationHeader = new String(Base64.encode(valueBytes));
        return "Basic " + authorizationHeader;
    }

    @Before
    public void beforeTest() {
        webClient.getOptions().setThrowExceptionOnFailingStatusCode(true);
    }

    @AfterClass
    public static void stopContainer() {
        if (jetty != null) {
            jetty.stop();
        }
    }

    private static int getFreePort() {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        } catch (IOException e) {
            throw new IllegalStateException("Failed to allocate free port", e);
        }
    }

    // Dealing with a keystore is NOT fun, it's easier to script one with the keytool
    // see src/main/resources/createKeyStore.sh for more info
    private static File setupKeyStore() {
        try {
            Path outKeyStoreFile = File.createTempFile("test-keystore", "jks").toPath();
            URL keyStoreResource = Thread.currentThread().getContextClassLoader().getResource("test-keystore.jks");
            Files.copy(keyStoreResource.openStream(), outKeyStoreFile, StandardCopyOption.REPLACE_EXISTING);
            File keyStoreFile = outKeyStoreFile.toFile();

            // clients will pick up the ssl keystore this way, so just set SSL properties
            System.setProperty("javax.net.ssl.trustStore", keyStoreFile.getAbsolutePath());
            System.setProperty("javax.net.ssl.trustStorePassword", TEST_KEYSTORE_PASSWORD);
            return keyStoreFile;
        } catch (IOException e) {
            throw new IllegalStateException("Failed to create test keystore", e);
        }
    }
}
