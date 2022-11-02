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

import com.gargoylesoftware.htmlunit.WebClient;
import io.undertow.Undertow;
import io.undertow.jsp.JspServletBuilder;
import io.undertow.server.handlers.PathHandler;
import io.undertow.servlet.api.DeploymentInfo;
import io.undertow.servlet.api.DeploymentManager;
import io.undertow.servlet.api.ServletContainer;
import java.util.HashMap;
import org.apache.jasper.deploy.JspPropertyGroup;
import org.apache.jasper.deploy.TagLibraryInfo;
import org.apache.shiro.lang.codec.Base64;
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

import static org.junit.Assert.assertEquals;

public abstract class JakartaAbstractContainerIT {

//    protected static Server jetty;

    protected static int tlsPort;

    protected final WebClient webClient = new WebClient();

    protected static final File TEST_KEYSTORE_PATH = setupKeyStore();
    protected static final String TEST_KEYSTORE_PASSWORD = "password";

    protected static final String classpath = ".";

    @BeforeClass
    public static void startContainer() throws Exception {
        final PathHandler servletPath = new PathHandler();
        final ServletContainer container = ServletContainer.Factory.newInstance();

        DeploymentInfo builder = new DeploymentInfo()
            .setClassLoader(JakartaAbstractContainerIT.class.getClassLoader())
            .setContextPath("/servletContext")
            //.setClassIntrospecter(TestClassIntrospector.INSTANCE)
            .setDeploymentName("servletContext.war")
            //.setResourceManager(new TestResourceLoader(SimpleJspTestCase.class))
            .addServlet(JspServletBuilder.createServlet("Default Jsp Servlet", "*.jsp"));
        JspServletBuilder.setupDeployment(builder, new HashMap<String, JspPropertyGroup>(), new HashMap<String, TagLibraryInfo>(), new TestInstanceManager());

        DeploymentManager manager = container.addDeployment(builder);
        manager.deploy();
        servletPath.addPrefixPath(builder.getContextPath(), manager.start());

        Undertow server = Undertow.builder()
            .addHttpListener(8080, "localhost")
            .setHandler(servletPath)
            .build();
        server.start();
    }

    protected static String getBaseUri() {
        return "http://localhost:8080/";
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
//        webClient.getOptions().setThrowExceptionOnFailingStatusCode(true);
    }

    @AfterClass
    public static void stopContainer() throws Exception {
//        if (jetty != null) {
//            jetty.stop();
//        }
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
