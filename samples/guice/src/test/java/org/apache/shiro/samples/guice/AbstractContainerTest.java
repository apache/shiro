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
package org.apache.shiro.samples.guice;

import com.gargoylesoftware.htmlunit.WebClient;
import org.junit.Before;
import org.junit.BeforeClass;
import org.mortbay.jetty.Connector;
import org.mortbay.jetty.Server;
import org.mortbay.jetty.nio.SelectChannelConnector;
import org.mortbay.jetty.webapp.WebAppContext;

import java.net.BindException;

import static org.junit.Assert.assertTrue;

public abstract class AbstractContainerTest {
    public static final int MAX_PORT = 9200;

    protected static PauseableServer server;

    private static int port = 9180;

    protected final WebClient webClient = new WebClient();

    @BeforeClass
    public static void startContainer() throws Exception {
        while (server == null && port < MAX_PORT) {
            try {
                server = createAndStartServer(port);
            } catch (BindException e) {
                System.err.printf("Unable to listen on port %d.  Trying next port.", port);
                port++;
            }
        }
        assertTrue(server.isStarted());
    }

    private static PauseableServer createAndStartServer(final int port) throws Exception {
        PauseableServer server = new PauseableServer();
        Connector connector = new SelectChannelConnector();
        connector.setPort(port);
        server.setConnectors(new Connector[]{connector});
        server.setHandler(new WebAppContext("src/main/webapp", "/"));
        server.start();
        return server;
    }

    protected static String getBaseUri() {
        return "http://localhost:" + port + "/";
    }

    @Before
    public void beforeTest() {
        webClient.setThrowExceptionOnFailingStatusCode(true);
    }

    public void pauseServer(boolean paused) {
        if (server != null) server.pause(paused);
    }

    public static class PauseableServer extends Server {
        public synchronized void pause(boolean paused) {
            try {
                if (paused) for (Connector connector : getConnectors())
                    connector.stop();
                else for (Connector connector : getConnectors())
                    connector.start();
            } catch (Exception e) {
            }
        }
    }
}
