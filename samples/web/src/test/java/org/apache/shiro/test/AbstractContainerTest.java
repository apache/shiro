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
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.BeforeClass;
import org.mortbay.jetty.Connector;
import org.mortbay.jetty.Handler;
import org.mortbay.jetty.Server;
import org.mortbay.jetty.handler.DefaultHandler;
import org.mortbay.jetty.handler.HandlerCollection;
import org.mortbay.jetty.nio.SelectChannelConnector;
import org.mortbay.jetty.webapp.WebAppContext;

public abstract class AbstractContainerTest {
    protected static PauseableServer server;

    protected static final int port = 8180;

    protected static final String BASEURI = "http://localhost:" + port + "/";

    protected final WebClient webClient = new WebClient();

    @BeforeClass
    public static void startContainer() throws Exception {
        if (server == null) {
            server = new PauseableServer();
            Connector connector = new SelectChannelConnector();
            connector.setPort(port);
            server.setConnectors(new Connector[]{connector});

            WebAppContext context = new WebAppContext("src/main/webapp", "/");

            HandlerCollection handlers = new HandlerCollection();
            handlers.setHandlers(new Handler[]{context, new DefaultHandler()});
            server.setHandler(handlers);
            server.start();
            assertTrue(server.isStarted());
        }
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
