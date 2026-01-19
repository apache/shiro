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

package org.apache.shiro.tools.hasher;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.Logger;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.config.Configuration;
import org.apache.logging.log4j.core.config.LoggerConfig;
import org.apache.logging.log4j.core.test.appender.ListAppender;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInfo;
import org.junit.jupiter.api.parallel.Isolated;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @since 2.0
 */
@Isolated("Uses System Input")
public class HasherTest {

    private final InputStream systemIn = System.in;

    private ByteArrayInputStream testIn;

    private ListAppender listAppender;

    @BeforeEach
    public void setUpOutput(TestInfo testInfo) {
        LoggerContext loggerContext = (LoggerContext) LogManager.getContext(false);
        Configuration configuration = loggerContext.getConfiguration();
        ((Logger) loggerContext.getLogger(Hasher.class)).setLevel(Level.INFO);
        LoggerConfig rootLoggerConfig = configuration.getLoggerConfig("");
        rootLoggerConfig.getAppenders().clear();

        listAppender = new ListAppender(testInfo.getTestMethod().get().getName());
        listAppender.start();
        rootLoggerConfig.addAppender(listAppender, Level.ALL, null);
    }

    private void provideInput(String data) {
        testIn = new ByteArrayInputStream(data.getBytes());
        System.setIn(testIn);
        listAppender.stop();
        listAppender.clear();
    }

    @AfterEach
    public void restoreSystemInputOutput() throws IOException {
        System.setIn(systemIn);
        testIn.close();
    }


    @Test
    public void testArgon2Hash() {
        // given
        String[] args = {"--debug", "--password", "--pnoconfirm"};
        provideInput("secret#shiro,password;Jo8opech");

        // when
        Hasher.main(args);

        // when
        assertEquals(1, listAppender.getEvents().size());
        LogEvent iLoggingEvent = listAppender.getEvents().get(0);
        assertTrue(iLoggingEvent.getMessage().getFormattedMessage().contains("$shiro2$argon2id$v=19"));
    }

    @Test
    public void testBCryptHash() {
        // given
        String[] args = {"--debug", "--password", "--pnoconfirm", "--algorithm", "bcrypt2y"};
        provideInput("secret#shiro,password;Jo8opech");

        // when
        Hasher.main(args);

        // when
        assertEquals(1, listAppender.getEvents().size());
        LogEvent iLoggingEvent = listAppender.getEvents().get(0);
        assertTrue(iLoggingEvent.getMessage().getFormattedMessage().contains("$shiro2$2y$10$"));
    }

    @Test
    public void testBCryptHashShortName() {
        // given
        String[] args = {"--debug", "--password", "--pnoconfirm", "--algorithm", "2y"};
        provideInput("secret#shiro,password;Jo8opech");

        // when
        Hasher.main(args);

        // when
        assertEquals(1, listAppender.getEvents().size());
        LogEvent iLoggingEvent = listAppender.getEvents().get(0);
        assertTrue(iLoggingEvent.getMessage().getFormattedMessage().contains("$shiro2$2y$10$"));
    }
}
