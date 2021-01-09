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

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @since 2.0.0
 */
public class HasherTest {

    private final InputStream systemIn = System.in;

    private ByteArrayInputStream testIn;

    private final Logger hasherToolLogger = (Logger) LoggerFactory.getLogger("ROOT");
    private final ListAppender<ILoggingEvent> listAppender = new ListAppender<>();

    @BeforeEach
    public void setUpOutput() {
        hasherToolLogger.detachAndStopAllAppenders();
        hasherToolLogger.addAppender(listAppender);
        listAppender.start();
    }

    private void provideInput(String data) {
        testIn = new ByteArrayInputStream(data.getBytes());
        System.setIn(testIn);
    }

    @AfterEach
    public void restoreSystemInputOutput() throws IOException {
        System.setIn(systemIn);
        testIn.close();
        listAppender.stop();
    }


    @Test
    public void testArgon2Hash() {
        // given
        String[] args = {"--debug", "--password", "--pnoconfirm"};
        provideInput("secret#shiro,password;Jo8opech");

        // when
        Hasher.main(args);
        List<ILoggingEvent> loggingEvents = listAppender.list;

        // when
        assertEquals(1, loggingEvents.size());
        ILoggingEvent iLoggingEvent = loggingEvents.get(0);
        assertTrue(iLoggingEvent.getMessage().contains("$shiro2$argon2id$v=19"));
    }

    @Test
    public void testBCryptHash() {
        // given
        String[] args = {"--debug", "--password", "--pnoconfirm", "--algorithm", "2y"};
        provideInput("secret#shiro,password;Jo8opech");

        // when
        Hasher.main(args);
        List<ILoggingEvent> loggingEvents = listAppender.list;

        // when
        assertEquals(1, loggingEvents.size());
        ILoggingEvent iLoggingEvent = loggingEvents.get(0);
        assertTrue(iLoggingEvent.getMessage().contains("$shiro2$2y$10$"));
    }
}
