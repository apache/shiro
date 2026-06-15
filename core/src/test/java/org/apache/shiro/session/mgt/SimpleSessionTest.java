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
package org.apache.shiro.session.mgt;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;

public class SimpleSessionTest {

    @Test
    void testDefaultSerialization() throws Exception {
        SimpleSession session = new SimpleSession();

        long timeout = session.getTimeout();
        Date start = session.getStartTimestamp();
        Date lastAccess = session.getLastAccessTime();

        SimpleSession deserialized = serializeAndDeserialize(session);

        assertThat(deserialized.getTimeout()).isEqualTo(timeout);
        assertThat(deserialized.getStartTimestamp()).isEqualTo(start);
        assertThat(deserialized.getLastAccessTime()).isEqualTo(lastAccess);
    }

    @Test
    void serializeHost() throws IOException, ClassNotFoundException {
        SimpleSession session = new SimpleSession("localhost");
        assertThat(serializeAndDeserialize(session).getHost()).isEqualTo("localhost");
    }

    @Test
    void serializeExpired() throws IOException, ClassNotFoundException {
        SimpleSession session = new SimpleSession();
        session.setExpired(true);
        assertThat(serializeAndDeserialize(session).isExpired()).isTrue();
    }

    private SimpleSession serializeAndDeserialize(SimpleSession session) throws IOException, ClassNotFoundException {
        ByteArrayOutputStream serialized = new ByteArrayOutputStream();
        ObjectOutputStream serializer = new ObjectOutputStream(serialized);
        serializer.writeObject(session);
        serializer.close();
        return (SimpleSession) new ObjectInputStream(new ByteArrayInputStream(serialized.toByteArray())).readObject();
    }
}
