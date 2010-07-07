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

import org.junit.Test;

import java.io.*;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class SimpleSessionTest {
    @Test
    public void serializeHost() throws IOException, ClassNotFoundException {
        SimpleSession session = new SimpleSession("localhost");
        assertEquals("localhost", serializeAndDeserialize(session).getHost());
    }

    @Test
    public void serializeExpired() throws IOException, ClassNotFoundException {
        SimpleSession session = new SimpleSession();
        session.setExpired(true);
        assertTrue(serializeAndDeserialize(session).isExpired());
    }

    private SimpleSession serializeAndDeserialize(SimpleSession session) throws IOException, ClassNotFoundException {
        ByteArrayOutputStream serialized = new ByteArrayOutputStream();
        ObjectOutputStream serializer = new ObjectOutputStream(serialized);
        serializer.writeObject(session);
        serializer.close();
        return (SimpleSession) new ObjectInputStream(new ByteArrayInputStream(serialized.toByteArray())).readObject();
    }
}
