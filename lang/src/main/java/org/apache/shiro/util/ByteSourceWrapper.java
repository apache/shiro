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

package org.apache.shiro.util;

import org.apache.shiro.lang.util.ByteSource;

import java.io.Closeable;
import java.io.IOException;

/**
 * To use try-with-resources idiom, this class supports wrapping existing ByteSource
 * object or byte array. At end of try block, it gets zeroed out automatically.
 */
public class ByteSourceWrapper implements Closeable {
    private byte[] bytes;

    private ByteSourceWrapper(byte[] bytes) {
        this.bytes = bytes;
    }

    /**
     * This method generically accepts byte array or ByteSource instance.
     */
    public static ByteSourceWrapper wrap(Object value) {
        if (value instanceof byte[]) {
            byte[] bytes = (byte[]) value;
            return new ByteSourceWrapper(bytes);
        } else if (value instanceof ByteSource) {
            byte[] bytes = ((ByteSource) value).getBytes();
            return new ByteSourceWrapper(bytes);
        }
        throw new IllegalArgumentException();
    }

    public byte[] getBytes() {
        return bytes;
    }

    public void close() throws IOException {
        ByteUtils.wipe(bytes);
    }
}
