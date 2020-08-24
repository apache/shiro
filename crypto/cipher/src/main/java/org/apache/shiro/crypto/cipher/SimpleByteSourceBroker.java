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

package org.apache.shiro.crypto.cipher;

import org.apache.shiro.lang.util.ByteSource;
import org.apache.shiro.lang.util.Destroyable;
import org.apache.shiro.util.ByteSourceWrapper;
import org.apache.shiro.util.ByteUtils;

import java.io.IOException;

/**
 * A simple implementation that maintains cipher service, ciphertext and key for decrypting it later.
 * {@link #useBytes(ByteSourceUser)} guarantees the sensitive data in byte array will be erased at end of use.
 */
public class SimpleByteSourceBroker implements ByteSourceBroker, Destroyable {
    private JcaCipherService cipherService;
    private byte[] ciphertext;
    private byte[] key;
    private boolean destroyed = false;

    public SimpleByteSourceBroker(JcaCipherService cipherService, byte[] ciphertext, byte[] key) {
        this.cipherService = cipherService;
        this.ciphertext = ciphertext.clone();
        this.key = key.clone();
    }

    public synchronized void useBytes(ByteSourceUser user) {
        if (destroyed || user == null) {
            return;
        }
        ByteSource byteSource = cipherService.decryptInternal(ciphertext, key);

        try (ByteSourceWrapper temp = ByteSourceWrapper.wrap(byteSource.getBytes())) {
            user.use(temp.getBytes());
        } catch (IOException e) {
            // ignore
        }

    }

    public byte[] getClonedBytes() {
        ByteSource byteSource = cipherService.decryptInternal(ciphertext, key);
        return byteSource.getBytes(); // this's a newly created byte array
    }

    public void destroy() throws Exception {
        if (!destroyed) {
            synchronized (this) {
                destroyed = true;
                cipherService = null;
                ByteUtils.wipe(ciphertext);
                ciphertext = null;
                ByteUtils.wipe(key);
                key = null;
            }
        }
    }
}
