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

/**
 * ByteSourceBroker holds an encrypted value to decrypt it on demand.
 * <br/>
 * {@link #useBytes(ByteSourceUser)} method is designed for dictating
 * developers to use the byte source in a special way, to prevent its prevalence
 * and difficulty of managing & zeroing that critical information at end of use.
 * <br/>
 * For exceptional cases we allow developers to use the other method,
 * {@link #getClonedBytes()}, but it's not advised.
 */
public interface ByteSourceBroker {
    /**
     * This method accepts an implementation of ByteSourceUser functional interface.
     * <br/>
     * To limit the decrypted value's existence, developers should maintain the
     * implementation part as short as possible.
     *
     * @param user Implements a use-case for the decrypted value.
     */
    void useBytes(ByteSourceUser user);

    /**
     * As the name implies, this returns a cloned byte array
     * and caller has a responsibility to wipe it out at end of use.
     */
    byte[] getClonedBytes();
}
