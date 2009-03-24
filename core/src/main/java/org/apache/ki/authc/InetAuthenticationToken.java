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
package org.apache.ki.authc;

import java.net.InetAddress;

/**
 * Authentication token that also preserves the IP from where the authentication attempt is taking place.
 *
 * @author Les Hazlewood
 * @since 0.2
 */
public interface InetAuthenticationToken extends AuthenticationToken {

    /**
     * Returns the InetAddress from where the authentication attempt is occurring.  May be null if the IP address
     * is ignored or unknown, in which case, it is up to the Authenticator processing the token to determine if
     * it is valid without the IP.
     *
     * @return the InetAddress from where the authentication attempt is occurring.
     */
    InetAddress getInetAddress();
}
