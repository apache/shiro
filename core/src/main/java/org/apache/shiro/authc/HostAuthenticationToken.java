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
package org.apache.shiro.authc;

/**
 * A {@code HostAuthenticationToken} retains the host information from where
 * an authentication attempt originates.
 *
 * @since 1.0
 */
public interface HostAuthenticationToken extends AuthenticationToken {

    /**
     * Returns the host name of the client from where the
     * authentication attempt originates or if the Shiro environment cannot or
     * chooses not to resolve the hostname to improve performance, this method
     * returns the String representation of the client's IP address.
     * <p/>
     * When used in web environments, this value is usually the same as the
     * {@code ServletRequest.getRemoteHost()} value.
     *
     * @return the fully qualified name of the client from where the
     *         authentication attempt originates or the String representation
     *         of the client's IP address is hostname resolution is not
     *         available or disabled.
     */
    String getHost();
}
