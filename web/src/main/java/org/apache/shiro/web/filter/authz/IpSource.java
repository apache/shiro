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
package org.apache.shiro.web.filter.authz;

import java.util.Collection;

/**
 * Represents a source of information for IP restrictions (see IpFilter)
 * @since 2.0 
 */
public interface IpSource {

    /**
     * Returns a set of strings representing IP address representing
     * IPv4 or IPv6 ranges / CIDRs. e.g. 192.168.0.0/16 from which
     * access should be allowed (if and only if the IP is not included
     * in the list of denied IPs)
     */
    public Collection<String> getAuthorizedIps();

    /**
     * Returns a set of strings representing IP address representing
     * IPv4 or IPv6 ranges / CIDRs. e.g. 192.168.0.0/16 from which
     * access should be denied.
     */
    public Collection<String> getDeniedIps();
}
