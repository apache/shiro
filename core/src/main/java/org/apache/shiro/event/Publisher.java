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
package org.apache.shiro.event;

/**
 * Publishes events to an event subsystem that will deliver events to registered {@link Subscribe}rs.
 *
 * @since 1.3
 */
public interface Publisher {

    /**
     * Publishes the specified event to an event subsystem that will deliver events to relevant {@link Subscribe}rs.
     *
     * @param event The event object to distribute to relevant subscribers.
     */
    void publish(Object event);
}
