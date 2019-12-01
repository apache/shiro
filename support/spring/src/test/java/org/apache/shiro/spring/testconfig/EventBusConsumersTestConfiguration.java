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
package org.apache.shiro.spring.testconfig;


import org.apache.shiro.event.EventBus;
import org.apache.shiro.event.EventBusAware;
import org.apache.shiro.event.Subscribe;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class EventBusConsumersTestConfiguration {

    @Bean
    protected EventBusAwareObject eventBusAwareObject() {
        return new EventBusAwareObject();
    }

    @Bean
    protected EventSubscriber subscriber(){
        return new EventSubscriber();
    }

    public class EventBusAwareObject implements EventBusAware {

        private EventBus eventBus;

        public EventBus getEventBus() {
            return eventBus;
        }

        public void setEventBus(EventBus eventBus) {
            this.eventBus = eventBus;
        }
    }

    public class EventSubscriber {

        @Subscribe
        public void listen(Object object) {}

    }

}
