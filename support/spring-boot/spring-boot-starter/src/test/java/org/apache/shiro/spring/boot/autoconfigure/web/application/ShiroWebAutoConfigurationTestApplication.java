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
package org.apache.shiro.spring.boot.autoconfigure.web.application;


import org.apache.shiro.event.EventBus;
import org.apache.shiro.event.EventBusAware;
import org.apache.shiro.event.Subscribe;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.realm.text.TextConfigurationRealm;
import org.apache.shiro.spring.web.config.DefaultShiroFilterChainDefinition;
import org.apache.shiro.spring.web.config.ShiroFilterChainDefinition;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableAutoConfiguration
public class ShiroWebAutoConfigurationTestApplication {

    public static void main(String[] args) {
        SpringApplication.run(ShiroWebAutoConfigurationTestApplication.class, args);
    }

    @Bean
    @SuppressWarnings("Duplicates")
    Realm getTextConfigurationRealm() {

        TextConfigurationRealm realm = new TextConfigurationRealm();
        realm.setUserDefinitions("joe.coder=password,user\n" +
                                 "jill.coder=password,admin");

        realm.setRoleDefinitions("admin=read,write\n" +
                                 "user=read");
        realm.setCachingEnabled(true);
        return realm;
    }

    @Bean
    ShiroFilterChainDefinition shiroFilterChainDefinition() {
        DefaultShiroFilterChainDefinition chainDefinition = new DefaultShiroFilterChainDefinition();
        chainDefinition.addPathDefinition("/login.html", "authc");
        return chainDefinition;
    }

    @Bean
    EventBusAwareObject eventBusAwareObject() {
        return new EventBusAwareObject();
    }

    @Bean
    SubscribedListener subscribedListener() {
        return new SubscribedListener();
    }


    public static class EventBusAwareObject implements EventBusAware {

        private EventBus eventBus;

        @Override
        public void setEventBus(EventBus bus) {
            this.eventBus = bus;
        }

        public EventBus getEventBus() {
            return eventBus;
        }
    }

    public static class SubscribedListener {

        @Subscribe
        public void onEvent(Object object) {}
    }
}
