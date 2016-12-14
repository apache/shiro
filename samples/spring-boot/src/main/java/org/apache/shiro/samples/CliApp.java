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
package org.apache.shiro.samples;

import org.apache.shiro.realm.Realm;
import org.apache.shiro.realm.text.TextConfigurationRealm;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;


/**
 * Spring Boot Application that show the usage of a user login, checking permissions, and annotation protected methods.
 *
 * @see QuickStart
 * @see SimpleService
 */
@Configuration
@SpringBootApplication
public class CliApp { //NOPMD

    public static void main(String[] args) {

        ConfigurableApplicationContext context = SpringApplication.run(CliApp.class, args);

        // Grab the 'QuickStart' bean, call 'run()' to start the example.
        context.getBean(QuickStart.class).run();
    }

    /**
     * Example hard coded Realm bean.
     * @return hard coded Realm bean
     */
    @Bean
    public Realm realm() {
        TextConfigurationRealm realm = new TextConfigurationRealm();
        realm.setUserDefinitions("joe.coder=password,user\n" +
                                 "jill.coder=password,admin");

        realm.setRoleDefinitions("admin=read,write\n" +
                                 "user=read");
        realm.setCachingEnabled(true);
        return realm;
    }

}
