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
package org.apache.shiro.samples.spring.config;

import org.apache.shiro.samples.spring.SampleManager;
import org.apache.shiro.spring.remoting.SecureRemoteInvocationExecutor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.remoting.httpinvoker.HttpInvokerServiceExporter;

/**
 * Remoting bean definitions.
 */
@Configuration
@ComponentScan("org.apache.shiro.samples.spring")
public class RemotingServletConfig {

    @Bean(name = "/sampleManager")
    public HttpInvokerServiceExporter accountServiceExporter(SampleManager sampleManager,
                                                             SecureRemoteInvocationExecutor secureRemoteInvocationExecutor) {

        HttpInvokerServiceExporter httpInvokerServiceExporter = new HttpInvokerServiceExporter();
        httpInvokerServiceExporter.setService(sampleManager);
        httpInvokerServiceExporter.setServiceInterface(SampleManager.class);
        httpInvokerServiceExporter.setRemoteInvocationExecutor(secureRemoteInvocationExecutor);
        return httpInvokerServiceExporter;
    }
}
