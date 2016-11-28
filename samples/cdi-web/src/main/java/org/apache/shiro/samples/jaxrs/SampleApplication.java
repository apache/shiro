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
package org.apache.shiro.samples.jaxrs;

import org.apache.shiro.samples.jaxrs.resources.HelloResource;
import org.apache.shiro.samples.jaxrs.resources.SecureResource;
import org.apache.shiro.samples.jaxrs.resources.WhoAmIResource;
import org.apache.shiro.web.jaxrs.ShiroFeature;

import javax.ws.rs.ApplicationPath;
import javax.ws.rs.core.Application;
import java.util.HashSet;
import java.util.Set;

/**
 * Simple JAX-RS {@link Application} that is implementation agnostic.
 * @since 1.4
 */
@ApplicationPath("/")
public class SampleApplication extends Application {

    @Override
    public Set<Class<?>> getClasses() {
        Set<Class<?>> classes = new HashSet<Class<?>>();

        // register Shiro
        classes.add(ShiroFeature.class);

        // register resources
        classes.add(HelloResource.class);
        classes.add(SecureResource.class);
        classes.add(WhoAmIResource.class);

        return classes;
    }


//    private static final URI BASE_URI = URI.create("http://localhost:8080/");
//
//    public static void main(String[] args) {
//        try {
//            System.out.println("Jersey CDI Example App");
//
//            final Weld weld = new Weld();
//            weld.initialize();
//
//            final HttpServer server = GrizzlyHttpServerFactory.createHttpServer(BASE_URI, createJaxRsApp(), false);
//            Runtime.getRuntime().addShutdownHook(new Thread(new Runnable() {
//                @Override
//                public void run() {
//                    server.shutdownNow();
//                    weld.shutdown();
//                }
//            }));
//            server.start();
//
//            System.out.println(String.format("Application started.\nTry out %s%s\nStop the application using CTRL+C",
//                    BASE_URI, "application.wadl"));
//
//            Thread.currentThread().join();
//        } catch (IOException | InterruptedException ex) {
//            LoggerFactory.getLogger(SampleApplication.class).error(null, ex);
//        }
//
//    }
//
//    private static ResourceConfig createJaxRsApp() {
//        return ResourceConfig.forApplicationClass(SampleApplication.class);
//    }

}
