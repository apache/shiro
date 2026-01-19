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
package org.apache.shiro.web.jaxrs;

import jakarta.ws.rs.core.Application;
import jakarta.ws.rs.core.Feature;
import jakarta.ws.rs.core.FeatureContext;
import jakarta.ws.rs.ext.Provider;


/**
 * Shiro JAX-RS feature which includes {@link UnauthorizedExceptionExceptionMapper}, {@link SubjectPrincipalRequestFilter}, and
 * {@link ShiroAnnotationFilterFeature}.
 * <p>
 * Typically, a JAX-RS {@link Application} class will include this Feature class in the
 * classes returned from {@link Application#getClasses()} method, for example:
 * <blockquote><pre>
 *     public class SampleApplication extends Application {
 *
 *         {@code @Override}
 *         {@code public Set<Class<?>>} getClasses() {
 *             {@code Set<Class<?>> classes = new HashSet<Class<?>>();}
 *
 *             // register Shiro
 *             classes.add(ShiroFeature.class);
 *             ...
 *             return classes;
 *         }
 *     }
 * </pre></blockquote>
 * NOTE: Apache CXF requires this annotation on this feature (jersey and resteasy do not)
 *
 * @since 1.4
 */
@Provider
public class ShiroFeature implements Feature {

    @Override
    public boolean configure(FeatureContext context) {
        context.register(UnauthenticatedExceptionExceptionMapper.class);
        context.register(UnauthorizedExceptionExceptionMapper.class);
        context.register(SubjectPrincipalRequestFilter.class);
        context.register(ShiroAnnotationFilterFeature.class);

        return true;
    }
}
