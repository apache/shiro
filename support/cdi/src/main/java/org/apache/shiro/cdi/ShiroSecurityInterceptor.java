/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.shiro.cdi;


import java.io.Serial;
import java.io.Serializable;
import jakarta.annotation.Priority;
import jakarta.enterprise.context.Dependent;
import jakarta.interceptor.AroundInvoke;
import jakarta.interceptor.Interceptor;
import jakarta.interceptor.InvocationContext;

import lombok.SneakyThrows;
import lombok.experimental.Delegate;
import org.apache.shiro.aop.DefaultAnnotationResolver;
import org.apache.shiro.aop.MethodInvocation;
import org.apache.shiro.authz.aop.AnnotationsAuthorizingMethodInterceptor;
import org.apache.shiro.authz.aop.AuthorizationAnnotations;

/**
 * Enforce Shiro security on EJBs and CDI Beans.
 * <p>
 * Delegates to the same {@link AnnotationsAuthorizingMethodInterceptor} chain used by the other integrations,
 * so annotations on interfaces, superclasses and composed annotations are honored identically.
 */
@Interceptor
@ShiroSecureAnnotation
@Dependent
@Priority(Interceptor.Priority.LIBRARY_BEFORE)
public class ShiroSecurityInterceptor implements Serializable {
    @Serial
    private static final long serialVersionUID = 1L;

    private static final AnnotationsAuthorizingMethodInterceptor INTERCEPTOR = new AnnotationsAuthorizingMethodInterceptor(
            new DefaultAnnotationResolver(), AuthorizationAnnotations.allTypes()) {
    };

    @AroundInvoke
    @SneakyThrows
    public Object propagateShiroSecurity(final InvocationContext ctx) {
        return INTERCEPTOR.invoke(new InvocationAdapter(ctx));
    }

    /**
     * Adapts a CDI {@link InvocationContext} to a Shiro {@link MethodInvocation}.
     * {@code proceed} and {@code getMethod} are delegated, the other two have different names in CDI.
     */
    private record InvocationAdapter(@Delegate InvocationContext context) implements MethodInvocation {
        @Override
        public Object[] getArguments() {
            return getParameters();
        }

        @Override
        public Object getThis() {
            return getTarget();
        }
    }
}
