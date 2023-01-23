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
package org.apache.shiro.ee.cdi;

import org.apache.shiro.ee.cdi.AopHelper.SecurityInterceptor;
import java.io.Serializable;
import java.util.List;
import javax.annotation.Priority;
import javax.enterprise.context.Dependent;
import javax.interceptor.AroundInvoke;
import javax.interceptor.Interceptor;
import javax.interceptor.InvocationContext;

/**
 * Enforce Shiro security on EJBs and CDI Beans
 */
@Interceptor @ShiroSecureAnnotation @Dependent @Priority(Interceptor.Priority.LIBRARY_BEFORE)
public class ShiroSecurityInterceptor implements Serializable {
    private static final long serialVersionUID = 1L;

    @AroundInvoke
    public Object propagateShiroSecurity(final InvocationContext ctx) throws Exception {
        checkPermissions(ctx);
        return ctx.proceed();
    }


    private void checkPermissions(final InvocationContext ctx) throws Exception {
        List<SecurityInterceptor> siList = AopHelper.createSecurityInterceptors(ctx.getMethod(),
                ctx.getMethod().getDeclaringClass());
        siList.forEach(SecurityInterceptor::intercept);
    }
}
