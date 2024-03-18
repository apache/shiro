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
package org.apache.shiro.ee.faces.tags;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.Subject;

import javax.faces.component.UIOutput;
import javax.faces.context.FacesContext;
import java.io.IOException;

/**
 * Base class for JSF components.
 *
 * <p>OBS: Your subclass is responsible for saving the state of the component.
 * See {@link org.apache.shiro.ee.faces.tags.PrincipalTag}'s
 * StateHolder Methods for an example.
 */
public abstract class SecureComponent extends UIOutput {
    protected Subject getSubject() {
        return SecurityUtils.getSubject();
    }

    @Override
    public void encodeEnd(FacesContext ctx) throws IOException {
        verifyAttributes();
        doEncodeAll(ctx);
    }

    protected void verifyAttributes() throws IOException {
    }

    protected abstract void doEncodeAll(FacesContext ctx) throws IOException;
}
