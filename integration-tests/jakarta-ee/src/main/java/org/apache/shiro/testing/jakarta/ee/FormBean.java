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
package org.apache.shiro.testing.jakarta.ee;

import javax.enterprise.inject.Model;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.apache.shiro.ee.filters.Forms;
import org.omnifaces.util.Faces;
import org.omnifaces.util.Messages;

/**
 * form's backing bean
 */
@Model
@Getter @Setter
@Slf4j
public class FormBean {
    private String firstName;
    private String lastName;
    private String address;
    private String city;

    public void submit() {
        Messages.addFlashGlobalInfo("Form Submitted - firstName: {0}, lastName: {1}", firstName, lastName);
        Faces.redirect(Faces.getRequestContextPath() + "/shiro/protected");
    }

    public void submit2() {
        if (Faces.isAjaxRequest()) {
            Messages.addGlobalInfo("2nd Form Submitted - Address: {0}, City: {1}", address, city);
        } else {
            Messages.addFlashGlobalInfo("2nd Form Submitted - Address: {0}, City: {1}", address, city);
            Forms.redirectToView();
        }
    }
}
