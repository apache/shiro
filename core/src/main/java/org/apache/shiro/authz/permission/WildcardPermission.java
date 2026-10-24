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
package org.apache.shiro.authz.permission;

import org.apache.shiro.authz.Permission;
import org.apache.shiro.authz.aop.AuthorizingAnnotationHandler.AuthorizationConfigPolicy;
import org.apache.shiro.lang.util.Assert;
import org.apache.shiro.util.CollectionUtils;
import org.apache.shiro.lang.util.StringUtils;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * A <code>WildcardPermission</code> is a very flexible permission construct supporting multiple levels of
 * permission matching. However, most people will probably follow some standard conventions as explained below.
 * <p/>
 * <h3>Simple Usage</h3>
 * <p/>
 * In the simplest form, <code>WildcardPermission</code> can be used as a simple permission string. You could grant a
 * user an &quot;editNewsletter&quot; permission and then check to see if the user has the editNewsletter
 * permission by calling
 * <p/>
 * <code>subject.isPermitted(&quot;editNewsletter&quot;)</code>
 * <p/>
 * This is (mostly) equivalent to
 * <p/>
 * <code>subject.isPermitted( new WildcardPermission(&quot;editNewsletter&quot;) )</code>
 * <p/>
 * but more on that later.
 * <p/>
 * The simple permission string may work for simple applications, but it requires you to have permissions like
 * <code>&quot;viewNewsletter&quot;</code>, <code>&quot;deleteNewsletter&quot;</code>,
 * <code>&quot;createNewsletter&quot;</code>, etc. You can also grant a user <code>&quot;*&quot;</code> permissions
 * using the wildcard character (giving this class its name), which means they have <em>all</em> permissions. But
 * using this approach there's no way to just say a user has &quot;all newsletter permissions&quot;.
 * <p/>
 * For this reason, <code>WildcardPermission</code> supports multiple <em>levels</em> of permissioning.
 * <p/>
 * <h3>Multiple Levels</h3>
 * <p/>
 * <code>WildcardPermission</code> also supports the concept of multiple <em>levels</em>.  For example, you could
 * restructure the previous simple example by granting a user the permission <code>&quot;newsletter:edit&quot;</code>.
 * The colon in this example is a special character used by the <code>WildcardPermission</code> that delimits the
 * next token in the permission.
 * <p/>
 * In this example, the first token is the <em>domain</em> that is being operated on
 * and the second token is the <em>action</em> being performed. Each level can contain multiple values.  So you
 * could simply grant a user the permission <code>&quot;newsletter:view,edit,create&quot;</code> which gives them
 * access to perform <code>view</code>, <code>edit</code>, and <code>create</code> actions in the <code>newsletter</code>
 * <em>domain</em>. Then you could check to see if the user has the <code>&quot;newsletter:create&quot;</code>
 * permission by calling
 * <p/>
 * <code>subject.isPermitted(&quot;newsletter:create&quot;)</code>
 * <p/>
 * (which would return true).
 * <p/>
 * In addition to granting multiple permissions via a single string, you can grant all permission for a particular
 * level. So if you wanted to grant a user all actions in the <code>newsletter</code> domain, you could simply give
 * them <code>&quot;newsletter:*&quot;</code>. Now, any permission check for <code>&quot;newsletter:XXX&quot;</code>
 * will return <code>true</code>. It is also possible to use the wildcard token at the domain level (or both): so you
 * could grant a user the <code>&quot;view&quot;</code> action across all domains <code>&quot;*:view&quot;</code>.
 * <p/>
 * <h3>Instance-level Access Control</h3>
 * <p/>
 * Another common usage of the <code>WildcardPermission</code> is to model instance-level Access Control Lists.
 * In this scenario you use three tokens - the first is the <em>domain</em>, the second is the <em>action</em>, and
 * the third is the <em>instance</em> you are acting on.
 * <p/>
 * So for example you could grant a user <code>&quot;newsletter:edit:12,13,18&quot;</code>.  In this example, assume
 * that the third token is the system's ID of the newsletter. That would allow the user to edit newsletters
 * <code>12</code>, <code>13</code>, and <code>18</code>. This is an extremely powerful way to express permissions,
 * since you can now say things like <code>&quot;newsletter:*:13&quot;</code> (grant a user all actions for newsletter
 * <code>13</code>), <code>&quot;newsletter:view,create,edit:*&quot;</code> (allow the user to
 * <code>view</code>, <code>create</code>, or <code>edit</code> <em>any</em> newsletter), or
 * <code>&quot;newsletter:*:*</code> (allow the user to perform <em>any</em> action on <em>any</em> newsletter).
 * <p/>
 * To perform checks against these instance-level permissions, the application should include the instance ID in the
 * permission check like so:
 * <p/>
 * <code>subject.isPermitted( &quot;newsletter:edit:13&quot; )</code>
 * <p/>
 * There is no limit to the number of tokens that can be used, so it is up to your imagination in terms of ways that
 * this could be used in your application.  However, the Shiro team likes to standardize some common usages shown
 * above to help people get started and provide consistency in the Shiro community.
 * <p/>
 * Permission strings are case-insensitive by default, using {@link Locale#ROOT}. Use the
 * {@link #WildcardPermission(String, boolean)} constructor for case-sensitive identifiers.
 * <p/>
 * Do not concatenate untrusted values into permission strings: {@code :}, {@code ,}, and {@code *} are permission
 * syntax, not literal data. Use {@link #fromLiteralParts(String...)} for both grants and checks built from data.
 * This factory rejects reserved characters instead of escaping them.
 * <p/>
 * Setting {@code -Dshiro.authz.strictConfig=true} rejects empty or blank parts and subparts, including trailing
 * separators such as {@code newsletter:edit:}. Without it, legacy parsing is preserved, including discarding trailing
 * separators, which can broaden a grant. Intentionally omitted parts and explicit wildcards remain supported.
 *
 * @since 0.9
 */
public class WildcardPermission implements Permission, Serializable {
    /*--------------------------------------------
    |             C O N S T A N T S             |
    ============================================*/
    protected static final String WILDCARD_TOKEN = "*";
    protected static final String PART_DIVIDER_TOKEN = ":";
    protected static final String SUBPART_DIVIDER_TOKEN = ",";
    protected static final boolean DEFAULT_CASE_SENSITIVE = false;

    /*--------------------------------------------
    |    I N S T A N C E   V A R I A B L E S    |
    ============================================*/
    private List<Set<String>> parts;

    /*--------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*/

    /**
     * Default no-arg constructor for subclasses only - end-user developers instantiating Permission instances must
     * provide a wildcard string at a minimum, since Permission instances are immutable once instantiated.
     * <p/>
     * Note that the WildcardPermission class is very robust and typically subclasses are not necessary unless you
     * wish to create type-safe Permission objects that would be used in your application, such as perhaps a
     * {@code UserPermission}, {@code SystemPermission}, {@code PrinterPermission}, etc.  If you want such type-safe
     * permission usage, consider subclassing the {@link DomainPermission DomainPermission} class for your needs.
     */
    protected WildcardPermission() {
    }

    public WildcardPermission(String wildcardString) {
        this(wildcardString, DEFAULT_CASE_SENSITIVE);
    }

    public WildcardPermission(String wildcardString, boolean caseSensitive) {
        setParts(wildcardString, caseSensitive);
    }

    /**
     * Creates a case-insensitive permission from literal values, without interpreting them as permission syntax.
     *
     * @param parts one literal value per permission level, such as domain, action, and instance ID
     * @return the permission
     * @throws IllegalArgumentException if no parts are supplied or a part is null, blank, has surrounding whitespace,
     *                                  or contains {@code :}, {@code ,}, or {@code *}
     * @since 3.0.2
     */
    public static WildcardPermission fromLiteralParts(String... parts) {
        return fromLiteralParts(DEFAULT_CASE_SENSITIVE, parts);
    }

    /**
     * Creates a permission from literal values. Validation is unconditional, regardless of the
     * {@code shiro.authz.strictConfig} system property. No escaping is supported.
     * <p/>
     * Supply every level needed by the application's permission model: an omitted level still implies all values at
     * that level. Use the string constructors only for trusted permission expressions requiring wildcards or lists.
     *
     * @param caseSensitive whether values are case-sensitive
     * @param parts one literal value per permission level
     * @return the permission
     * @throws IllegalArgumentException if no parts are supplied or a part is null, blank, has surrounding whitespace,
     *                                  or contains {@code :}, {@code ,}, or {@code *}
     * @since 3.0.2
     */
    public static WildcardPermission fromLiteralParts(boolean caseSensitive, String... parts) {
        Assert.notEmpty(parts, "At least one literal permission part is required.");
        Arrays.stream(parts).forEach(part -> {
            Assert.hasText(part, "Literal permission parts cannot be null, empty, or blank.");
            Assert.isTrue(part.equals(part.trim()), "Literal permission parts cannot have surrounding whitespace.");
            List.of(PART_DIVIDER_TOKEN, SUBPART_DIVIDER_TOKEN, WILDCARD_TOKEN).forEach(token ->
                    Assert.doesNotContain(part, token, "Literal permission parts cannot contain ':', ',', or '*'."));
        });
        return new WildcardPermission(String.join(PART_DIVIDER_TOKEN, parts), caseSensitive);
    }

    protected void setParts(String wildcardString) {
        setParts(wildcardString, DEFAULT_CASE_SENSITIVE);
    }

    protected void setParts(String wildcardString, boolean caseSensitive) {
        wildcardString = StringUtils.clean(wildcardString);

        if (wildcardString == null || wildcardString.isEmpty()) {
            throw new IllegalArgumentException("Wildcard string cannot be null or empty. "
                    + "Make sure permission strings are properly formatted.");
        }

        if (!caseSensitive) {
            // Locale.ROOT (as in SHIRO-415/SHIRO-483): under certain non-English default locales "ADMIN" would become "admın"
            wildcardString = wildcardString.toLowerCase(Locale.ROOT);
        }

        List<String> parts = CollectionUtils.asList(wildcardString.split(PART_DIVIDER_TOKEN,
                AuthorizationConfigPolicy.isStrictParsing() ? -1 : 0));

        this.parts = new ArrayList<>();
        parts.stream().map(part -> CollectionUtils.asSet(part.split(SUBPART_DIVIDER_TOKEN,
                        AuthorizationConfigPolicy.isStrictParsing() ? -1 : 0)))
                .forEach(subparts -> {
            if (subparts.isEmpty() || (AuthorizationConfigPolicy.isStrictParsing()
                    && subparts.stream().anyMatch(value -> !StringUtils.hasText(value)))) {
                throw new IllegalArgumentException("Wildcard string cannot contain empty or blank parts or subparts. "
                        + "Make sure permission strings are properly formatted.");
            }
            this.parts.add(subparts);
        });

        if (this.parts.isEmpty()) {
            throw new IllegalArgumentException("Wildcard string cannot contain only dividers. "
                        + "Make sure permission strings are properly formatted.");
        }
    }

    /*--------------------------------------------
    |  A C C E S S O R S / M O D I F I E R S    |
    ============================================*/
    protected List<Set<String>> getParts() {
        return this.parts;
    }

    /**
     * Sets the pre-split String parts of this <code>WildcardPermission</code>.
     *
     * @param parts pre-split String parts.
     * @since 1.3.0
     */
    protected void setParts(List<Set<String>> parts) {
        this.parts = parts;
    }

    /*--------------------------------------------
    |               M E T H O D S               |
    ============================================*/

    @Override
    public boolean implies(Permission p) {
        // By default, only supports comparisons with other WildcardPermissions
        if (!(p instanceof WildcardPermission wp)) {
            return false;
        }

        List<Set<String>> otherParts = wp.getParts();

        int i = 0;
        for (Set<String> otherPart : otherParts) {
            // If this permission has fewer parts than the other permission, everything after the number of parts contained
            // in this permission is automatically implied, so return true
            if (getParts().size() - 1 < i) {
                return true;
            } else {
                Set<String> part = getParts().get(i);
                if (!part.contains(WILDCARD_TOKEN) && !part.containsAll(otherPart)) {
                    return false;
                }
                i++;
            }
        }

        // If this permission has more parts than the other parts, only imply it if all of the other parts are wildcards
        for (; i < getParts().size(); i++) {
            Set<String> part = getParts().get(i);
            if (!part.contains(WILDCARD_TOKEN)) {
                return false;
            }
        }

        return true;
    }

    @Override
    public String toString() {
        StringBuilder buffer = new StringBuilder();
        for (Set<String> part : parts) {
            if (!buffer.isEmpty()) {
                buffer.append(PART_DIVIDER_TOKEN);
            }
            Iterator<String> partIt = part.iterator();
            while (partIt.hasNext()) {
                buffer.append(partIt.next());
                if (partIt.hasNext()) {
                    buffer.append(SUBPART_DIVIDER_TOKEN);
                }
            }
        }
        return buffer.toString();
    }

    @Override
    public boolean equals(Object o) {
        if (o instanceof WildcardPermission wp) {
            return parts.equals(wp.parts);
        }
        return false;
    }

    @Override
    public int hashCode() {
        return parts.hashCode();
    }

}
