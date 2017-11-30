package org.apache.shiro.realm.ldap;

import org.apache.shiro.util.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class UserDnTemplate {
    private static final Logger log = LoggerFactory.getLogger(UserDnTemplate.class);

    //The zero index currently means nothing, but could be utilized in the future for other substitution techniques.
    static final String SUBSTITUTION_TOKEN = "{0}";

    private final String prefix;
    private final String suffix;

    static UserDnTemplate fromString(final String template) throws IllegalArgumentException {
        if (!StringUtils.hasText(template)) {
            String msg = "User DN template cannot be null or empty.";
            throw new IllegalArgumentException(msg);
        }
        final int index = template.indexOf(SUBSTITUTION_TOKEN);
        if (index < 0) {
            String msg = "User DN template must contain the '" +
                    SUBSTITUTION_TOKEN + "' replacement token to understand where to " +
                    "insert the runtime authentication principal.";
            throw new IllegalArgumentException(msg);
        }
        final String prefix = template.substring(0, index);
        final String suffix = template.substring(prefix.length() + SUBSTITUTION_TOKEN.length());
        if (log.isDebugEnabled()) {
            log.debug("Determined user DN prefix [{}] and suffix [{}]", prefix, suffix);
        }
        return new UserDnTemplate(prefix, suffix);
    }

    static final UserDnTemplate EMPTY = new UserDnTemplate(null, null);

    private UserDnTemplate(final String prefix, final String suffix) {
        this.prefix = prefix;
        this.suffix = suffix;
    }

    String getPrefix() {
        return prefix;
    }

    String getSuffix() {
        return suffix;
    }

    String getUserDn(final String principal) throws IllegalArgumentException, IllegalStateException {
        if (!StringUtils.hasText(principal)) {
            throw new IllegalArgumentException("User principal cannot be null or empty for User DN construction.");
        }
        if (prefix == null && suffix == null) {
            log.debug("userDnTemplate property has not been configured, indicating the submitted " +
                    "AuthenticationToken's principal is the same as the User DN.  Returning the method argument " +
                    "as is.");
            return principal;
        }

        final int prefixLength = prefix != null ? prefix.length() : 0;
        final int suffixLength = suffix != null ? suffix.length() : 0;
        final StringBuilder sb = new StringBuilder(prefixLength + principal.length() + suffixLength);
        if (prefixLength > 0) {
            sb.append(prefix);
        }
        sb.append(principal);
        if (suffixLength > 0) {
            sb.append(suffix);
        }
        return sb.toString();
    }

    @Override
    public String toString() {
        return getUserDn(SUBSTITUTION_TOKEN);
    }
}
