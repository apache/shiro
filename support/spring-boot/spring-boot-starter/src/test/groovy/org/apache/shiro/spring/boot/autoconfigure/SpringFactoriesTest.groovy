package org.apache.shiro.spring.boot.autoconfigure

import org.junit.Test

import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.matchesPattern
import static org.hamcrest.Matchers.not

class SpringFactoriesTest {

    @Test
    void springFactoriesConfigContainsNoWhitespace() {
        Properties props = new Properties()
        props.load(new FileReader("src/main/resources/META-INF/spring.factories"))
        assertNoWhitespaceInEntries(props)
    }

    static private assertNoWhitespaceInEntries(Properties props) {
        props.each{ key, val ->
            assertThat "Property [${key}] contains whitespace",
            props.get("org.springframework.boot.autoconfigure.EnableAutoConfiguration"), not(matchesPattern(".*\\s.*"))
        }
    }
}
