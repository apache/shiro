package org.apache.shiro.subject;

import junit.framework.TestCase;
import org.junit.Test;

public class SimplePrincipalCollectionTest {
    @Test
    public void multiplePrincipalsTest()
    {
        SimplePrincipalCollection principalCollection = new SimplePrincipalCollection();
        principalCollection.add("frank", "realm1");
        principalCollection.add("johnny", "realm1");
        principalCollection.add("Alberto", "realm2");

        PrincipalCollection underTest = principalCollection;

//        underTest.

        System.out.println(principalCollection);
    }
}
