package org.apache.shiro.authz.permission;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import javax.naming.spi.Resolver;

import org.junit.Test;

public class WildcardPermissionResolverTest {

    @Test
    public void testDefaultIsNonCaseSensitive()
    {
        WildcardPermissionResolver resolver = new WildcardPermissionResolver();
        assertFalse( "Default sensitivity should be false", resolver.isCaseSensitive());
        /* this is a round-about test as permissions don't store case sensitivity just lower case 
        the string. */
        WildcardPermission permission = (WildcardPermission) resolver.resolvePermission( "Foo:*" );
        assertEquals( "string should be lowercase", "foo:*", permission.toString());
    }
    
    @Test
    public void testCaseSensitive()
    {
        WildcardPermissionResolver resolver = new WildcardPermissionResolver(true);
        assertTrue( "Sensitivity should be true", resolver.isCaseSensitive());
        /* this is a round-about test as permissions don't store case sensitivity just lower case 
        the string. */
        WildcardPermission permission = (WildcardPermission) resolver.resolvePermission( "Foo:*" );
        assertEquals( "string should be mixed case", "Foo:*", permission.toString());
    }

    @Test
    public void testCaseInsensitive()
    {
        WildcardPermissionResolver resolver = new WildcardPermissionResolver(false);
        assertFalse( "Sensitivity should be false", resolver.isCaseSensitive());
        /* this is a round-about test as permissions don't store case sensitivity just lower case 
        the string. */
        WildcardPermission permission = (WildcardPermission) resolver.resolvePermission( "Foo:*" );
        assertEquals( "string should be lowercase", "foo:*", permission.toString());
    }
    
    @Test
    public void testCaseSensitiveToggle()
    {
        WildcardPermissionResolver resolver = new WildcardPermissionResolver();
        assertFalse( "Default sensitivity should be false", resolver.isCaseSensitive());
        resolver.setCaseSensitive( true );
        assertTrue( "Sensitivity should be true", resolver.isCaseSensitive());
        resolver.setCaseSensitive( false );
        assertFalse( "Sensitivity should be false", resolver.isCaseSensitive());
    }

}
