package org.jsecurity.samples.spring.ui;

import org.springframework.context.support.ClassPathXmlApplicationContext;

/**
 * Insert JavaDoc here.
 */
public class WebStartDriver {

    /*--------------------------------------------
    |             C O N S T A N T S             |
    ============================================*/

    /*--------------------------------------------
    |    I N S T A N C E   V A R I A B L E S    |
    ============================================*/

    /*--------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*/

    /*--------------------------------------------
    |  A C C E S S O R S / M O D I F I E R S    |
    ============================================*/

    /*--------------------------------------------
    |               M E T H O D S               |
    ============================================*/

    public static void main(String[] args) {
        new ClassPathXmlApplicationContext( "webstart.spring.xml" );
    }
}
