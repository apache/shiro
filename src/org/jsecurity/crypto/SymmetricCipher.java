package org.jsecurity.crypto;

/**
 * Created by IntelliJ IDEA.
 * User: lhazlewood
 * Date: Feb 7, 2008
 * Time: 1:06:15 AM
 * To change this template use File | Settings | File Templates.
 */
public interface SymmetricCipher extends Cipher {

    byte[] encrypt( byte[] raw );

    byte[] decrypt( byte[] encrypted );
}
