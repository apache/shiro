package org.jsecurity.crypto;

/**
 * Created by IntelliJ IDEA.
 * User: lhazlewood
 * Date: Feb 7, 2008
 * Time: 1:07:36 AM
 * To change this template use File | Settings | File Templates.
 */
public interface AsymmetricCipher extends Cipher {

    byte[] encode( byte[] raw, Key key );

    byte[] decode( byte[] encoded, Key key );
}
