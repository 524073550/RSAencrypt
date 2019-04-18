package lau.stephen.rsaencrypt;

import android.util.Base64;

public class EncryptUtils {

    static {
        System.loadLibrary("encrypt");
    }

    public static native byte[] encodeByRSAPubKey(byte[] src);
    public static native byte[] decodeByRSAPrivateKey(byte[] src);

    public static String encode(String toEncodeString) {
        byte[] encodedData = encodeByRSAPubKey(toEncodeString.getBytes());

        return Base64.encodeToString(encodedData, Base64.NO_WRAP);
    }

    public static String decode(String toDecodeString) {

        byte[] toDecodeData = Base64.decode(toDecodeString, Base64.NO_WRAP);

        byte[] decodedData = decodeByRSAPrivateKey(toDecodeData);
        if (decodedData == null) {
            return "";
        }
        return new String(decodedData);
    }
}
