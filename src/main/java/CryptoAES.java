import java.io.UnsupportedEncodingException;
import java.security.*;
import java.util.Base64;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
//used for encrypting and decrypting files using aes algorithm
public class CryptoAES {
    public SecretKey keyGen() throws NoSuchAlgorithmException {

        KeyGenerator kgen = KeyGenerator.getInstance("AES");

        SecretKey skey = kgen.generateKey();
        return skey;
    }
    public IvParameterSpec ivGen() throws NoSuchAlgorithmException, NoSuchProviderException {
        byte[] iv = new byte[128/8];
        SecureRandom srandom = SecureRandom.getInstance("SHA1PRNG", "SUN");

        IvParameterSpec ivspec = new IvParameterSpec(iv);
        return ivspec;
    }
    public SecretKey skey=keyGen();
    public IvParameterSpec ivspec=ivGen();
    public String encrypt(String message) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException {


        Cipher ci = Cipher.getInstance("AES/CBC/PKCS5Padding");
        ci.init(Cipher.ENCRYPT_MODE, skey, ivspec);
        byte[] input = message.getBytes("UTF-8");
        byte[] encoded = ci.doFinal(input);
        return Base64.getEncoder().encodeToString(encoded);

    }
    public String decrypt(String encryptedMessage) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException{

        byte[] messageToBytes = Base64.getDecoder().decode(encryptedMessage);
        Cipher ci = Cipher.getInstance("AES/CBC/PKCS5Padding");
        ci.init(Cipher.DECRYPT_MODE, skey, ivspec);
        byte[] decryptedMessage = ci.doFinal(messageToBytes);

        return  new String(decryptedMessage,"UTF8");

    }
    public String encryptArg(String message,SecretKey secretKey,IvParameterSpec ivspec) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException{


        Cipher ci = Cipher.getInstance("AES/CBC/PKCS5Padding");
        ci.init(Cipher.ENCRYPT_MODE, secretKey, ivspec);
        byte[] input = message.getBytes("UTF-8");
        byte[] encoded = ci.doFinal(input);
        return Base64.getEncoder().encodeToString(encoded);

    }
    public String decryptArg(String encryptedMessage,SecretKey secretKey,IvParameterSpec ivspec) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException{

        byte[] messageToBytes = Base64.getDecoder().decode(encryptedMessage);
        Cipher ci = Cipher.getInstance("AES/CBC/PKCS5Padding");
        ci.init(Cipher.DECRYPT_MODE, secretKey, ivspec);
        byte[] decryptedMessage = ci.doFinal(messageToBytes);

        return  new String(decryptedMessage,"UTF8");

    }


    public CryptoAES() throws NoSuchAlgorithmException, NoSuchProviderException {
    }
}
