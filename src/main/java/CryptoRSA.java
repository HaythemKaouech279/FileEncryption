import javax.crypto.*;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.util.Base64;
//used to encrypt/decrypt files using rsa algorithm
public class CryptoRSA {
    private KeyPair Key;
    private int keySize;
    private PublicKey publicKey;
    private  PrivateKey privateKey;


    public void init(int keySize) throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(keySize);
        Key=keyPairGen.generateKeyPair();
        privateKey=Key.getPrivate();
        publicKey=Key.getPublic();

    }
    public String crypter(String message) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        byte[] messageToBytes =message.getBytes();
        Cipher c= Cipher.getInstance("RSA/ECB/OAEPwithSHA1andMGF1Padding");
        c.init(Cipher.ENCRYPT_MODE,publicKey);
        byte[] encryptedMessage = c.doFinal(messageToBytes);
        return Base64.getEncoder().encodeToString(encryptedMessage);
    }
    public String decrypter(String encryptedmessage) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {

        byte[] messageToBytes = Base64.getDecoder().decode(encryptedmessage);

        Cipher c= Cipher.getInstance("RSA/ECB/OAEPwithSHA1andMGF1Padding");
        c.init(Cipher.DECRYPT_MODE,privateKey);
        byte[] decryptedMessage = c.doFinal(messageToBytes);

       return  new String(decryptedMessage,"UTF8");

    }
    public byte[] crypterByte(byte[] message) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher c= Cipher.getInstance("RSA/ECB/OAEPwithSHA1andMGF1Padding");
        c.init(Cipher.ENCRYPT_MODE,publicKey);
        byte[] encryptedMessage = c.doFinal(message);
        return encryptedMessage;
    }
    public byte[] decrypterByte(byte[] encryptedmessage) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {


        Cipher c= Cipher.getInstance("RSA/ECB/OAEPwithSHA1andMGF1Padding");
        c.init(Cipher.DECRYPT_MODE,privateKey);
        byte[] decryptedMessage = c.doFinal(encryptedmessage);

        return  decryptedMessage;
    }

    public CryptoRSA() {
    }
}
