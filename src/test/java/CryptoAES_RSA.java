import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
//used for encrypting the Secret key with RSA protocol then encrypting the actual message with AES protocol
public class CryptoAES_RSA {

    public static void main(String[] args) throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, NoSuchProviderException, UnsupportedEncodingException, InvalidAlgorithmParameterException {
        CryptoAES caes =new CryptoAES();
        CryptoRSA crsa =new CryptoRSA();
        crsa.init(1024);
        IvParameterSpec ivspec=caes.ivGen();
        SecretKey originalSecretKey = caes.keyGen();

        String encryptedMessage=caes.encryptArg("bonjour",originalSecretKey,ivspec);
        System.out.println(encryptedMessage);
        byte[] encryptedSecretKey=crsa.crypterByte(originalSecretKey.getEncoded());
        byte[] decryptedSecretKeyByte=crsa.decrypterByte(encryptedSecretKey);
        SecretKeySpec decryptedSecretkey=new SecretKeySpec(decryptedSecretKeyByte, "AES");
        String decryptedMessage = caes.decryptArg(encryptedMessage,decryptedSecretkey,ivspec);
        System.out.println(decryptedMessage);




    }




}
