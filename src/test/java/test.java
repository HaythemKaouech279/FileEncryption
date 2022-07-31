import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
// to test the CryptoAES,CryptoRSA classes and all their functions
public class test {
    public static void main(String [] args) throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, UnsupportedEncodingException, NoSuchProviderException, InvalidAlgorithmParameterException {
        CryptoRSA crsa =new CryptoRSA();
        crsa.init(1024);
        String encrypted =crsa.crypter("bonjour");
       System.out.println("encripted message RSA: "+ encrypted);
       System.out.println("decripted message RSA : " +crsa.decrypter(encrypted));
       CryptoAES caes =new CryptoAES();
       String encryptedAES = caes.encrypt("hello");
        System.out.println("encripted message AES: "+ encryptedAES);
        System.out.println("decripted message AES : " +caes.decrypt(encryptedAES));


    }
}
