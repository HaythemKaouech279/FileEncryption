import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public  class CryptoFile {
    public static CryptoRSA crsa =new CryptoRSA();


    public CryptoFile() throws NoSuchAlgorithmException {

        crsa.init(1048);    }
    public static void init(int keySize) throws NoSuchAlgorithmException {

        crsa.init(keySize);

    }
    //anytype of file encryption ... note that we return the secret key in a byte[] format to be used later in the decryption
    public static byte[] encryptFile(String algorithm, SecretKey key, IvParameterSpec iv,
                                   File inputFile, File outputFile) throws IOException, NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        FileInputStream inputStream = new FileInputStream(inputFile);
        FileOutputStream outputStream = new FileOutputStream(outputFile);
        byte[] buffer = new byte[64];
        int bytesRead;
        while ((bytesRead = inputStream.read(buffer)) != -1) {
            byte[] output = cipher.update(buffer, 0, bytesRead);
            if (output != null) {
                outputStream.write(output);
            }
        }
        byte[] outputBytes = cipher.doFinal();
        if (outputBytes != null) {
            outputStream.write(outputBytes);
        }
        inputStream.close();
        outputStream.close();
      return   crsa.crypterByte(key.getEncoded());

    }
    //used to decrypt any kind of file
    public static void decryptFile(String algorithm, byte[] key, IvParameterSpec iv,
                                   File inputFile, File outputFile) throws IOException, NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {
        byte[] decryptedSecretKeyByte=crsa.decrypterByte(key);
        SecretKeySpec decryptedSecretkey=new SecretKeySpec(decryptedSecretKeyByte, "AES");
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, decryptedSecretkey, iv);
        FileInputStream inputStream = new FileInputStream(inputFile);
        FileOutputStream outputStream = new FileOutputStream(outputFile);
        byte[] buffer = new byte[64];
        int bytesRead;
        while ((bytesRead = inputStream.read(buffer)) != -1) {
            byte[] output = cipher.update(buffer, 0, bytesRead);
            if (output != null) {
                outputStream.write(output);
            }
        }
        byte[] outputBytes = cipher.doFinal();
        if (outputBytes != null) {
            outputStream.write(outputBytes);
        }
        inputStream.close();
        outputStream.close();
    }
    // you only give the name of the files (input output and encrypted )
    public static void FullEncryptionDecription(String inputFile,String outputFile,String encryptedFile) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, IOException, BadPaddingException, InvalidKeyException {
        File input = new File(inputFile);
        File encrypted = new File(encryptedFile);
        File decrypted = new File(outputFile);

        init(1048);

        KeyGenerator kgen = KeyGenerator.getInstance("AES");

        SecretKey skey = kgen.generateKey();
        byte[] iv = new byte[128/8];

        IvParameterSpec ivspec = new IvParameterSpec(iv);
        String algo="AES/CBC/PKCS5Padding";


        byte[]encryptedKey=encryptFile(algo,skey,ivspec,input,encrypted);
        decryptFile(algo,encryptedKey,ivspec,encrypted,decrypted);

    }
    //this overriden function gives you the possiblity to specify the parameters like the algorithm used and iv parameter
   public static void FullEncryptionDecription(String algorithm, SecretKey key, IvParameterSpec iv,
                                  String inputFile,String outputFile,String encryptedFile) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, IOException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        File input = new File(inputFile);
        File encrypted = new File(encryptedFile);
        File decrypted = new File(outputFile);
        byte[]encryptedKey=encryptFile(algorithm,key,iv,input,encrypted);
        decryptFile(algorithm,encryptedKey,iv,encrypted,decrypted);
    }




    }





