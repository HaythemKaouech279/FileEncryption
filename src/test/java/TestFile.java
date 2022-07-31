


import javax.crypto.*;

import java.io.IOException;
import java.security.*;

public class TestFile {
    public static void main(String[] args) throws NoSuchAlgorithmException,  IOException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
      CryptoFile.FullEncryptionDecription("inputFile.txt","outputFile.txt","encryptedFile.txt");
      CryptoFile.FullEncryptionDecription("inputFile.docx","outputFile.docx","encryptedFile.docx");
      CryptoFile.FullEncryptionDecription("inputFile.png","outputFile.png","encryptedFile.png");
      CryptoFile.FullEncryptionDecription("inputFile.mp4","outputFile.mp4","encryptedFile.mp4");
      CryptoFile.FullEncryptionDecription("inputFile.mp3","outputFile.mp3","encryptedFile.mp3");


    }
}
