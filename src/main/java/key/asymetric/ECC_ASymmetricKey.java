package key.asymetric;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.security.spec.ECGenParameterSpec;

public class ECC_ASymmetricKey {

    public static void main(String[] argv) {

        try {

            // BouncyCastle is a Java library that complements the default Java Cryptographic Extension (JCE).
            Security.addProvider(new BouncyCastleProvider());

            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
            keyPairGenerator.initialize(new ECGenParameterSpec("secp256r1"));

            KeyPair pair = keyPairGenerator.generateKeyPair();


            // We'll use the public key to encrypt the data and the private one for decrypting it
            PrivateKey privateKey = pair.getPrivate();
            PublicKey publicKey = pair.getPublic();

            // Initialize the cipher for encryption
            Cipher cipher = Cipher.getInstance("ECIESwithAES-CBC");

            // Initialize the cipher for encryption with a public key
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);


            //sensitive information
            byte[] text = "No body can see me".getBytes();

            System.out.println("Text [Byte Format] : " + text);
            System.out.println("Text : " + new String(text));

            // Encrypt the text
            byte[] textEncrypted = cipher.doFinal(text);

            System.out.println("Text Encrypted : " + textEncrypted);

            // Initialize the same cipher for decryption with a private key
            cipher.init(Cipher.DECRYPT_MODE, privateKey, cipher.getParameters());

            // Decrypt the text
            byte[] textDecrypted = cipher.doFinal(textEncrypted);

            System.out.println("Text Decrypted : " + new String(textDecrypted));

        } catch (NoSuchAlgorithmException | NoSuchPaddingException| InvalidKeyException| IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException | NoSuchProviderException e) {
            e.printStackTrace();
        }

    }
}
