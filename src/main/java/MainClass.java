import java.security.*;
import java.text.MessageFormat;
import java.util.Base64;

public class MainClass {
    public static void main(String[] args) {
        new MainClass().SignAndVerify("some string");
    }

    void SignAndVerify(String message) {
        try {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

            KeyPair keyPair = generateKeyPair();
            PublicKey publicKey = keyPair.getRsaPublicKey();
            PrivateKey privateKey = keyPair.getRsaPrivateKey();

            byte[] sigBytes = sign(message, privateKey);


            boolean result = verifySignature(message, sigBytes, publicKey);


            print("public key = {0}", publicKey);
            print("private key = {0}", privateKey);
            print("message: {0}", message);
            byte[] sign = Base64.getEncoder().encode(sigBytes);
            print("signature: {0}", sign);
            System.out.println("result = "+result);
        } catch (NoSuchAlgorithmException | NoSuchProviderException | SignatureException | InvalidKeyException ex) {
            System.out.println(ex.toString());
        }
    }

    private byte[] sign(String message, PrivateKey privateKey) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance("SHA1withRSA", "BC");
        signature.initSign(privateKey, new SecureRandom());
        signature.update(message.getBytes());
        return signature.sign();
    }

    private boolean verifySignature(String message, byte[] sigBytes, PublicKey publicKey) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance("SHA1withRSA", "BC");
        signature.initVerify(publicKey);
        signature.update(message.getBytes());
        return signature.verify(sigBytes);
    }

    private KeyPair generateKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException {

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
        keyPairGenerator.initialize(512, new SecureRandom());
        java.security.KeyPair keyPair = keyPairGenerator.generateKeyPair();
        KeyPair generateKeyPair1 = new KeyPair(keyPair.getPrivate(), keyPair.getPublic());
        return generateKeyPair1;
    }

    private void print(String pattern, Object... args) {
        System.out.println(MessageFormat.format(pattern, args));
    }

    public class KeyPair {
        private PublicKey rsaPublicKey;
        private PrivateKey rsaPrivateKey;

        public KeyPair(PrivateKey privateKey, PublicKey publicKey) {
            rsaPublicKey = publicKey;
            rsaPrivateKey = privateKey;
        }

        public PublicKey getRsaPublicKey() {
            return rsaPublicKey;
        }

        public PrivateKey getRsaPrivateKey() {
            return rsaPrivateKey;
        }

    }
}
