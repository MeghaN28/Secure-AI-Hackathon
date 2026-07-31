import java.security.MessageDigest;

public class VulnerableCrypto {

    public static void main(String[] args) throws Exception {

        MessageDigest digest =
            MessageDigest.getInstance("MD5");

        byte[] hash =
            digest.digest("sensitive-data".getBytes());

        System.out.println(hash);
    }
}