 public class getSalt {
    public static void main(String[] args) {
        byte[] salt = { -87, -101, -56, 50, 86, 53, -29, 3 };
        StringBuilder sb = new StringBuilder();
        
        for (byte b : salt) {
            sb.append(String.format("%02X ", b));
        }

        System.out.println(sb.toString());
    }
}
