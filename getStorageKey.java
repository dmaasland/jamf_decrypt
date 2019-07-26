 public class getStorageKey {
    public static void main(String[] args) {
        String allCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()-=_+[]{}|;':,.<>?";
        StringBuffer t = new StringBuffer();
        t.append(allCharacters.charAt(53));
        t.append(allCharacters.charAt(38));
        t.append(allCharacters.charAt(64));
        t.append(allCharacters.charAt(59));
        t.append(allCharacters.charAt(55));
        t.append(allCharacters.charAt(72));
        t.append(allCharacters.charAt(87));
        t.append(allCharacters.charAt(71));
        t.append(allCharacters.charAt(24));
        t.append(allCharacters.charAt(67));
        t.append(allCharacters.charAt(66));
        t.append(allCharacters.charAt(53));
        t.append(allCharacters.charAt(10));
        t.append(allCharacters.charAt(32));
        t.append(allCharacters.charAt(12));
        t.append(allCharacters.charAt(39));
        t.append(allCharacters.charAt(60));
        t.append(allCharacters.charAt(58));
        t.append(allCharacters.charAt(51));
        t.append(allCharacters.charAt(37));

        t.append(allCharacters.charAt(5));
        t.append(allCharacters.charAt(7));
        t.append(allCharacters.charAt(1));
        t.append(allCharacters.charAt(37));
        t.append(allCharacters.charAt(80));
        t.append(allCharacters.charAt(72));
        t.append(allCharacters.charAt(38));
        t.append(allCharacters.charAt(83));
        t.append(allCharacters.charAt(9));
        t.append(allCharacters.charAt(88));
        System.out.println(t.toString());
    }
}
