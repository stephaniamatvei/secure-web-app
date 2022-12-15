package md.utm.securewebapp.service;

public class CaesarService {
    public StringBuilder encrypt(String message, int offset) {
        StringBuilder result = new StringBuilder();

        for (char character : message.toCharArray()) {
            if (character != ' ') {
                int originalAlphabetPosition = character - 'a';
                int newAlphabetPosition = (originalAlphabetPosition + offset) % 26;
                char newCharacter = (char) ('a' + newAlphabetPosition);
                result.append(newCharacter);
            } else {
                result.append(character);
            }
        }
        return result;
    }

    public StringBuilder decrypt(String message, int offset) {
        return encrypt(message, 26 - (offset % 26));
    }
}
