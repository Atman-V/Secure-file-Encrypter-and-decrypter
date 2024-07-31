import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.util.Base64;

public class SecureFileEncryptor extends JFrame {
    private JTextField filePathField;
    private JButton browseButton, encryptButton, decryptButton;
    private SecretKey secretKey;

    public SecureFileEncryptor() {
        setTitle("Secure File Encryptor");
        setSize(400, 200);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLayout(new FlowLayout());

        filePathField = new JTextField(20);
        browseButton = new JButton("Browse");
        encryptButton = new JButton("Encrypt");
        decryptButton = new JButton("Decrypt");

        add(new JLabel("File: "));
        add(filePathField);
        add(browseButton);
        add(encryptButton);
        add(decryptButton);

        browseButton.addActionListener(e -> chooseFile());
        encryptButton.addActionListener(e -> encryptFile());
        decryptButton.addActionListener(e -> decryptFile());

        generateAESKey();
    }

    private void chooseFile() {
        JFileChooser fileChooser = new JFileChooser();
        int returnValue = fileChooser.showOpenDialog(this);
        if (returnValue == JFileChooser.APPROVE_OPTION) {
            filePathField.setText(fileChooser.getSelectedFile().getAbsolutePath());
        }
    }

    private void generateAESKey() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256, new SecureRandom());
            secretKey = keyGen.generateKey();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void encryptFile() {
        String filePath = filePathField.getText();
        if (filePath.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Please select a file.");
            return;
        }
        try {
            File inputFile = new File(filePath);
            byte[] fileData = Files.readAllBytes(inputFile.toPath());
            byte[] encryptedData = encrypt(fileData);
            File outputFile = new File(inputFile.getParent(), inputFile.getName() + ".enc");
            Files.write(outputFile.toPath(), encryptedData);
            JOptionPane.showMessageDialog(this, "File encrypted successfully!" + "\nSaved as: " + outputFile.getAbsolutePath());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void decryptFile() {
        String filePath = filePathField.getText();
        if (filePath.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Please select a file.");
            return;
        }
        try {
            File inputFile = new File(filePath);
            byte[] fileData = Files.readAllBytes(inputFile.toPath());
            byte[] decryptedData = decrypt(fileData);
            File outputFile = new File(inputFile.getParent(), inputFile.getName().replace(".enc", "_decrypted"));
            Files.write(outputFile.toPath(), decryptedData);
            JOptionPane.showMessageDialog(this, "File decrypted successfully!" + "\nSaved as: " + outputFile.getAbsolutePath());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private byte[] encrypt(byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return cipher.doFinal(data);
    }

    private byte[] decrypt(byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        return cipher.doFinal(data);
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new SecureFileEncryptor().setVisible(true));
    }
}