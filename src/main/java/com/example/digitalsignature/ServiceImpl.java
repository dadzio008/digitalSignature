package com.example.digitalsignature;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.AddressException;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import javax.mail.util.ByteArrayDataSource;
import java.net.PasswordAuthentication;
import java.security.*;

@Service
public class ServiceImpl {

    public void sendDokumentMail(MultipartFile[] file,String email) {
        Security.addProvider(new BouncyCastleProvider());

        try {
            // Generowanie klucza
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
            keyPairGenerator.initialize(2048); // Długość klucza
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();

            // Przygotowanie danych do podpisu
            String message = "Hello, this is a document to be signed.";
            byte[] data = message.getBytes();

            // Podpisywanie danych
            Signature signature = Signature.getInstance("SHA256withRSA", "BC");
            signature.initSign(privateKey);
            signature.update(data);
            byte[] digitalSignature = signature.sign();

            // Weryfikacja podpisu
            signature.initVerify(publicKey);
            signature.update(data);
            boolean verified = signature.verify(digitalSignature);
            System.out.println("Signature verified: " + verified);

            // Wysyłanie zabezpieczonego dokumentu mailem
            sendEmailWithAttachment("sender@example.com", "recipient@example.com", "Signed Don cument", message, digitalSignature);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void sendEmailWithAttachment(String from, String to, String subject, String content, byte[] attachment) {
        final String username = "your_email@example.com";
        final String password = "your_email_password";

        java.util.Properties props = new java.util.Properties();
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.starttls.enable", "true");
        props.put("mail.smtp.host", "smtp.example.com");
        props.put("mail.smtp.port", "587");

        Session session = Session.getInstance(props,
                new javax.mail.Authenticator() {
                    protected PasswordAuthentication getPasswordAuthentication() {
                        return new PasswordAuthentication(username, password);
                    }
                });

        try {
            Message message = new MimeMessage(session);
            message.setFrom(new InternetAddress(from));
            message.setRecipients(Message.RecipientType.TO, InternetAddress.parse(to));
            message.setSubject(subject);
            message.setText(content);

            // Załącznik z podpisem
            MimeMessageHelper helper = new MimeMessageHelper(message, true);
            ByteArrayDataSource source = new ByteArrayDataSource(attachment, "application/octet-stream");
            helper.addAttachment("signature.dat", source);

            Transport.send(message);
            System.out.println("Email sent successfully.");
        } catch (MessagingException e) {
            throw new RuntimeException(e);
        }
    }
}

