package com.example.digitalsignature;

import jakarta.mail.internet.MimeBodyPart;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestAlgorithmIdentifierFinder;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.*;
import java.security.cert.Certificate;

import javax.activation.CommandMap;
import javax.activation.DataHandler;
import javax.activation.MailcapCommandMap;
import javax.crypto.Cipher;
import javax.mail.*;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;
import javax.mail.util.ByteArrayDataSource;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.util.Arrays;
import java.util.Date;
import java.util.Properties;

import static jakarta.mail.Message.RecipientType.CC;
import static jakarta.mail.Message.RecipientType.TO;

@Service
public class ServiceImpl {

    public static final String USERNAME_OUTLOOK = "helpthomeautomatication@outlook.com";
    public static final String PASSWORD = "Zabrze1234567890@5";
    public static final String FROM_EMAIL = "helpthomeautomatication@outlook.com";
    public static final String CC_EMAIL = "";
    public static final String EMAIL_SUBJECT = "PDF file - signed";
    public static final String OUTLOOK_SMTP_SERVER = "smtp-mail.outlook.com";
    public static final String YAHOOO_SMTP_SERVER = "smtp.mail.yahoo.com";
    public static final String SMTP_HOST = "mail.smtp.host";
    public static final String SMTP_AUTH = "mail.smtp.auth";
    public static final String SMTP_PORT = "mail.smtp.port";
    public static final int DEFAULT_PORT = 587;
    public static final String SMTP_STARTTLS_ENABLE = "mail.smtp.starttls.enable";
    public static final String SMTP_STARTTLS_REQUIRED = "mail.smtp.starttls.required";

    public void sendDokument(MultipartFile file, String email) {
        try {
           byte[] signedPDF = signPdfFile(file,"718293".toCharArray(),"JKS","sender");
           saveBytesToFile(signedPDF, "test.pdf");
            jakarta.mail.Message message = createEmail(email, "test.pdf");
            jakarta.mail.Transport.send(message, USERNAME_OUTLOOK, PASSWORD);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

    }

    public static void saveBytesToFile(byte[] bytes, String filePath) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(filePath)) {
            fos.write(bytes);
        }
    }

    private jakarta.mail.Message createEmail(String recipientsEmails, String filePath) throws jakarta.mail.MessagingException, MessagingException, IOException {
        jakarta.mail.Message message = new jakarta.mail.internet.MimeMessage(getEmailSession());
        message.setFrom(new jakarta.mail.internet.InternetAddress(FROM_EMAIL));
        MimeBodyPart attachmentPart = new MimeBodyPart();
        attachmentPart.attachFile(filePath);
        message.setRecipients(TO, jakarta.mail.internet.InternetAddress.parse(recipientsEmails));
        message.setRecipients(CC, jakarta.mail.internet.InternetAddress.parse(CC_EMAIL, false));
        message.setSubject(EMAIL_SUBJECT);
        try {
            message.setText("Hello. U received new pdf file. Public key is: '" + getPublicKey("sender_certificate.cer") + "'");
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        message.setSentDate(new Date());
        message.saveChanges();
        return message;
    }

    private jakarta.mail.Session getEmailSession() {
        Properties properties = System.getProperties();
        properties.put(SMTP_HOST, OUTLOOK_SMTP_SERVER);
        properties.put(SMTP_PORT, DEFAULT_PORT);
        properties.put(SMTP_AUTH, true);
        properties.put("mail.smtp.socketFactory.port", "587");
        properties.put("mail.smtp.socketFactory.class", "javax.net.ssl.SSLSocketFactory");
        properties.put(SMTP_STARTTLS_ENABLE, true);
        properties.put(SMTP_STARTTLS_REQUIRED, true);
        return jakarta.mail.Session.getInstance(properties, new jakarta.mail.Authenticator() {
            protected jakarta.mail.PasswordAuthentication getPasswordAuthentication() {
                return new jakarta.mail.PasswordAuthentication(USERNAME_OUTLOOK, PASSWORD);
            }
        });
    }


    public static PrivateKey getPrivateKey(MultipartFile file, char[] password, String storeType, String alias) throws Exception {
        KeyStore keyStore = KeyStore.getInstance(storeType);
        keyStore.load(new FileInputStream("sender_keystore.jks"), password);
        return (PrivateKey) keyStore.getKey(alias, password);
    }

    public static PublicKey getPublicKey(String certificateFilePath) throws Exception {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        FileInputStream fis = new FileInputStream(certificateFilePath);
        Certificate certificate = certificateFactory.generateCertificate(fis);
        fis.close();
        return certificate.getPublicKey();
    }

    public static byte[] sign(byte[] message, String signingAlgorithm, PrivateKey signingKey) throws SecurityException {
        try {
            Signature signature = Signature.getInstance(signingAlgorithm);
            signature.initSign(signingKey);
            signature.update(message);
            return signature.sign();
        } catch (GeneralSecurityException exp) {
            throw new SecurityException("Error during signature generation", exp);
        }
    }

    public static boolean verify(byte[] messageBytes, String signingAlgorithm, PublicKey publicKey, byte[] signedData) {
        try {
            Signature signature = Signature.getInstance(signingAlgorithm);
            signature.initVerify(publicKey);
            signature.update(messageBytes);
            return signature.verify(signedData);
        } catch (GeneralSecurityException exp) {
            throw new SecurityException("Error during verifying", exp);
        }
    }

    public static byte[] signWithMessageDigestAndCipher(byte[] messageBytes, String hashingAlgorithm, PrivateKey privateKey) {
        try {
            MessageDigest md = MessageDigest.getInstance(hashingAlgorithm);
            byte[] messageHash = md.digest(messageBytes);
            DigestAlgorithmIdentifierFinder hashAlgorithmFinder = new DefaultDigestAlgorithmIdentifierFinder();
            AlgorithmIdentifier hashingAlgorithmIdentifier = hashAlgorithmFinder.find(hashingAlgorithm);
            DigestInfo digestInfo = new DigestInfo(hashingAlgorithmIdentifier, messageHash);
            byte[] hashToEncrypt = digestInfo.getEncoded();

            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, privateKey);
            return cipher.doFinal(hashToEncrypt);
        } catch (GeneralSecurityException | IOException exp) {
            throw new SecurityException("Error during signature generation", exp);
        }
    }

    public static boolean verifyWithMessageDigestAndCipher(byte[] messageBytes, String hashingAlgorithm, PublicKey publicKey, byte[] encryptedMessageHash) {
        try {
            MessageDigest md = MessageDigest.getInstance(hashingAlgorithm);
            byte[] newMessageHash = md.digest(messageBytes);
            DigestAlgorithmIdentifierFinder hashAlgorithmFinder = new DefaultDigestAlgorithmIdentifierFinder();
            AlgorithmIdentifier hashingAlgorithmIdentifier = hashAlgorithmFinder.find(hashingAlgorithm);
            DigestInfo digestInfo = new DigestInfo(hashingAlgorithmIdentifier, newMessageHash);
            byte[] hashToEncrypt = digestInfo.getEncoded();

            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, publicKey);
            byte[] decryptedMessageHash = cipher.doFinal(encryptedMessageHash);
            return Arrays.equals(decryptedMessageHash, hashToEncrypt);
        } catch (GeneralSecurityException | IOException exp) {
            throw new SecurityException("Error during verifying", exp);
        }
    }

    public static byte[] signPdfFile(MultipartFile file, char[] keystorePassword, String keystoreType, String alias) throws Exception {
        PrivateKey privateKey = getPrivateKey(file, keystorePassword, keystoreType, alias);
        byte[] pdfFileBytes = file.getBytes();
        return sign(pdfFileBytes, "SHA256withRSA", privateKey);
    }

    // Metoda do weryfikacji podpisu elektronicznego pliku PDF
//    public static boolean verifyPdfFile(String pdfFilePath, byte[] signature, char[] keystorePassword, String keystoreType, String alias) throws Exception {
//        PublicKey publicKey = getPublicKey(pdfFilePath, keystorePassword, keystoreType, alias);
//        byte[] pdfFileBytes = Files.readAllBytes(new File(pdfFilePath).toPath());
//        return verify(pdfFileBytes, "SHA256withRSA", publicKey, signature);
//    }

    public void verifyDokument(String originalFilename) {
    }
}

