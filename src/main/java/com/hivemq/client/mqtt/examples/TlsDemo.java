package com.hivemq.client.mqtt.examples;

import com.hivemq.client.mqtt.datatypes.MqttQos;
import com.hivemq.client.mqtt.mqtt5.Mqtt5AsyncClient;
import com.hivemq.client.mqtt.mqtt5.Mqtt5Client;

import javax.net.ssl.*;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.concurrent.TimeUnit;

public class TlsDemo {
    private static final String KEYSTORE_PATH = System.getenv("KEYSTORE_PATH");
    private static final String KEYSTORE_PASS = System.getenv("KEYSTORE_PASS");
    private static final String PRIVATE_KEY_PASS = System.getenv("PRIVATE_KEY_PASS");
    private static final String TRUSTSTORE_PATH = System.getenv("TRUSTSTORE_PATH");
    private static final String TRUSTSTORE_PASS = System.getenv("TRUSTSTORE_PASS");
    private static final String server = System.getenv("MQTT_SERVER");
    private static final int port = Integer.parseInt(System.getenv("MQTT_PORT"));
    private static final MqttQos qos = MqttQos.fromCode(Integer.parseInt(System.getenv("MQTT_QOS")));
    private static final String topic = System.getenv("MQTT_TOPIC");
    private static final String KEYSTORE_TYPE = System.getenv("KEYSTORE_TYPE");
    private static final boolean verifyHostname = Boolean.parseBoolean(System.getenv("VERIFY_HOSTNAME"));

    public static void main(final String[] args) throws InterruptedException, SSLException {

        System.out.println("KEYSTORE_PATH: " + KEYSTORE_PATH);
        System.out.println("KEYSTORE_PASS: " + KEYSTORE_PASS);
        System.out.println("PRIVATE_KEY_PASS: " + PRIVATE_KEY_PASS);
        System.out.println("TRUSTSTORE_PATH: " + TRUSTSTORE_PATH);
        System.out.println("TRUSTSTORE_PASS: " + TRUSTSTORE_PASS);
        System.out.println("server: " + server);
        System.out.println("port: " + port);
        System.out.println("qos: " + qos);
        System.out.println("topic: " + topic);
        System.out.println("KEYSTORE_TYPE: " + KEYSTORE_TYPE);
        System.out.println("verifyHostname: " + verifyHostname);

        checkCertificateExpiry(new File(KEYSTORE_PATH), KEYSTORE_PASS);
        checkCertificateExpiry(new File(TRUSTSTORE_PATH), TRUSTSTORE_PASS);

        final Mqtt5AsyncClient client;

        if (!verifyHostname) {
            System.out.println("building client disabling verification");
            client = Mqtt5Client.builder()
                    .serverHost(server)
                    .serverPort(port)
                    .sslConfig()
                    .keyManagerFactory(keyManagerFromKeystore(
                            new File(KEYSTORE_PATH), KEYSTORE_PASS, PRIVATE_KEY_PASS))
                    .trustManagerFactory(trustManagerFromKeystore(
                            new File(TRUSTSTORE_PATH), TRUSTSTORE_PASS
                    ))
                    .hostnameVerifier(new HostnameVerifier() {
                        public boolean verify(String hostname, SSLSession session) {
                            System.out.println("OK verifying hostname: " + hostname);
                            return true;
                        }
                    })
                    .applySslConfig()
                    .buildAsync();
        } else {
            System.out.println("building client WITH default verification");

            client = Mqtt5Client.builder()
                    .serverHost(server)
                    .serverPort(port)
                    .sslConfig()
                    .keyManagerFactory(keyManagerFromKeystore(
                            new File(KEYSTORE_PATH), KEYSTORE_PASS, PRIVATE_KEY_PASS))
                    .trustManagerFactory(trustManagerFromKeystore(
                            new File(TRUSTSTORE_PATH), TRUSTSTORE_PASS
                    ))
                    .applySslConfig()
                    .buildAsync();
        }

        System.out.println("connecting client...");
        client.connect()
                .thenAccept(connAck -> System.out.println("connected " + connAck))
                .thenCompose(v -> client.publishWith().topic(topic).qos(qos).send())
                .thenAccept(publishResult -> System.out.println("published " + publishResult))
                .thenCompose(v -> client.disconnect())
                .thenAccept(v -> System.out.println("disconnected"));

        System.out.println("...");
        for (int i = 0; i < 5; i++) {
            TimeUnit.MILLISECONDS.sleep(50);
            System.out.println("...");
        }

    }

    public static void checkCertificateExpiry(File keystoreFile, String keystorePassword) {
        try (FileInputStream fis = new FileInputStream(keystoreFile)) {
            KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE);
            keyStore.load(fis, keystorePassword.toCharArray());

            Enumeration<String> aliases = keyStore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                try {
                    Certificate cert = keyStore.getCertificate(alias);
                    if (cert instanceof X509Certificate) {
                        X509Certificate x509Cert = (X509Certificate) cert; //https://docs.oracle.com/en/java/javase/11/docs/api/java.base/java/security/cert/X509Certificate.html
                        try {
                            x509Cert.checkValidity();
                            System.out.println("Certificate '" + alias + "' in keystore " + keystoreFile.getAbsolutePath() + " is valid until " + x509Cert.getNotAfter());
                        } catch (CertificateExpiredException e) {
                            System.out.println("Certificate '" + alias + "' in keystore " + keystoreFile.getAbsolutePath() + " has expired on " + x509Cert.getNotAfter());
                        }
                    }
                } catch (KeyStoreException e) {
                    System.err.println("Error checking certificate with alias '" + alias + "' in keystore " + keystoreFile.getAbsolutePath() + ": " + e.getMessage());
                    //throw new Exception("Error checking certificate", e);
                }
            }
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
            System.err.println("Error checking certificates in keystore " + keystoreFile.getAbsolutePath() + ": " + e.getMessage());
            //throw new Exception("Error checking certificate", e);
        }
    }

    public static TrustManagerFactory trustManagerFromKeystore(
            final File trustStoreFile, final String trustStorePassword) throws SSLException {

        try (final FileInputStream fileInputStream = new FileInputStream(trustStoreFile)) {
            final KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE);
            keyStore.load(fileInputStream, trustStorePassword.toCharArray());

            final TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(keyStore);
            return tmf;

        } catch (final KeyStoreException | IOException e) {
            throw new SSLException(
                    "Not able to open or read trust store '" + trustStoreFile.getAbsolutePath() + "'", e);
        } catch (final NoSuchAlgorithmException | CertificateException e) {
            throw new SSLException(
                    "Not able to read certificate from trust store '" + trustStoreFile.getAbsolutePath() + "'", e);
        }
    }

    public static KeyManagerFactory keyManagerFromKeystore(
            final File keyStoreFile,
            final String keyStorePassword,
            final String privateKeyPassword) throws SSLException {

        try (final FileInputStream fileInputStream = new FileInputStream(keyStoreFile)) {
            final KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE);
            keyStore.load(fileInputStream, keyStorePassword.toCharArray());

            final KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(keyStore, privateKeyPassword.toCharArray());
            return kmf;

        } catch (final UnrecoverableKeyException e) {
            throw new SSLException(
                    "Not able to recover key from key store '" + keyStoreFile.getAbsolutePath() + "', please check your private key password and your key store password",
                    e);
        } catch (final KeyStoreException | IOException e) {
            throw new SSLException("Not able to open or read key store '" + keyStoreFile.getAbsolutePath() + "'", e);

        } catch (final NoSuchAlgorithmException | CertificateException e) {
            throw new SSLException(
                    "Not able to read certificate from key store '" + keyStoreFile.getAbsolutePath() + "'", e);
        }
    }
}
