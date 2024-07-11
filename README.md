# HiveMQ MQTT Client with TLS Keystore and Truststore

This project demonstrates how to use the HiveMQ MQTT client with TLS keystore and truststore from files.

## Prerequisites

- HiveMQ broker installed
- Java Development Kit (JDK)
- Gradle

## Setup and Testing

### 1. Configure Domain Name

Add the domain name `example1.com` to your hosts file:

```sh
sudo vi /etc/hosts
```

Add the following line:

```
127.0.0.1  example1.com
```

### 2. Generate Certificates, Keystore, and Truststore

Use the [certly.sh](https://github.com/hivemq/support-tools/blob/main/certly/certly.sh) script from the HiveMQ support tools repository with the hostname `example1.com`.

### 3. Configure the Server

1. Copy the generated certificates to the HiveMQ home directory:

   ```sh
   cp certs/broker*jks $HIVEMQ_HOME/
   ```

2. Add a TLS listener to the HiveMQ configuration file:

   ```xml
   <listeners>        
       <tls-tcp-listener>
           <port>8883</port>
           <bind-address>0.0.0.0</bind-address>
           <name>tls-tcp-listener</name>
           <tls>
               <keystore>
                   <path>broker-keystore.jks</path>
                   <password>changeme</password>
                   <private-key-password>changeme</private-key-password>
               </keystore>
               <client-authentication-mode>OPTIONAL</client-authentication-mode>
               <truststore>
                   <path>broker-truststore.jks</path>
                   <password>changeme</password>
               </truststore>
           </tls>
       </tls-tcp-listener>
   </listeners>
   ```

3. Start the server with TLS debugging enabled:

   ```sh
   JAVA_OPTS="$JAVA_OPTS -Djavax.net.debug=ssl,handshake" $HIVEMQ_HOME/bin/run.sh
   ```

### 4. Build the client from code:
```sh
./gradlew clean shadowJar
```
This will produce the following artefact:
```
build/libs/hivemq-mqtt-client-tls-demo-1.0-SNAPSHOT-all.jar
```

### 5. Run the client:

   ```sh
   #!/bin/bash
   
   # Set environment variables
   export KEYSTORE_PATH="/path/to/keystore"
   export KEYSTORE_PASS="your_keystore_password"
   export PRIVATE_KEY_PASS="your_private_key_password"
   export TRUSTSTORE_PATH="/path/to/truststore"
   export TRUSTSTORE_PASS="your_truststore_password"
   export MQTT_SERVER="your_mqtt_server"
   export MQTT_PORT="8883"
   export MQTT_QOS="1"
   export MQTT_TOPIC="your_topic"
   export KEYSTORE_TYPE="JKS"
   export VERIFY_HOSTNAME="true"
   
   # Run the Java program
   java -jar build/libs/hivemq-mqtt-client-tls-demo-1.0-SNAPSHOT-all.jar
   ```

## Additional Information

* For more details on configuring TLS for HiveMQ, please refer to the [official HiveMQ documentation](https://docs.hivemq.com/hivemq/latest/user-guide/security.html#tls).
* https://docs.oracle.com/en/java/javase/11/docs/api/java.base/java/security/cert/X509Certificate.html

