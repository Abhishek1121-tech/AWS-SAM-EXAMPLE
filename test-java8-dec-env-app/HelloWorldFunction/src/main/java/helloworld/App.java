package helloworld;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.nio.ByteBuffer;
import java.util.Base64;


import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;

import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClientBuilder;
import com.amazonaws.services.kms.model.EncryptRequest;
import com.amazonaws.services.kms.model.DecryptRequest;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.regions.Regions;

/**
 * Handler for requests to Lambda function.
 */
public class App implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final byte[] EXAMPLE_DATA = "Hello World".getBytes(StandardCharsets.UTF_8);

    public APIGatewayProxyResponseEvent handleRequest(final APIGatewayProxyRequestEvent input, final Context context) {
        Map<String, String> headers = new HashMap<>();
        headers.put("Content-Type", "application/json");
        headers.put("X-Custom-Header", "application/json");

        APIGatewayProxyResponseEvent response = new APIGatewayProxyResponseEvent()
                .withHeaders(headers);
        String data=App.encryptAndDecrypt("replace_with_your_own");
        try {
            String output = String.format("{ \"encrypted value\": \"%s\", \"decrypted value\": \"%s\" }",System.getenv("ENC_HELLO_WORLD_PARAM") ,data);

            return response
                    .withStatusCode(200)
                    .withBody(output);
        } catch (Exception e) {
            return response
                    .withBody("{}")
                    .withStatusCode(500);
        }
    }

    private String getPageContents(String address) throws IOException{
        URL url = new URL(address);
        try(BufferedReader br = new BufferedReader(new InputStreamReader(url.openStream()))) {
            return br.lines().collect(Collectors.joining(System.lineSeparator()));
        }
    }

    static String encryptAndDecrypt(final String keyArn) {
        AWSKMS kmsClient = AWSKMSClientBuilder.standard().build();
        String keyId = keyArn;
        //ByteBuffer plaintextEnc = ByteBuffer.wrap(EXAMPLE_DATA);
        //System.out.print(plaintextEnc);
        byte[] ENC_HELLO_WORLD_PARAM = Base64.getDecoder().decode(System.getenv("ENC_HELLO_WORLD_PARAM"));
        ByteBuffer ciphertext = ByteBuffer.wrap(ENC_HELLO_WORLD_PARAM);
        //EncryptRequest reqEnc = new EncryptRequest().withKeyId(keyId).withPlaintext(plaintextEnc);
        //ByteBuffer ciphertext = kmsClient.encrypt(reqEnc).getCiphertextBlob();
        //System.out.print("Cypher Base64: "+Base64.getEncoder().encodeToString(ciphertext.array()));
    
        DecryptRequest reqDec = new DecryptRequest().withCiphertextBlob(ciphertext);
        ByteBuffer plainText = kmsClient.decrypt(reqDec).getPlaintext();
        //System.out.println("decrypted: "+StandardCharsets.UTF_8.decode(plainText).toString());
        String returnData = StandardCharsets.UTF_8.decode(plainText).toString();
        return returnData;
    }
}
