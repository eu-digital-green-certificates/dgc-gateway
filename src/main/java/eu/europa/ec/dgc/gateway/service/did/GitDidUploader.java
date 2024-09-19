package eu.europa.ec.dgc.gateway.service.did;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import eu.europa.ec.dgc.gateway.config.DgcConfigProperties;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.stereotype.Service;

@ConditionalOnExpression("'${dgc.did.didUploadProvider}'.contains('git')")
@Service
@Slf4j
public class GitDidUploader implements DidUploader {
    
    private final DgcConfigProperties configProperties;    
    
    public GitDidUploader(DgcConfigProperties configProperties) {
        this.configProperties = configProperties;        
    }
    
   
    private Request prepareRequest(String owner, String repo, String path, String content, String token)
            throws JsonProcessingException {
        String url = "https://api.github.com/repos/" + owner + "/" + repo + "/contents/" + path;

        // Encode file content to Base64
        String encodedContent = Base64.getEncoder().encodeToString(content.getBytes(StandardCharsets.UTF_8));

        // Prepare JSON payload
        Map<String, String> jsonMap = new HashMap<>();
        jsonMap.put("message", "Automated commit message");
        jsonMap.put("content", encodedContent);
        jsonMap.put("branch", configProperties.getDid().getGit().getBranch());

        ObjectMapper objectMapper = new ObjectMapper();
        String jsonPayload = objectMapper.writeValueAsString(jsonMap);

        RequestBody body = RequestBody.create(jsonPayload, MediaType.parse("application/json"));
        Request request = new Request.Builder()
                .url(url)
                .header("Authorization", "Bearer " + token)
                .header("Accept", "application/vnd.github+json")
                .header("X-GitHub-Api-Version", "2022-11-28")
                .put(body)
                .build();
        return request;
    }
    
    private void uploadFileToGitHub(String owner, String repo, String path, String content, String token) 
        throws IOException {
        OkHttpClient client = new OkHttpClient();

        Request request = prepareRequest(owner, repo, path, content, token);

        Response response = client.newCall(request).execute();
        if (response.isSuccessful()) {
            log.info("File uploaded successfully");
        } else {
            log.error("Failed to upload file: " + response.message());
        }
    }

    @Override
    public void uploadDid(byte[] content) {        
        String fileContent = new String(content, StandardCharsets.UTF_8);
        try {
            uploadFileToGitHub(configProperties.getDid().getGit().getOwner(), 
                    configProperties.getDid().getGit().getWorkdir(), 
                    configProperties.getDid().getGit().getPrefix() + "/" + configProperties.getDid().getGit().getUrl(), 
                    fileContent, 
                    configProperties.getDid().getGit().getPat());
        } catch (IOException e) {
            log.error("Error occured while uploading a file to Github");
        }
        log.info("Upload successful");
    }    

    @Override
    public void uploadDid(String subContainer, byte[] content) {
        
        String fileContent = new String(content, StandardCharsets.UTF_8);
        try {
            uploadFileToGitHub(configProperties.getDid().getGit().getOwner(), 
                    configProperties.getDid().getGit().getWorkdir(), 
                    configProperties.getDid().getGit().getPrefix() + "/" 
                    + subContainer + "/" + configProperties.getDid().getGit().getUrl(), 
                    fileContent, 
                    configProperties.getDid().getGit().getPat());
        } catch (IOException e) {
            log.error("Error occured while uploading a file to Github");
        }
        log.info("Upload successful");
    }
}
