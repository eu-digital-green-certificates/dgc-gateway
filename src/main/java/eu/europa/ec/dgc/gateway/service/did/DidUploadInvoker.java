package eu.europa.ec.dgc.gateway.service.did;

import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class DidUploadInvoker {
    
    @Autowired
    List<DidUploader> didUploaders;
    
    /**
     * Method invokes the DID document upload of all the DidUploader implementations. 
     * @param content DID document in byte array form
     */
    public void uploadDid(byte[] content) {
        for (DidUploader didUploader : didUploaders) {
            didUploader.uploadDid(content);
        }
    }
    
    /**
     * Method invokes the DID document upload of all the DidUploader implementations.
     * @param subDirectory is a sub folder
     * @param content DID document in byte array form
     */
    public void uploadDid(String subDirectory, byte[] content) {
        for (DidUploader didUploader : didUploaders) {
            didUploader.uploadDid(subDirectory, content);
        }
    }

}
