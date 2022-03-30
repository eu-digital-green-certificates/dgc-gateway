/*-
 * ---license-start
 * EU Digital Green Certificate Gateway Service / dgc-gateway
 * ---
 * Copyright (C) 2021 - 2022 T-Systems International GmbH and all other contributors
 * ---
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ---license-end
 */

package eu.europa.ec.dgc.gateway.client;

import eu.europa.ec.dgc.gateway.model.AssetManagerSynchronizeResponseDto;
import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;

@FeignClient(
    name = "assetManagerClient",
    url = "${dgc.publication.url}",
    configuration = AssetManagerClientConfig.class)
@ConditionalOnProperty("dgc.publication.enabled")
public interface AssetManagerClient {

    @PutMapping(
        value = "/remote.php/dav/files/{uid}/{path}/{filename}",
        consumes = MediaType.APPLICATION_OCTET_STREAM_VALUE,
        produces = MediaType.ALL_VALUE)
    ResponseEntity<Void> uploadFile(@RequestHeader(HttpHeaders.AUTHORIZATION) String authHeader,
                                    @PathVariable("uid") String uid,
                                    @PathVariable("path") String path,
                                    @PathVariable("filename") String filename,
                                    @RequestBody byte[] file);

    @PostMapping(
        value = "/ocs/v2.php/apps/files/api/v2/synchronize",
        consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE,
        produces = MediaType.APPLICATION_JSON_VALUE
    )
    ResponseEntity<AssetManagerSynchronizeResponseDto> synchronize(
        @RequestHeader(HttpHeaders.AUTHORIZATION) String authHeader,
        @RequestHeader("OCS-APIRequest") String ocsApiRequest,
        @RequestBody SynchronizeFormData formData);

    @Getter
    @AllArgsConstructor
    class SynchronizeFormData {
        private String path;
        private String nodeList;
        private String notifyEmails;
    }
}
