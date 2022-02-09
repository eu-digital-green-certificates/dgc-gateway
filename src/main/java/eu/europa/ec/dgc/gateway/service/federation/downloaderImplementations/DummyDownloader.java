/*-
 * ---license-start
 * WHO Digital Documentation Covid Certificate Gateway Service / ddcc-gateway
 * ---
 * Copyright (C) 2022 T-Systems International GmbH and all other contributors
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


package eu.europa.ec.dgc.gateway.service.federation.downloaderImplementations;

import eu.europa.ec.dgc.gateway.entity.FederationGatewayEntity;
import eu.europa.ec.dgc.gateway.service.federation.FederationDownloader;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;

@Service
@Qualifier(DummyDownloader.downloaderIdentifier)
@Slf4j
@RequiredArgsConstructor
public class DummyDownloader implements FederationDownloader {


    final static String downloaderIdentifier = "dummyDownloader_V1";

    @Override
    public String getDownloaderIdentifier() {
        return downloaderIdentifier;
    }

    @Override
    public void fullDownload(FederationGatewayEntity gateway) {
        log.info("Successfully called full Download in DummyDownloader for Gateway {}", gateway.getGatewayId());
    }

    @Override
    public void incrementalDownload(FederationGatewayEntity gateway) {
        log.info("Successfully called incremental Download in DummyDownloader for Gateway {}", gateway.getGatewayId());
    }
}
