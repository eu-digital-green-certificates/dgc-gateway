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

package eu.europa.ec.dgc.gateway.service.federation;

import eu.europa.ec.dgc.gateway.config.DgcConfigProperties;
import eu.europa.ec.dgc.gateway.connector.mapper.TrustListMapper;
import eu.europa.ec.dgc.gateway.entity.FederationGatewayEntity;
import eu.europa.ec.dgc.gateway.service.TrustedPartyService;
import java.util.List;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.beans.factory.annotation.BeanFactoryAnnotationUtils;
import org.springframework.context.ApplicationContext;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class FederationGatewayDownloadService {

    private static final String MDC_PROP_GATEWAY_ID = "gatewayId";
    private static final String MDC_PROP_PARSER_STATE = "parserState";

    private final DgcConfigProperties dgcConfigProperties;
    private final FederationGatewayService federationGatewayService;
    private final TrustedPartyService trustedPartyService;
    private final ApplicationContext applicationContext;
    private final TrustListMapper trustListMapper;

    public void triggerDownload() {
        log.info("Starting Download from Federation Gateways");

        List<FederationGatewayEntity> gateways = federationGatewayService.getFederationGateways();
        log.info("Got {} Federation Gateways for download.", gateways.size());

        gateways.forEach(gateway -> {
            FederationDownloader downloader;
            try {
                downloader = BeanFactoryAnnotationUtils.qualifiedBeanOfType(
                    applicationContext.getAutowireCapableBeanFactory(),
                    FederationDownloader.class,
                    gateway.getDownloaderImplementation()
                );
            } catch (NoSuchBeanDefinitionException e) {
                log.error("Unable to find Implementation >>{}<< for Gateway {}",
                    gateway.getDownloaderImplementation(), gateway.getGatewayId());
                federationGatewayService.setStatus(gateway, false, "Unable to find Implementation");
                return;
            }

            log.debug("Found Downloader implementation >>{}<< for Gateway {}",
                downloader.getDownloaderIdentifier(), gateway.getGatewayId());

            try {
                downloader.fullDownload(gateway);
            } catch (FederationDownloader.FederationDownloaderException e) {
                log.error("Failed to Download Data from Gateway {}, Reason: {}", gateway.getGatewayId(), e.getReason());
                federationGatewayService.setStatus(gateway, false, e.getReason());
                return;
            }
            federationGatewayService.setStatus(gateway, true, null);
        });

        log.info("Finished Federation Gateway Download.");
    }
}
