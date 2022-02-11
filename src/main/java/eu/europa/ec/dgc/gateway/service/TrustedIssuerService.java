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

package eu.europa.ec.dgc.gateway.service;

import eu.europa.ec.dgc.gateway.entity.TrustedIssuerEntity;
import eu.europa.ec.dgc.gateway.repository.TrustedIssuerRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import java.util.List;

@Slf4j
@Service
@RequiredArgsConstructor
public class TrustedIssuerService {

    private final TrustedIssuerRepository trustedIssuerRepository;

    /**
     * Method to query the db for all trusted issuers.
     *
     * @return List holding the found trusted issuers.
     */
    public List<TrustedIssuerEntity> getAllIssuers() {
        return trustedIssuerRepository.findAll();
    }

    /**
     * Method to query the db for trusted issuers by countryCode.
     *
     * @return List holding the found trusted issuers.
     */
    public List<TrustedIssuerEntity> getAllIssuers(final String countryCode) {
        return trustedIssuerRepository.getAllByCountry(countryCode);
    }
}
