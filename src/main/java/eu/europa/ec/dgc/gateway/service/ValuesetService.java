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

package eu.europa.ec.dgc.gateway.service;

import eu.europa.ec.dgc.gateway.entity.ValuesetEntity;
import eu.europa.ec.dgc.gateway.repository.ValuesetRepository;
import eu.europa.ec.dgc.gateway.utils.DgcMdc;
import java.util.List;
import java.util.Optional;
import javax.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Service
@Slf4j
@RequiredArgsConstructor
public class ValuesetService {

    private final ValuesetRepository valuesetRepository;

    /**
     * Gets a list of existing valueset IDs.
     *
     * @return List of Strings
     */
    public List<String> getValuesetIds() {
        log.info("Getting ValueSet IDs");

        return valuesetRepository.getIds();
    }

    /**
     * Gets the content of a valueset by its id.
     *
     * @param id id of the valueset
     * @return the json content
     */
    public Optional<String> getValueSetById(String id) {
        DgcMdc.put("valueSetId", id);
        log.info("Requesting Value Set.");

        return valuesetRepository.findById(id).map(ValuesetEntity::getJson);
    }

    /**
     * Sets the JSON-Value of a ValueSet.
     * If a Valueset with the given ID does not exists it will be created.
     *
     * @param id    ValueSet-ID
     * @param value JSON String containing Valueset.
     */
    @Transactional
    public void updateValueSet(String id, String value) {
        log.info("Updating Valueset.");

        Optional<ValuesetEntity> valuesetEntityOptional = valuesetRepository.findById(id);

        ValuesetEntity valuesetEntity = valuesetEntityOptional.orElse(new ValuesetEntity());
        valuesetEntity.setId(id);
        valuesetEntity.setJson(value);

        valuesetRepository.save(valuesetEntity);
    }

}
