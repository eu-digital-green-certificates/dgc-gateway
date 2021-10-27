/*-
 * ---license-start
 * EU Digital Green Certificate Gateway Service / dgc-gateway
 * ---
 * Copyright (C) 2021 T-Systems International GmbH and all other contributors
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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import eu.europa.ec.dgc.gateway.client.JrcClient;
import eu.europa.ec.dgc.gateway.model.JrcRatValueset;
import eu.europa.ec.dgc.gateway.model.JrcRatValuesetResponse;
import eu.europa.ec.dgc.gateway.model.RatValueset;
import eu.europa.ec.dgc.gateway.model.Valueset;
import eu.europa.ec.dgc.gateway.utils.DgcMdc;
import feign.FeignException;
import java.time.LocalDate;
import java.time.ZonedDateTime;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Optional;
import javax.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class RatValuesetUpdateService {

    private static final String RAT_VALUESET_ID = "covid-19-lab-test-manufacturer-and-name";

    private static final TypeReference<Valueset<String, RatValueset>> typeReference = new TypeReference<>() {
    };

    private final ValuesetService valuesetService;

    private final ObjectMapper objectMapper;

    private final JrcClient jrcClient;

    /**
     * Setup ObjectMapper to keep Timezone when deserializing.
     */
    @PostConstruct
    public void setup() {
        objectMapper.disable(DeserializationFeature.ADJUST_DATES_TO_CONTEXT_TIME_ZONE);
    }

    /**
     * Updates the ValueSet for Rapid Antigen Tests.
     */
    @Scheduled(fixedDelayString = "${dgc.jrc.interval:21600000}")
    @SchedulerLock(name = "rat_valueset_update")
    public void update() {
        log.info("Starting RAT Valueset update");

        Optional<String> valueSetJson = valuesetService.getValueSetById(RAT_VALUESET_ID);
        Valueset<String, RatValueset> parsedValueset =
            new Valueset<>(RAT_VALUESET_ID, LocalDate.now(), new HashMap<>());

        if (valueSetJson.isPresent()) {
            try {
                parsedValueset = objectMapper.readValue(valueSetJson.get(), typeReference);
            } catch (JsonProcessingException e) {
                log.error("Could not parse RatValueSet", e);
            }
        }

        JrcRatValuesetResponse jrcResponse;
        try {
            jrcResponse = jrcClient.downloadRatValues();
        } catch (FeignException e) {
            log.error("Failed to download RatValueset from JRC", e);
            return;
        }

        for (JrcRatValueset device : jrcResponse.getDeviceList()) {
            JrcRatValueset.HscListHistory latestHistoryEntryNotInFuture = null;
            JrcRatValueset.HscListHistory latestHistoryEntry = null;
            long now = ZonedDateTime.now().toEpochSecond();

            if (device.getHscListHistory() != null) {

                latestHistoryEntryNotInFuture = device.getHscListHistory().stream()
                    .sorted(Comparator
                        .comparing((JrcRatValueset.HscListHistory x) -> x.getListDate().toEpochSecond())
                        .reversed())
                    .dropWhile(x -> x.getListDate().toEpochSecond() > now)
                    .findFirst()
                    .orElse(null);

                latestHistoryEntry = device.getHscListHistory().stream()
                    .max(Comparator.comparing(x -> x.getListDate().toEpochSecond()))
                    .orElse(null);
            }

            if (latestHistoryEntry == null) {
                DgcMdc.put("valuesetId", device.getIdDevice());
                log.error("Valueset Entry has no history information. Skipping entry.");
                DgcMdc.remove("valuesetId");
            } else {
                RatValueset valuesetInDb =
                    parsedValueset.getValue().computeIfAbsent(device.getIdDevice(), s -> new RatValueset());

                valuesetInDb.setDisplay(
                    String.format("%s, %s", device.getManufacturer().getName(), device.getCommercialName()));

                if (latestHistoryEntryNotInFuture != null) {
                    valuesetInDb.setActive(latestHistoryEntryNotInFuture.getInCommonList());
                    valuesetInDb.setVersion(latestHistoryEntryNotInFuture.getListDate());
                } else {
                    valuesetInDb.setActive(null);
                    valuesetInDb.setVersion(null);
                }

                if (latestHistoryEntry.getListDate().toEpochSecond() < now) {
                    valuesetInDb.setValidUntil(null);
                } else {
                    valuesetInDb.setValidUntil(latestHistoryEntry.getListDate());
                }
            }
        }

        parsedValueset.setDate(LocalDate.now());
        String updatedValuesetJson;
        try {
            updatedValuesetJson = objectMapper.writeValueAsString(parsedValueset);
        } catch (JsonProcessingException e) {
            log.error("Failed to write updated RAT Valueset as String", e);
            return;
        }

        valuesetService.updateValueSet(RAT_VALUESET_ID, updatedValuesetJson);
        log.info("Updating RAT Valueset finished.");
    }
}
