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

import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import eu.europa.ec.dgc.gateway.client.JrcClient;
import eu.europa.ec.dgc.gateway.entity.ValuesetEntity;
import eu.europa.ec.dgc.gateway.model.JrcRatValueset;
import eu.europa.ec.dgc.gateway.model.JrcRatValuesetResponse;
import eu.europa.ec.dgc.gateway.model.RatValueset;
import eu.europa.ec.dgc.gateway.model.Valueset;
import eu.europa.ec.dgc.gateway.repository.ValuesetRepository;
import feign.FeignException;
import feign.Request;
import feign.RequestTemplate;
import java.time.LocalDate;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;

@SpringBootTest
class RatValuesetUpdateServiceTest {

    @MockBean
    JrcClient jrcClientMock;

    @Autowired
    RatValuesetUpdateService ratValuesetUpdateService;

    @Autowired
    ValuesetRepository valuesetRepository;

    @Autowired
    ValuesetService valuesetService;

    @Autowired
    ObjectMapper objectMapper;

    private static final String RAT_VALUESET_ID = "covid-19-lab-test-manufacturer-and-name";

    private RatValueset rat1, rat2;
    private final static String RAT1_ID = "1234";
    private final static String RAT2_ID = "5678";
    private ValuesetEntity otherValuesetEntity, valuesetEntity;
    private Valueset<String, RatValueset> valueset;
    private static final TypeReference<Valueset<String, RatValueset>> typeReference = new TypeReference<>() {
    };
    public static final Request dummyRequest =
        Request.create(Request.HttpMethod.GET, "url", new HashMap<>(), null, new RequestTemplate());

    @BeforeEach
    void setup() throws JsonProcessingException {
        valuesetRepository.deleteAll();

        // Create a dummy valueset which should not be touched
        otherValuesetEntity = new ValuesetEntity(
            "other-valueset-with-different-id",
            "this-should-not-be-changes"
        );
        otherValuesetEntity = valuesetRepository.save(otherValuesetEntity);

        // Create a RAT valueset which should be updated
        rat1 = new RatValueset();
        rat1.setActive(true);
        rat1.setVersion(ZonedDateTime.now().minus(5, ChronoUnit.DAYS));
        rat1.setDisplay("RAT 1");

        rat2 = new RatValueset();
        rat2.setActive(true);
        rat2.setVersion(ZonedDateTime.now().minus(6, ChronoUnit.DAYS));
        rat2.setDisplay("RAT 2");

        valueset = new Valueset<>(
            RAT_VALUESET_ID,
            LocalDate.now().minus(1, ChronoUnit.DAYS),
            Map.of(
                RAT1_ID, rat1,
                RAT2_ID, rat2
            )
        );

        valuesetEntity = new ValuesetEntity(
            RAT_VALUESET_ID,
            objectMapper.writeValueAsString(valueset)
        );
        valuesetEntity = valuesetRepository.save(valuesetEntity);
    }

    @Test
    void testRatValuesetUpdateActiveFalse() throws JsonProcessingException {
        JrcRatValueset.Manufacturer manufacturer = new JrcRatValueset.Manufacturer();
        manufacturer.setId("1111");
        manufacturer.setCountry("eu");
        manufacturer.setName("Manufacturer Name");
        manufacturer.setWebsite("https://example.org");

        JrcRatValueset.HscListHistory history1 = new JrcRatValueset.HscListHistory();
        history1.setInCommonList(true);
        history1.setInMutualRecognition(true);
        history1.setListDate(ZonedDateTime.now().minus(3, ChronoUnit.DAYS));

        JrcRatValueset.HscListHistory history2 = new JrcRatValueset.HscListHistory();
        history2.setInCommonList(false);
        history2.setInMutualRecognition(true);
        history2.setListDate(ZonedDateTime.now().minus(1, ChronoUnit.DAYS));

        JrcRatValueset jrcValueset = new JrcRatValueset();
        jrcValueset.setIdDevice(RAT1_ID);
        jrcValueset.setCommercialName("New Com Name");
        jrcValueset.setManufacturer(manufacturer);
        jrcValueset.setHscListHistory(List.of(history1, history2));

        JrcRatValuesetResponse jrcResponse = new JrcRatValuesetResponse();
        jrcResponse.setExtractedOn(ZonedDateTime.now());
        jrcResponse.setDeviceList(List.of(jrcValueset));

        when(jrcClientMock.downloadRatValues()).thenReturn(jrcResponse);

        ratValuesetUpdateService.update();

        String updatedValuesetJson = valuesetService.getValueSetById(RAT_VALUESET_ID).orElseThrow();
        Valueset<String, RatValueset> updatedValueset = objectMapper.readValue(updatedValuesetJson, typeReference);

        Assertions.assertEquals(LocalDate.now(), updatedValueset.getDate(), "Valueset Date was not updated.");
        Assertions.assertEquals(2, updatedValueset.getValue().size(), "Valueset List size has been changed");
        Assertions.assertFalse(updatedValueset.getValue().get(RAT1_ID).getActive());
        Assertions.assertEquals(String.format("%s, %s", manufacturer.getName(), jrcValueset.getCommercialName()), updatedValueset.getValue().get(RAT1_ID).getDisplay());
        Assertions.assertEquals(history2.getListDate().toEpochSecond(), updatedValueset.getValue().get(RAT1_ID).getVersion().toEpochSecond());
    }

    @Test
    void testRatValuesetUpdateActiveTrue() throws JsonProcessingException {
        JrcRatValueset.Manufacturer manufacturer = new JrcRatValueset.Manufacturer();
        manufacturer.setId("1111");
        manufacturer.setCountry("eu");
        manufacturer.setName("Manufacturer Name");
        manufacturer.setWebsite("https://example.org");

        JrcRatValueset.HscListHistory history1 = new JrcRatValueset.HscListHistory();
        history1.setInCommonList(false);
        history1.setInMutualRecognition(true);
        history1.setListDate(ZonedDateTime.now().minus(3, ChronoUnit.DAYS));

        JrcRatValueset.HscListHistory history2 = new JrcRatValueset.HscListHistory();
        history2.setInCommonList(true);
        history2.setInMutualRecognition(true);
        history2.setListDate(ZonedDateTime.now().minus(1, ChronoUnit.DAYS));

        JrcRatValueset jrcValueset = new JrcRatValueset();
        jrcValueset.setIdDevice(RAT1_ID);
        jrcValueset.setCommercialName("New Com Name");
        jrcValueset.setManufacturer(manufacturer);
        jrcValueset.setHscListHistory(List.of(history1, history2));

        JrcRatValuesetResponse jrcResponse = new JrcRatValuesetResponse();
        jrcResponse.setExtractedOn(ZonedDateTime.now());
        jrcResponse.setDeviceList(List.of(jrcValueset));

        when(jrcClientMock.downloadRatValues()).thenReturn(jrcResponse);

        ratValuesetUpdateService.update();

        String updatedValuesetJson = valuesetService.getValueSetById(RAT_VALUESET_ID).orElseThrow();
        Valueset<String, RatValueset> updatedValueset = objectMapper.readValue(updatedValuesetJson, typeReference);

        Assertions.assertEquals(LocalDate.now(), updatedValueset.getDate(), "Valueset Date was not updated.");
        Assertions.assertEquals(2, updatedValueset.getValue().size(), "Valueset List size has been changed");
        Assertions.assertTrue(updatedValueset.getValue().get(RAT1_ID).getActive());
        Assertions.assertEquals(String.format("%s, %s", manufacturer.getName(), jrcValueset.getCommercialName()), updatedValueset.getValue().get(RAT1_ID).getDisplay());
        Assertions.assertEquals(history2.getListDate().toEpochSecond(), updatedValueset.getValue().get(RAT1_ID).getVersion().toEpochSecond());
    }

    @Test
    void testRatValuesetInsertedIfNotExist() throws JsonProcessingException {
        valuesetRepository.deleteAll();

        JrcRatValueset.Manufacturer manufacturer = new JrcRatValueset.Manufacturer();
        manufacturer.setId("1111");
        manufacturer.setCountry("eu");
        manufacturer.setName("Manufacturer Name");
        manufacturer.setWebsite("https://example.org");

        JrcRatValueset.HscListHistory history1 = new JrcRatValueset.HscListHistory();
        history1.setInCommonList(false);
        history1.setInMutualRecognition(true);
        history1.setListDate(ZonedDateTime.now().minus(3, ChronoUnit.DAYS));

        JrcRatValueset.HscListHistory history2 = new JrcRatValueset.HscListHistory();
        history2.setInCommonList(true);
        history2.setInMutualRecognition(true);
        history2.setListDate(ZonedDateTime.now().minus(1, ChronoUnit.DAYS));

        JrcRatValueset jrcValueset = new JrcRatValueset();
        jrcValueset.setIdDevice(RAT1_ID);
        jrcValueset.setCommercialName("New Com Name");
        jrcValueset.setManufacturer(manufacturer);
        jrcValueset.setHscListHistory(List.of(history1, history2));

        JrcRatValuesetResponse jrcResponse = new JrcRatValuesetResponse();
        jrcResponse.setExtractedOn(ZonedDateTime.now());
        jrcResponse.setDeviceList(List.of(jrcValueset));

        when(jrcClientMock.downloadRatValues()).thenReturn(jrcResponse);

        ratValuesetUpdateService.update();

        String updatedValuesetJson = valuesetService.getValueSetById(RAT_VALUESET_ID).orElseThrow();
        Valueset<String, RatValueset> updatedValueset = objectMapper.readValue(updatedValuesetJson, typeReference);

        Assertions.assertEquals(LocalDate.now(), updatedValueset.getDate(), "Valueset Date was not updated.");
        Assertions.assertEquals(1, updatedValueset.getValue().size(), "Valueset List size has been changed");
        Assertions.assertTrue(updatedValueset.getValue().get(RAT1_ID).getActive());
        Assertions.assertEquals(String.format("%s, %s", manufacturer.getName(), jrcValueset.getCommercialName()), updatedValueset.getValue().get(RAT1_ID).getDisplay());
        Assertions.assertEquals(history2.getListDate().toEpochSecond(), updatedValueset.getValue().get(RAT1_ID).getVersion().toEpochSecond());
    }

    @Test
    void testRatValuesetUpdatedIfJsonInDbIsInvalid() throws JsonProcessingException {
        valuesetEntity.setJson("blablabla");
        valuesetRepository.save(valuesetEntity);

        JrcRatValueset.Manufacturer manufacturer = new JrcRatValueset.Manufacturer();
        manufacturer.setId("1111");
        manufacturer.setCountry("eu");
        manufacturer.setName("Manufacturer Name");
        manufacturer.setWebsite("https://example.org");

        JrcRatValueset.HscListHistory history1 = new JrcRatValueset.HscListHistory();
        history1.setInCommonList(false);
        history1.setInMutualRecognition(true);
        history1.setListDate(ZonedDateTime.now().minus(3, ChronoUnit.DAYS));

        JrcRatValueset.HscListHistory history2 = new JrcRatValueset.HscListHistory();
        history2.setInCommonList(true);
        history2.setInMutualRecognition(true);
        history2.setListDate(ZonedDateTime.now().minus(1, ChronoUnit.DAYS));

        JrcRatValueset jrcValueset = new JrcRatValueset();
        jrcValueset.setIdDevice(RAT1_ID);
        jrcValueset.setCommercialName("New Com Name");
        jrcValueset.setManufacturer(manufacturer);
        jrcValueset.setHscListHistory(List.of(history1, history2));

        JrcRatValuesetResponse jrcResponse = new JrcRatValuesetResponse();
        jrcResponse.setExtractedOn(ZonedDateTime.now());
        jrcResponse.setDeviceList(List.of(jrcValueset));

        when(jrcClientMock.downloadRatValues()).thenReturn(jrcResponse);

        ratValuesetUpdateService.update();

        String updatedValuesetJson = valuesetService.getValueSetById(RAT_VALUESET_ID).orElseThrow();
        Valueset<String, RatValueset> updatedValueset = objectMapper.readValue(updatedValuesetJson, typeReference);

        Assertions.assertEquals(LocalDate.now(), updatedValueset.getDate(), "Valueset Date was not set.");
        Assertions.assertEquals(1, updatedValueset.getValue().size());
        Assertions.assertTrue(updatedValueset.getValue().get(RAT1_ID).getActive());
        Assertions.assertEquals(String.format("%s, %s", manufacturer.getName(), jrcValueset.getCommercialName()), updatedValueset.getValue().get(RAT1_ID).getDisplay());
        Assertions.assertEquals(history2.getListDate().toEpochSecond(), updatedValueset.getValue().get(RAT1_ID).getVersion().toEpochSecond());
    }

    @Test
    void testRatValuesetUpdatedSkipIfHistoryEmpty() throws JsonProcessingException {
        JrcRatValueset.Manufacturer manufacturer = new JrcRatValueset.Manufacturer();
        manufacturer.setId("1111");
        manufacturer.setCountry("eu");
        manufacturer.setName("Manufacturer Name");
        manufacturer.setWebsite("https://example.org");

        JrcRatValueset jrcValueset = new JrcRatValueset();
        jrcValueset.setIdDevice(RAT1_ID);
        jrcValueset.setCommercialName("New Com Name");
        jrcValueset.setManufacturer(manufacturer);
        jrcValueset.setHscListHistory(Collections.emptyList());

        JrcRatValuesetResponse jrcResponse = new JrcRatValuesetResponse();
        jrcResponse.setExtractedOn(ZonedDateTime.now());
        jrcResponse.setDeviceList(List.of(jrcValueset));

        when(jrcClientMock.downloadRatValues()).thenReturn(jrcResponse);

        ratValuesetUpdateService.update();

        String updatedValuesetJson = valuesetService.getValueSetById(RAT_VALUESET_ID).orElseThrow();
        Valueset<String, RatValueset> updatedValueset = objectMapper.readValue(updatedValuesetJson, typeReference);

        Assertions.assertEquals(LocalDate.now(), updatedValueset.getDate(), "Valueset Date was not set.");
        Assertions.assertEquals(2, updatedValueset.getValue().size());
        Assertions.assertTrue(updatedValueset.getValue().get(RAT1_ID).getActive());
        assertEquals(rat1, updatedValueset.getValue().get(RAT1_ID));
    }

    @Test
    void testRatValuesetUpdatedSkipIfHistoryNull() throws JsonProcessingException {
        JrcRatValueset.Manufacturer manufacturer = new JrcRatValueset.Manufacturer();
        manufacturer.setId("1111");
        manufacturer.setCountry("eu");
        manufacturer.setName("Manufacturer Name");
        manufacturer.setWebsite("https://example.org");

        JrcRatValueset jrcValueset = new JrcRatValueset();
        jrcValueset.setIdDevice(RAT1_ID);
        jrcValueset.setCommercialName("New Com Name");
        jrcValueset.setManufacturer(manufacturer);
        jrcValueset.setHscListHistory(null);

        JrcRatValuesetResponse jrcResponse = new JrcRatValuesetResponse();
        jrcResponse.setExtractedOn(ZonedDateTime.now());
        jrcResponse.setDeviceList(List.of(jrcValueset));

        when(jrcClientMock.downloadRatValues()).thenReturn(jrcResponse);

        ratValuesetUpdateService.update();

        String updatedValuesetJson = valuesetService.getValueSetById(RAT_VALUESET_ID).orElseThrow();
        Valueset<String, RatValueset> updatedValueset = objectMapper.readValue(updatedValuesetJson, typeReference);

        Assertions.assertEquals(LocalDate.now(), updatedValueset.getDate(), "Valueset Date was not set.");
        Assertions.assertEquals(2, updatedValueset.getValue().size());
        Assertions.assertTrue(updatedValueset.getValue().get(RAT1_ID).getActive());
        assertEquals(rat1, updatedValueset.getValue().get(RAT1_ID));
    }

    @Test
    void testRatValuesetUpdateShouldNotUpdateWhenRequestFails() throws JsonProcessingException {

        doThrow(new FeignException.Unauthorized("", dummyRequest, null))
            .when(jrcClientMock).downloadRatValues();

        ratValuesetUpdateService.update();

        String updatedValuesetJson = valuesetService.getValueSetById(RAT_VALUESET_ID).orElseThrow();
        Valueset<String, RatValueset> updatedValueset = objectMapper.readValue(updatedValuesetJson, typeReference);

        Assertions.assertEquals(LocalDate.now().minus(1, ChronoUnit.DAYS), updatedValueset.getDate(), "Valueset Date has been updated.");
        Assertions.assertEquals(2, updatedValueset.getValue().size(), "Valueset List size has been changed");
        assertEquals(rat1, updatedValueset.getValue().get(RAT1_ID));
        assertEquals(rat2, updatedValueset.getValue().get(RAT2_ID));
    }

    @Test
    void testRatValuesetUpdateLatestAllHistoryEntriesAreInFuture() throws JsonProcessingException {
        JrcRatValueset.Manufacturer manufacturer = new JrcRatValueset.Manufacturer();
        manufacturer.setId("1111");
        manufacturer.setCountry("eu");
        manufacturer.setName("Manufacturer Name");
        manufacturer.setWebsite("https://example.org");

        JrcRatValueset.HscListHistory history1 = new JrcRatValueset.HscListHistory();
        history1.setInCommonList(false);
        history1.setInMutualRecognition(true);
        history1.setListDate(ZonedDateTime.now().plus(3, ChronoUnit.DAYS));

        JrcRatValueset.HscListHistory history2 = new JrcRatValueset.HscListHistory();
        history2.setInCommonList(true);
        history2.setInMutualRecognition(true);
        history2.setListDate(ZonedDateTime.now().plus(1, ChronoUnit.DAYS));

        JrcRatValueset jrcValueset = new JrcRatValueset();
        jrcValueset.setIdDevice(RAT1_ID);
        jrcValueset.setCommercialName("New Com Name");
        jrcValueset.setManufacturer(manufacturer);
        jrcValueset.setHscListHistory(List.of(history1, history2));

        JrcRatValuesetResponse jrcResponse = new JrcRatValuesetResponse();
        jrcResponse.setExtractedOn(ZonedDateTime.now());
        jrcResponse.setDeviceList(List.of(jrcValueset));

        when(jrcClientMock.downloadRatValues()).thenReturn(jrcResponse);

        ratValuesetUpdateService.update();

        String updatedValuesetJson = valuesetService.getValueSetById(RAT_VALUESET_ID).orElseThrow();
        Valueset<String, RatValueset> updatedValueset = objectMapper.readValue(updatedValuesetJson, typeReference);

        Assertions.assertEquals(LocalDate.now(), updatedValueset.getDate(), "Valueset Date was not updated.");
        Assertions.assertEquals(2, updatedValueset.getValue().size(), "Valueset List size has been changed");
        Assertions.assertNull(updatedValueset.getValue().get(RAT1_ID).getActive());
        Assertions.assertEquals(String.format("%s, %s", manufacturer.getName(), jrcValueset.getCommercialName()), updatedValueset.getValue().get(RAT1_ID).getDisplay());
        Assertions.assertNull(updatedValueset.getValue().get(RAT1_ID).getVersion());
        assertEquals(history1.getListDate(), updatedValueset.getValue().get(RAT1_ID).getValidUntil());
    }

    @Test
    void testRatValuesetUpdateLatestHistoryEntryNotInFuture() throws JsonProcessingException {
        JrcRatValueset.Manufacturer manufacturer = new JrcRatValueset.Manufacturer();
        manufacturer.setId("1111");
        manufacturer.setCountry("eu");
        manufacturer.setName("Manufacturer Name");
        manufacturer.setWebsite("https://example.org");

        JrcRatValueset.HscListHistory history1 = new JrcRatValueset.HscListHistory();
        history1.setInCommonList(false);
        history1.setInMutualRecognition(true);
        history1.setListDate(ZonedDateTime.now().minus(3, ChronoUnit.DAYS));

        JrcRatValueset.HscListHistory history2 = new JrcRatValueset.HscListHistory();
        history2.setInCommonList(true);
        history2.setInMutualRecognition(true);
        history2.setListDate(ZonedDateTime.now().minus(1, ChronoUnit.DAYS));

        JrcRatValueset.HscListHistory history3 = new JrcRatValueset.HscListHistory();
        history3.setInCommonList(true);
        history3.setInMutualRecognition(true);
        history3.setListDate(ZonedDateTime.now().plus(1, ChronoUnit.DAYS));

        JrcRatValueset jrcValueset = new JrcRatValueset();
        jrcValueset.setIdDevice(RAT1_ID);
        jrcValueset.setCommercialName("New Com Name");
        jrcValueset.setManufacturer(manufacturer);
        jrcValueset.setHscListHistory(List.of(history1, history2, history3));

        JrcRatValuesetResponse jrcResponse = new JrcRatValuesetResponse();
        jrcResponse.setExtractedOn(ZonedDateTime.now());
        jrcResponse.setDeviceList(List.of(jrcValueset));

        when(jrcClientMock.downloadRatValues()).thenReturn(jrcResponse);

        ratValuesetUpdateService.update();

        String updatedValuesetJson = valuesetService.getValueSetById(RAT_VALUESET_ID).orElseThrow();
        Valueset<String, RatValueset> updatedValueset = objectMapper.readValue(updatedValuesetJson, typeReference);

        Assertions.assertEquals(LocalDate.now(), updatedValueset.getDate(), "Valueset Date was not updated.");
        Assertions.assertEquals(2, updatedValueset.getValue().size(), "Valueset List size has been changed");
        Assertions.assertEquals(history2.getInCommonList(), updatedValueset.getValue().get(RAT1_ID).getActive());
        Assertions.assertEquals(String.format("%s, %s", manufacturer.getName(), jrcValueset.getCommercialName()), updatedValueset.getValue().get(RAT1_ID).getDisplay());
        assertEquals(history2.getListDate(), updatedValueset.getValue().get(RAT1_ID).getVersion());
        assertEquals(history3.getListDate(), updatedValueset.getValue().get(RAT1_ID).getValidUntil());
    }

    void assertEquals(ZonedDateTime expected, ZonedDateTime given) {
        Assertions.assertEquals(expected.toEpochSecond(), given.toEpochSecond());
    }

    void assertEquals(RatValueset expected, RatValueset given) {
        Assertions.assertEquals(expected.getVersion().toEpochSecond(), given.getVersion().toEpochSecond());
        Assertions.assertEquals(expected.getActive(), given.getActive());
        Assertions.assertEquals(expected.getDisplay(), given.getDisplay());
        Assertions.assertEquals(expected.getLang(), given.getLang());
        Assertions.assertEquals(expected.getSystem(), given.getSystem());
    }
}
