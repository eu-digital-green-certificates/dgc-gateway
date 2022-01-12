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

package eu.europa.ec.dgc.gateway.repository;

import eu.europa.ec.dgc.gateway.entity.SignerInformationEntity;
import java.util.List;
import java.util.Optional;
import javax.transaction.Transactional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SignerInformationRepository extends JpaRepository<SignerInformationEntity, Long> {

    Optional<SignerInformationEntity> getFirstByThumbprint(String thumbprint);

    Optional<SignerInformationEntity> getFirstByThumbprintStartsWith(String thumbprintStart);

    @Transactional
    void deleteByThumbprint(String thumbprint);

    List<SignerInformationEntity> getByCertificateType(SignerInformationEntity.CertificateType type);

    List<SignerInformationEntity> getByCertificateTypeAndCountry(
        SignerInformationEntity.CertificateType type, String countryCode);

}
