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

package eu.europa.ec.dgc.gateway.entity;

import java.time.ZonedDateTime;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.EnumType;
import javax.persistence.Enumerated;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;
import javax.persistence.UniqueConstraint;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Entity
@Table(name = "validation_rule", uniqueConstraints = {@UniqueConstraint(columnNames = {"rule_id", "version"})})
public class ValidationRuleEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    private Long id;

    /**
     * Timestamp of the Record.
     */
    @Column(name = "created_at", nullable = false)
    private ZonedDateTime createdAt = ZonedDateTime.now();

    /**
     * Identifier of the Rule.
     * Needs to be a non ID column because Rule ID is not unique.
     */
    @Column(name = "rule_id", nullable = false, length = 100)
    private String ruleId;

    /**
     * CMS containing the whole JSON validation rule.
     */
    @Column(name = "signature", nullable = false, length = 10000)
    private String cms;

    /**
     * Date from when a rule is valid.
     */
    @Column(name = "validFrom", nullable = false)
    private ZonedDateTime validFrom;

    /**
     * Date until a rule is valid.
     */
    @Column(name = "validTo", nullable = false)
    private ZonedDateTime validTo;

    /**
     * Version of the rule.
     */
    @Column(name = "version", nullable = false, length = 30)
    private String version;

    /**
     * 2-Digit Country Code of origin of the rule.
     */
    @Column(name = "country", nullable = false, length = 2)
    private String country;

    /**
     * Type of the certificate (Authentication, Upload, CSCA).
     */
    @Column(name = "type", nullable = false)
    @Enumerated(EnumType.STRING)
    ValidationRuleType validationRuleType;

    public enum ValidationRuleType {
        /**
         * Rule is used to validate a certificate.
         */
        ACCEPTANCE,

        /**
         * Rule is used to invalidate a certificate.
         */
        INVALIDATION
    }
}
