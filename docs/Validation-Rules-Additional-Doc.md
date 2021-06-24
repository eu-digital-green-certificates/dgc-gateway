### Validation Rules

The ValidationRules API contains some complex logic. This documents helps to understand it.

## Validation Rules Download

The download is executed per Country (2 Digit Country Code)
You will get a Map with Rule Identifier as Key and a List of ValidationRules with this Identifier and different versions
as Value.

If the last uploaded Validation Rule's ValidFrom property is already in the past, the list will only contain this rule.
If the last uploaded Validation Rule's ValidFrom property is in the future, all versions of this ValidationRule which
will are currently valid or will be valid in future will be in the list.

**Example**:\
The Database Contains 5 Rules with Identifier IR-EU-0001 with the following ValidFrom Values:

1. 21.06.2021 12:00:00
2. 21.06.2021 14:00:00
3. 23.06.2021 18:00:00
4. 24.06.2021 09:00:00
5. 25.06.2021 10:00:00

Current Timestamp is 18.06.2021 22:00:00\
GET /rules/EU --> List with Rules 1, 2, 3, 4 and 5

Current Timestamp is 23.06.2021 22:00:00\
GET /rules/EU --> List with Rules 3, 4 and 5

Current Timestamp is 27.06.2021 22:00:00\
GET /rules/EU --> List only with Rule 5

## Validation Rules Validation

This documents describes the validation which will be executed when uploading a new Validation Rule to the gateway.

### Signing

The JSON file containing the ValidationRule has to be uploaded as a signed CMS. The signed CMS can be created with
the [SignedStringMessageBuilder](https://github.com/eu-digital-green-certificates/dgc-lib/blob/cdd10ea33df19e702828a2e7acc4cd563da1f6ea/src/main/java/eu/europa/ec/dgc/signing/SignedStringMessageBuilder.java)
of [dgc-lib](https://github.com/eu-digital-green-certificates/dgc-lib)
To sign the CMS a valid (onboarded) upload certificate must used.

### Syntax

The uploaded JSON file will be checked if it aligns to
the [JSON-Schema for ValidationRules](../src/main/resources/validation-rule.schema.json)

### Content Checks

In addition the content of the fields of the ValidationRule will be checked.

| Field | Concerns To | Validation | Possible Error Message |
| --- | --- | --- | --- |
| Identifier | Acceptance Rules | Identifier must start with GR, VR, TR or RR | 400, Invalid RuleID |
| Identifier | Invalidation Rules | Identifier must start with IR | 400, Invalid RuleID |
| Identifier | All | Country in Identifier must be equal to Country of your authentication certificate | 403, Invalid Country sent |
| Country | All | Must be equal to Country of your authentication certificate | 403, Invalid Country sent |
| Version | Rules with previous version | Version of uploaded Rule must be higher than version of the last uploaded rule | 400, Invalid Version | 
| ValidFrom | All | Value of ValidFrom must be before value of ValidTo | 400, Invalid Timestamp(s) |  
| ValidFrom | All | Value of ValidFrom must be within 2 weeks from today | 400, Invalid Timestamp(s) |  
| ValidFrom | Acceptance Rules | Value of ValidFrom must be at least 48h in future from today | 400, Invalid Timestamp(s) |  
| ValidFrom | Invalidation Rules | Value of ValidFrom must be in future from today | 400, Invalid Timestamp(s) |
| ValidFrom | Rules with previous version | Value of ValidFrom must be after or equal to ValidFrom from ValidationRule of previous version | 400, Invalid Timestamp(s) |
| ValidTo | All | Value of ValidTo must be after value of ValidFrom | 400, Invalid Timestamp(s) |
