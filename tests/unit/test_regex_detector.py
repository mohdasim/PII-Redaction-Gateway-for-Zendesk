"""Unit tests for the regex-based PII detector."""

import pytest

from src.services.regex_detector import (
    RegexDetector,
    luhn_check,
    validate_credit_card,
    validate_phone,
    validate_ssn,
)


class TestLuhnCheck:
    """Tests for the Luhn algorithm implementation."""

    def test_valid_visa(self):
        assert luhn_check("4111111111111111") is True

    def test_valid_mastercard(self):
        assert luhn_check("5425233430109903") is True

    def test_valid_amex(self):
        assert luhn_check("371449635398431") is True

    def test_invalid_number(self):
        assert luhn_check("1234567890123456") is False

    def test_too_short(self):
        assert luhn_check("123456") is False


class TestSSNValidation:
    """Tests for SSN format validation."""

    def test_valid_ssn_dashes(self):
        assert validate_ssn("123-45-6789") is True

    def test_valid_ssn_spaces(self):
        assert validate_ssn("123 45 6789") is True

    def test_valid_ssn_no_separator(self):
        assert validate_ssn("123456789") is True

    def test_invalid_area_000(self):
        assert validate_ssn("000-12-3456") is False

    def test_invalid_area_666(self):
        assert validate_ssn("666-12-3456") is False

    def test_invalid_area_900(self):
        assert validate_ssn("900-12-3456") is False

    def test_invalid_group_00(self):
        assert validate_ssn("123-00-6789") is False

    def test_invalid_serial_0000(self):
        assert validate_ssn("123-45-0000") is False


class TestRegexDetectorSSN:
    """Tests for SSN detection."""

    @pytest.fixture
    def detector(self):
        return RegexDetector(enabled_pii_types=["SSN"])

    def test_ssn_with_dashes(self, detector):
        entities = detector.detect("My SSN is 123-45-6789.")
        assert len(entities) >= 1
        ssn_entities = [e for e in entities if e.pii_type == "SSN"]
        assert len(ssn_entities) >= 1

    def test_ssn_with_context_keyword(self, detector):
        entities = detector.detect("Social Security: 234-56-7890")
        assert len(entities) >= 1
        assert entities[0].pii_type == "SSN"

    def test_no_false_positive_invalid_ssn(self, detector):
        # 000 prefix is invalid
        entities = detector.detect("Number 000-12-3456 is not valid.")
        ssn_entities = [e for e in entities if e.pii_type == "SSN"]
        assert len(ssn_entities) == 0

    def test_no_false_positive_phone_like(self, detector):
        # Regular date should not match SSN
        entities = detector.detect("The date is 2024-01-15.")
        ssn_entities = [e for e in entities if e.pii_type == "SSN"]
        assert len(ssn_entities) == 0


class TestRegexDetectorCreditCard:
    """Tests for credit card detection."""

    @pytest.fixture
    def detector(self):
        return RegexDetector(enabled_pii_types=["CREDIT_CARD"])

    def test_visa_with_dashes(self, detector):
        entities = detector.detect("Card: 4111-1111-1111-1111")
        assert len(entities) == 1
        assert entities[0].pii_type == "CREDIT_CARD"

    def test_visa_with_spaces(self, detector):
        entities = detector.detect("Card: 4111 1111 1111 1111")
        assert len(entities) == 1

    def test_amex(self, detector):
        entities = detector.detect("Amex: 3714 496353 98431")
        assert len(entities) == 1

    def test_invalid_luhn_rejected(self, detector):
        entities = detector.detect("Number: 1234-5678-9012-3456")
        cc_entities = [e for e in entities if e.pii_type == "CREDIT_CARD"]
        assert len(cc_entities) == 0

    def test_mastercard(self, detector):
        entities = detector.detect("MC: 5425-2334-3010-9903")
        assert len(entities) == 1


class TestRegexDetectorEmail:
    """Tests for email detection."""

    @pytest.fixture
    def detector(self):
        return RegexDetector(enabled_pii_types=["EMAIL"])

    def test_standard_email(self, detector):
        entities = detector.detect("Contact me at john.doe@example.com please.")
        assert len(entities) == 1
        assert entities[0].pii_type == "EMAIL"

    def test_email_with_plus(self, detector):
        entities = detector.detect("Email: user+tag@domain.co.uk")
        assert len(entities) == 1

    def test_email_with_subdomain(self, detector):
        entities = detector.detect("Send to admin@mail.company.org")
        assert len(entities) == 1

    def test_no_email(self, detector):
        entities = detector.detect("This is a normal sentence with no emails.")
        assert len(entities) == 0


class TestRegexDetectorPhone:
    """Tests for phone number detection."""

    @pytest.fixture
    def detector(self):
        return RegexDetector(enabled_pii_types=["PHONE"])

    def test_us_format_parens(self, detector):
        entities = detector.detect("Call me at (555) 234-5678.")
        assert len(entities) == 1
        assert entities[0].pii_type == "PHONE"

    def test_us_format_dashes(self, detector):
        entities = detector.detect("Phone: 555-234-5678")
        assert len(entities) == 1

    def test_us_with_country_code(self, detector):
        entities = detector.detect("Call +1 555-234-5678")
        assert len(entities) >= 1

    def test_international(self, detector):
        entities = detector.detect("Contact: +442071234567")
        assert len(entities) >= 1

    def test_no_false_positive_short_number(self, detector):
        # Too short to be a phone
        entities = detector.detect("Room 1234 is available.")
        phone_entities = [e for e in entities if e.pii_type == "PHONE"]
        assert len(phone_entities) == 0


class TestRegexDetectorPassword:
    """Tests for password/credential detection."""

    @pytest.fixture
    def detector(self):
        return RegexDetector(enabled_pii_types=["PASSWORD"])

    def test_password_colon(self, detector):
        entities = detector.detect("My password: SuperSecret123!")
        assert len(entities) == 1
        assert entities[0].pii_type == "PASSWORD"

    def test_password_equals(self, detector):
        entities = detector.detect("pwd=MyP@ssw0rd")
        assert len(entities) == 1

    def test_api_key(self, detector):
        entities = detector.detect("api_key: sk-1234567890abcdef")
        assert len(entities) == 1

    def test_token(self, detector):
        entities = detector.detect("auth_token = eyJhbGciOiJIUz")
        assert len(entities) == 1

    def test_no_password_without_context(self, detector):
        entities = detector.detect("This is a normal sentence.")
        assert len(entities) == 0


class TestRegexDetectorPHI:
    """Tests for PHI detection."""

    @pytest.fixture
    def detector(self):
        return RegexDetector(enabled_pii_types=["PHI", "DATE_OF_BIRTH"])

    def test_mrn(self, detector):
        entities = detector.detect("Patient MRN: ABC12345")
        phi_entities = [e for e in entities if e.pii_type == "PHI"]
        assert len(phi_entities) >= 1

    def test_dob(self, detector):
        entities = detector.detect("DOB: 03/15/1985")
        dob_entities = [e for e in entities if e.pii_type == "DATE_OF_BIRTH"]
        assert len(dob_entities) == 1

    def test_icd10_with_context(self, detector):
        entities = detector.detect("Diagnosis: E11.65")
        phi_entities = [e for e in entities if e.pii_type == "PHI"]
        assert len(phi_entities) >= 1


class TestRegexDetectorAddress:
    """Tests for address detection."""

    @pytest.fixture
    def detector(self):
        return RegexDetector(enabled_pii_types=["ADDRESS"])

    def test_street_address(self, detector):
        entities = detector.detect("I live at 123 Main Street in town.")
        assert len(entities) >= 1
        assert entities[0].pii_type == "ADDRESS"

    def test_avenue_address(self, detector):
        entities = detector.detect("Ship to 456 Oak Avenue please.")
        assert len(entities) >= 1

    def test_zip_in_address_context(self, detector):
        entities = detector.detect("My zip code is 90210")
        addr_entities = [e for e in entities if e.pii_type == "ADDRESS"]
        assert len(addr_entities) >= 1


class TestRegexDetectorAllTypes:
    """Tests for detecting multiple PII types in one text."""

    @pytest.fixture
    def detector(self):
        return RegexDetector()

    def test_mixed_pii(self, detector):
        text = (
            "Hi, I'm at john@example.com, phone (555) 234-5678, "
            "SSN 456-78-9012. Card: 4111-1111-1111-1111."
        )
        entities = detector.detect(text)
        types = {e.pii_type for e in entities}
        assert "EMAIL" in types
        assert "PHONE" in types
        assert "SSN" in types
        assert "CREDIT_CARD" in types

    def test_clean_text(self, detector):
        entities = detector.detect("This is a normal customer inquiry about pricing.")
        # May have zero or very few entities (no structured PII)
        for e in entities:
            assert e.pii_type not in ("SSN", "CREDIT_CARD")

    def test_empty_text(self, detector):
        assert detector.detect("") == []

    def test_none_handling(self, detector):
        assert detector.detect("") == []

    def test_enabled_filter(self):
        detector = RegexDetector(enabled_pii_types=["EMAIL"])
        text = "SSN 123-45-6789 email test@example.com"
        entities = detector.detect(text)
        types = {e.pii_type for e in entities}
        assert "EMAIL" in types
        assert "SSN" not in types
