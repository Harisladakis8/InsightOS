import phonenumbers
from phonenumbers import geocoder, carrier, timezone

def track_phone(phone: str):
    try:
        parsed = phonenumbers.parse(phone, None)
        return {
            "valid": phonenumbers.is_valid_number(parsed),
            "carrier": carrier.name_for_number(parsed, "en"),
            "location": geocoder.description_for_number(parsed, "en"),
            "timezone": timezone.time_zones_for_number(parsed),
            "international": phonenumbers.format_number(
                parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL
            )
        }
    except Exception as e:
        return {"error": str(e)}
