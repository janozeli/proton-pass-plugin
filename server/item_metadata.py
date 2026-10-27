"""Project CLI item data to metadata and references, never field values."""
from collections import Counter


def reference_fields(item, valid_reference):
    content = item["content"]
    names = [key for key in ("title", "note") if content.get(key)]
    names += [field.get("name", "") for field in content.get("extra_fields", [])]
    variants = content.get("content")
    if isinstance(variants, dict):
        kind, value = next(iter(variants.items()))
        # Names follow Pass CLI 2.5.1's Item::fields, not the JSON property
        # names in arbitrary objects. In particular URLs are plural and a
        # TOTP reference resolves to a code, not to the stored seed.
        fields = {
            "Login": ("username", "email", "password", "urls"),
            "SshKey": ("private_key", "public_key"),
            "Wifi": ("ssid", "password"),
            "CreditCard": ("cardholder_name", "number", "verification_number", "expiration_date", "pin"),
        }.get(kind, ())
        names += [key for key in fields if value.get(key)]
        if kind == "Login" and value.get("totp_uri"):
            names.append("totp")
        if kind in ("Custom", "SshKey", "Wifi", "Identity"):
            sections = value.get("extra_sections" if kind == "Identity" else "sections", [])
            for section in sections:
                names += [section.get("section_name", "") + "." + field.get("name", "")
                          for field in section.get("section_fields", [])]
        if kind == "Identity":
            for group in ("extra_personal_details", "extra_address_details", "extra_contact_details", "extra_work_details"):
                names += [field.get("name", "") for field in value.get(group, [])]
    # CLI chooses the first matching name. Do not emit a misleading reference
    # when custom and built-in names collide (including case differences).
    names = [name for name in names if isinstance(name, str) and name]
    counts = Counter(name.casefold() for name in names)
    refs, unavailable = {}, []
    for name in dict.fromkeys(names):
        ref = f"pass://{item['share_id']}/{item['id']}/{name}"
        if counts[name.casefold()] != 1 or not valid_reference(ref) or any(ord(c) < 32 for c in name):
            unavailable.append(name)
        else:
            refs[name] = ref
    return refs, unavailable
