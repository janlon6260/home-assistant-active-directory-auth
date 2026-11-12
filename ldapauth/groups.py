from ldap3.core.exceptions import LDAPInvalidDnError
from ldap3.utils.dn import escape_rdn, parse_dn


def normalize_dn(value: str) -> str:
    return "".join(
        f"{attribute.casefold()}={component.casefold()}{separator}"
        for attribute, component, separator in parse_dn(value.strip(), strip=True)
    )


def resolve_group_dn(group: str, base: str) -> str:
    value = group.strip()
    if not value:
        raise ValueError("A group name or full distinguished name is required")
    try:
        components = parse_dn(value, strip=True)
    except LDAPInvalidDnError:
        components = []
    if len(components) > 1 and components[0][0].casefold() == "cn":
        return normalize_dn(value)
    if not base.strip():
        raise ValueError("groups_base_dn is required when a group is specified by CN")
    return normalize_dn(f"CN={escape_rdn(value)},{base.strip()}")
