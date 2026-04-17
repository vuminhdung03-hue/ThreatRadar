"""
CPE-aware technology matching service.

Improves on simple prefix matching by handling common NVD product name
synonyms (e.g. apache:httpd <-> apache:http_server) and normalising
version suffixes (e.g. windows_server_2019 -> windows_server).
"""

# Maps NVD product names to the canonical names used in environment profiles.
# Add entries here whenever a new mismatch is discovered.
SYNONYMS: dict[str, str] = {
    # Apache HTTP Server
    "httpd": "http_server",
    # Microsoft SQL Server (versioned NVD slugs → generic profile slug)
    "sql_server_2012": "sql_server",
    "sql_server_2014": "sql_server",
    "sql_server_2016": "sql_server",
    "sql_server_2017": "sql_server",
    "sql_server_2019": "sql_server",
    "sql_server_2022": "sql_server",
    # Microsoft Exchange
    "exchange_server": "exchange",
    "exchange_server_2010": "exchange",
    "exchange_server_2013": "exchange",
    "exchange_server_2016": "exchange",
    "exchange_server_2019": "exchange",
    # Oracle / Sun Java
    "jdk": "java",
    "jre": "java",
    "jrockit": "java",
    "graalvm": "java",
    # Node.js (NVD uses "nodejs" vendor with "node.js" product — covered by env match)
    "nodejs": "node.js",
    # Ubuntu (NVD uses ubuntu_linux)
    "ubuntu_linux": "ubuntu",
    # RHEL
    "enterprise_linux_server": "enterprise_linux",
    "enterprise_linux_workstation": "enterprise_linux",
    "enterprise_linux_desktop": "enterprise_linux",
    "enterprise_linux_eus": "enterprise_linux",
    "enterprise_linux_aus": "enterprise_linux",
    # Cisco networking devices
    "ios": "network",
    "ios_xe": "network",
    "ios_xr": "network",
    "nx-os": "network",
    "nx_os": "network",
    "catalyst_sd-wan_manager": "network",
    # Cisco security / firewall
    "adaptive_security_appliance_software": "firewall",
    "firepower_management_center": "firewall",
    "firepower_threat_defense": "firewall",
    "asa_software": "firewall",
    # Oracle Database
    "database_server": "database",
    # IBM WebSphere
    "websphere_application_server": "websphere",
    # VMware
    "vsphere_esxi": "vsphere",
    "vcenter_server": "vsphere",
    "esxi": "vsphere",
    # Microsoft Windows (generic)
    "windows_nt": "windows",
    "windows_10": "windows",
    "windows_11": "windows",
    # PostgreSQL
    "postgresql": "postgresql",  # identity — already matches
}


class CPEMatcher:
    """Stateless helper for matching environment tech strings against CPE entries."""

    @staticmethod
    def _normalize(product: str) -> str:
        """Return canonical product name via SYNONYMS, or the original."""
        return SYNONYMS.get(product, product)

    @classmethod
    def match_score(cls, env_tech: str, cpe_vendor: str, cpe_product: str) -> float:
        """
        Score how well (cpe_vendor, cpe_product) matches the env_tech string
        ("vendor:product"). Returns:
          1.0 — exact match
          0.9 — synonym match
          0.8 — prefix match (env "windows_server" vs CPE "windows_server_2019")
          0.0 — no match
        """
        env_vendor, _, env_product = env_tech.partition(":")
        if env_vendor != cpe_vendor:
            return 0.0

        if env_product == cpe_product:
            return 1.0

        # Prefix match: env "windows_server" matches CPE "windows_server_2019"
        if cpe_product.startswith(env_product + "_") or cpe_product.startswith(env_product + ":"):
            return 0.8

        # Synonym match
        norm_env = cls._normalize(env_product)
        norm_cpe = cls._normalize(cpe_product)
        if norm_env == cpe_product or norm_cpe == env_product or norm_env == norm_cpe:
            return 0.9

        return 0.0

    @classmethod
    def count_matches(
        cls,
        env_techs: list[str],
        cpe_data: list[dict],
    ) -> tuple[int, float]:
        """
        Return (match_count, total_score) for a list of env techs vs. CPE entries.

        Each env tech contributes its best match score across all CPE entries
        (so one env tech can only match once, but scores are continuous 0–1).
        """
        total_score = 0.0
        count = 0
        for et in env_techs:
            best = max(
                (
                    cls.match_score(et, c.get("vendor", ""), c.get("product", ""))
                    for c in cpe_data
                ),
                default=0.0,
            )
            if best > 0:
                count += 1
                total_score += best
        return count, total_score
