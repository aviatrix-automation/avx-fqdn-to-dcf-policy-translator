
# Webgroup rules (HTTP/HTTPS on 80/443)
resource "aviatrix_fqdn_tag_rule" "webgroup_rule_1" {
    fqdn_tag_name = "test-webgroup-tag"
    fqdn = "*.github.com"
    protocol = "tcp"
    port = "443"
}

resource "aviatrix_fqdn_tag_rule" "webgroup_rule_2" {
    fqdn_tag_name = "test-webgroup-tag"
    fqdn = "api.example.com"
    protocol = "http"
    port = "80"
}

# Hostname rules (non-standard ports/protocols)
resource "aviatrix_fqdn_tag_rule" "hostname_rule_1" {
    fqdn_tag_name = "test-enabled-tag"
    fqdn = "custom.internal.com"
    protocol = "tcp"
    port = "8080"
}

resource "aviatrix_fqdn_tag_rule" "hostname_rule_2" {
    fqdn_tag_name = "test-enabled-tag"
    fqdn = "*.monitoring.local"
    protocol = "all"
    port = ""
}

# DCF compatibility edge cases
resource "aviatrix_fqdn_tag_rule" "valid_wildcard" {
    fqdn_tag_name = "test-enabled-tag"
    fqdn = "*"
    protocol = "tcp"
    port = "443"
}

resource "aviatrix_fqdn_tag_rule" "invalid_wildcard" {
    fqdn_tag_name = "test-disabled-tag"
    fqdn = "*invalid-pattern"
    protocol = "tcp"
    port = "443"
}

# Rules for disabled FQDN tag (should be filtered out)
resource "aviatrix_fqdn_tag_rule" "disabled_rule" {
    fqdn_tag_name = "test-disabled-tag"
    fqdn = "should.be.filtered.com"
    protocol = "tcp"
    port = "443"
}
