
# Minimal FQDN test data for unit tests
resource "aviatrix_fqdn" "test_enabled" {
    fqdn_mode = "white"
    fqdn_enabled = true
    gw_filter_tag_list {
        gw_name = "test-gateway"
    }
    fqdn_tag = "test-enabled-tag"
    manage_domain_names = false
}

resource "aviatrix_fqdn" "test_disabled" {
    fqdn_mode = "white"
    fqdn_enabled = false
    fqdn_tag = "test-disabled-tag"
    manage_domain_names = false
}

resource "aviatrix_fqdn" "test_webgroup" {
    fqdn_mode = "white"
    fqdn_enabled = true
    fqdn_tag = "test-webgroup-tag"
    manage_domain_names = false
}
