from app.services.normalization import canonical_key, display_path, normalize_path, resource_key, template_runtime_path, version_from_path


def test_every_parameter_syntax_maps_to_one_template():
    for path in ("/users/{userId}", "/users/:id", "/users/<int:user_id>", "/users/{id:[0-9]+}", "/users/{id}/"):
        assert normalize_path(path) == "/users/{id}"
    assert display_path("/users/:userId") == "/users/{userId}"
    assert display_path("/carts/{customerId:.*}") == "/carts/{customerId}"


def test_version_and_resource_keys():
    assert version_from_path("/inventory/v2/stock/{sku}") == "v2"
    assert version_from_path("/stock") == "unversioned"
    assert resource_key("/v1/customers/{id}") == resource_key("/v2/customers/{cid}") == "/customers/{id}"
    assert canonical_key("Org", "API.example", "get", "/a/") == canonical_key("org", "api.example", "GET", "/a")


def test_runtime_paths_match_known_templates_then_heuristics():
    template, raw = template_runtime_path("/customers/alice", ["/customers/{id}"])
    assert (template, raw) == ("/customers/{id}", "alice")
    assert template_runtime_path("/orders/123")[0] == "/orders/{id}"
    assert template_runtime_path("/items/3395a43e-2d88-40de-b95f-e00e1502085b")[0] == "/items/{id}"
    assert template_runtime_path("/catalogue/size")[0] == "/catalogue/size"
    assert template_runtime_path("/customers/57a98d98e4b0", ["/customers*"])[0] == "/customers*"
