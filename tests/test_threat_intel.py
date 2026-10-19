import json

from app.services.threat_intel.cvss import base_score, severity_from_score
from app.services.threat_intel.sbom import scan_directory
from app.services.threat_intel.versions import compare, is_affected


def test_cvss_calculator_matches_reference_scores():
    assert base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8
    assert base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N") == 6.1
    assert base_score("CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:L") == 1.8
    assert severity_from_score(7.5) == "HIGH" and base_score("not a vector") is None


def test_version_ranges():
    affected = {"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.1.3"}]}]}
    assert is_affected("PyPI", "3.1.2", affected) and not is_affected("PyPI", "3.1.3", affected)
    semver = {"ranges": [{"type": "SEMVER", "events": [{"introduced": "4.0.0"}, {"last_affected": "4.17.20"}]}]}
    assert is_affected("npm", "4.17.15", semver) and not is_affected("npm", "4.17.21", semver) and not is_affected("npm", "3.9.0", semver)
    assert is_affected("Go", "v1.2.0", {"versions": ["v1.2.0"]})
    assert compare("Maven", "1.1.0.RELEASE", "1.10.0") < 0 and compare("npm", "1.0.0-beta", "1.0.0") < 0


def test_manifest_scanning(tmp_path):
    (tmp_path / "requirements.txt").write_text("Jinja2==3.1.2\nrequests>=2  # unpinned, skipped\n")
    (tmp_path / "web").mkdir()
    (tmp_path / "web" / "package.json").write_text(json.dumps({"dependencies": {"express": "^4.17.1", "local": "file:../x"}}))
    (tmp_path / "go.mod").write_text("module x\n\nrequire (\n\tgithub.com/gorilla/mux v1.8.0\n\tgolang.org/x/net v0.1.0 // indirect\n)\n")
    (tmp_path / "pom.xml").write_text('<project xmlns="http://maven.apache.org/POM/4.0.0"><properties><spring.version>5.3.1</spring.version></properties>'
                                      '<dependencies><dependency><groupId>org.springframework</groupId><artifactId>spring-web</artifactId>'
                                      '<version>${spring.version}</version></dependency></dependencies></project>')
    found = {(d.ecosystem, d.name, d.version) for d in scan_directory(tmp_path)}
    assert found == {("PyPI", "jinja2", "3.1.2"), ("npm", "express", "4.17.1"), ("Go", "github.com/gorilla/mux", "v1.8.0"),
                     ("Go", "golang.org/x/net", "v0.1.0"), ("Maven", "org.springframework:spring-web", "5.3.1")}
