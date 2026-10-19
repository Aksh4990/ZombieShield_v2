from app.services.discovery.code_routes import routes_from_files
from app.services.discovery.logs import parse_line, parse_lines
from app.services.discovery.openapi import SpecError, parse_spec

import pytest


def routes(files):
    return {(r.method, r.path) for r in routes_from_files(files)}


def test_openapi3_and_swagger2_with_deprecation_and_security():
    oas = parse_spec("openapi: 3.0.0\ninfo: {title: t, version: '2'}\nservers: [{url: 'https://api.test/base'}]\nsecurity: [{bearer: []}]\n"
                     "paths:\n  /a:\n    get: {deprecated: true}\n    post: {security: []}\n")
    ops = {(o.method, o.path): o for o in oas.operations}
    assert oas.host == "api.test" and set(ops) == {("GET", "/base/a"), ("POST", "/base/a")}
    assert ops[("GET", "/base/a")].deprecated and ops[("GET", "/base/a")].security == ["bearer"]
    assert ops[("POST", "/base/a")].security == [] and ops[("POST", "/base/a")].security_declared
    swagger = parse_spec('{"swagger": "2.0", "info": {"title": "s"}, "basePath": "/api", "paths": {"/x/{id}": {"delete": {}}}}')
    assert swagger.format == "swagger2" and [(o.method, o.path) for o in swagger.operations] == [("DELETE", "/api/x/{id}")]
    with pytest.raises(SpecError):
        parse_spec("not: [valid")


def test_python_routes_with_router_prefixes_and_comments():
    code = ('router = APIRouter(prefix="/v2")\n@router.get("/items/{id}")\ndef a(): ...\n'
            '# @router.get("/commented-out")\n@app.api_route("/both", methods=["GET", "POST"])\ndef b(): ...\n'
            'bp = Blueprint("x", __name__, url_prefix="/legacy")\n@bp.route("/old/<int:id>", methods=["PUT"])\ndef c(): ...\n')
    assert routes({"svc/app.py": code}) == {("GET", "/v2/items/{id}"), ("GET", "/both"), ("POST", "/both"), ("PUT", "/legacy/old/<int:id>")}


def test_express_mounts_across_files(tmp_path):
    (tmp_path / "routes").mkdir()
    main, stock = tmp_path / "index.js", tmp_path / "routes" / "stock.js"
    main.write_text("const app = express();\nconst stock = require('./routes/stock');\napp.use('/inventory/v1', stock);\napp.get('/health', h);\n")
    stock.write_text("const router = express.Router();\nrouter.get('/stock/:sku', h);\nrouter.route('/stock').get(a).post(b);\n/* router.get('/old', h) */\n")
    found = routes({str(main): main.read_text(), str(stock): stock.read_text()})
    assert found == {("GET", "/health"), ("GET", "/inventory/v1/stock/:sku"), ("GET", "/inventory/v1/stock"), ("POST", "/inventory/v1/stock")}


def test_spring_and_go_routes():
    java = ('@RestController\n@RequestMapping("/carts")\npublic class C {\n  @GetMapping("/{id}")\n  void a() {}\n'
            '  @RequestMapping(value = "/{id}/items", method = RequestMethod.POST)\n  void b() {}\n}\n')
    go = ('r.Methods("GET").Path("/catalogue/{id}").Handler(h)\nr.Methods("GET").PathPrefix("/customers").Handler(h)\n'
          'api := r.PathPrefix("/api").Subrouter()\napi.HandleFunc("/tags", h).Methods("GET", "HEAD")\n'
          'g := e.Group("/v1")\ng.POST("/orders", h)\nmux.HandleFunc("DELETE /items/{id}", h)\n// r.HandleFunc("/dead", h)\n')
    assert routes({"C.java": java}) == {("GET", "/carts/{id}"), ("POST", "/carts/{id}/items")}
    assert routes({"main.go": go}) == {("GET", "/catalogue/{id}"), ("GET", "/customers*"), ("GET", "/api/tags"), ("HEAD", "/api/tags"),
                                       ("POST", "/v1/orders"), ("DELETE", "/items/{id}")}


def test_log_formats():
    gateway = parse_line('{"ts":"2026-01-01T10:00:00+00:00","client":"10.0.0.1","method":"GET","uri":"/a/1?q=x","status":200,"latency":0.012,"auth":"0"}')
    assert (gateway.path, gateway.query, gateway.status, gateway.authenticated, round(gateway.latency_ms)) == ("/a/1", "q=x", 200, False, 12)
    combined = parse_line('10.0.0.2 - - [10/Oct/2026:13:55:36 +0000] "POST /login HTTP/1.1" 401 12 "-" "curl/8"')
    assert (combined.method, combined.path, combined.status, combined.client) == ("POST", "/login", 401, "10.0.0.2")
    simple = parse_line("2026-01-01T00:00:00Z GET /health 200")
    assert simple.method == "GET" and simple.ts.year == 2026
    records, skipped = parse_lines("garbage line\nGET /ok 200\n")
    assert len(records) == 1 and skipped == 1
