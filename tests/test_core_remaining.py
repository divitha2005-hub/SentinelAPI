import asyncio
import json

import httpx
import pytest

from sentinelapi.classifier import check_schema, violates
from sentinelapi.cli import main
from sentinelapi.engine import Fuzzer
from sentinelapi.spec import Endpoint, parse_endpoints


@pytest.mark.parametrize('status', [200, 204, 302, 400, 401, 403, 404, 422, 500])
def test_auth_requires_successful_independent_anonymous_response(status):
    requests = []
    def handler(request):
        requests.append(request)
        if request.headers.get('authorization'):
            return httpx.Response(200, json={})
        return httpx.Response(status, json={})
    fz = Fuzzer([Endpoint('GET', '/private', secured=True)],
        headers={'Authorization': 'Bearer secret', 'X-API-Key': 'secret', 'Cookie': 'session=secret'},
        transport=httpx.MockTransport(handler))
    findings = asyncio.run(fz.run())
    assert fz.baseline_status['GET /private'] == 200
    assert len(requests) == fz.requests == 2
    assert not any(key in requests[1].headers for key in ('authorization', 'x-api-key', 'cookie'))
    assert bool([f for f in findings if f.kind == 'AUTH_NOT_ENFORCED']) == (200 <= status < 300)


def test_declared_query_api_key_removed_and_optional_security_not_flagged():
    spec = {'security': [{'Key': []}], 'components': {'securitySchemes': {
        'Key': {'type': 'apiKey', 'in': 'query', 'name': 'key'}}},
        'paths': {'/private': {'get': {'parameters': [
            {'name': 'key', 'in': 'query', 'schema': {'type': 'string'}}]}},
            '/optional': {'get': {'security': [{'Key': []}, {}]}}}}
    eps = parse_endpoints(spec)
    assert eps[0].auth_params == [('query', 'key')]
    assert not eps[1].secured
    requests = []
    def handler(request):
        requests.append(request)
        return httpx.Response(200 if 'key' in request.url.params else 401)
    fz = Fuzzer(eps[:1], transport=httpx.MockTransport(handler), max_requests=2)
    assert not asyncio.run(fz.run())
    assert 'key' not in requests[1].url.params


@pytest.mark.parametrize('budget', [0, 1, 2])
def test_anonymous_probe_respects_budget(budget):
    seen = []
    def handler(request):
        seen.append(request)
        return httpx.Response(200)
    fz = Fuzzer([Endpoint('GET', '/private', secured=True)],
        transport=httpx.MockTransport(handler), max_requests=budget)
    asyncio.run(fz.run())
    assert len(seen) == fz.requests == budget
    assert fz.client.is_closed


@pytest.mark.parametrize('schema,value', [
    ({'type': 'integer'}, 2), ({'type': 'number'}, 0.5),
    ({'type': 'boolean'}, False), ({'type': 'string'}, ''),
    ({'type': 'array', 'items': {'type': 'integer'}}, []),
    ({'type': 'string', 'nullable': True}, None),
])
def test_root_json_body_is_sent_without_object_wrapping(schema, value):
    seen = []
    def handler(request):
        seen.append(request)
        return httpx.Response(200, json={})
    ep = Endpoint('POST', '/body', body_schema=schema)
    fz = Fuzzer([ep], transport=httpx.MockTransport(handler))
    async def send():
        try:
            await fz._request(ep, {('body', None): value})
        finally:
            await fz.client.aclose()
    asyncio.run(send())
    assert json.loads(seen[0].content) == value
    assert seen[0].headers['content-type'] == 'application/json'


def test_root_array_baseline_and_fuzz_values():
    seen = []
    def handler(request):
        seen.append(json.loads(request.content))
        return httpx.Response(200, json={})
    ep = Endpoint('POST', '/body', body_schema={'type': 'array', 'minItems': 1,
        'items': {'type': 'integer'}})
    fz = Fuzzer([ep], transport=httpx.MockTransport(handler))
    findings = asyncio.run(fz.run())
    assert seen[0] == [1]
    assert [] in seen and 'scalar' in seen
    assert any(f.kind == 'VALIDATION_BYPASS' for f in findings)


@pytest.mark.parametrize('schema,bad,good', [
    ({'type': 'integer'}, True, 1),
    ({'type': 'string', 'nullable': True}, 1, None),
    ({'type': 'number', 'minimum': 1, 'maximum': 5}, 6, 3),
    ({'type': 'number', 'minimum': 1, 'exclusiveMinimum': True}, 1, 2),
    ({'type': 'number', 'exclusiveMaximum': 3}, 3, 2),
    ({'type': 'number', 'multipleOf': .1}, .25, .3),
    ({'type': 'string', 'minLength': 2, 'maxLength': 4}, 'a', 'abc'),
    ({'type': 'string', 'pattern': '^[a-z]+$'}, '123', 'abc'),
    ({'enum': ['a', 'b']}, 'c', 'a'),
    ({'type': 'array', 'minItems': 1, 'maxItems': 2}, [], [1]),
    ({'type': 'array', 'uniqueItems': True}, [1, 1], [1, 2]),
    ({'type': 'array', 'items': {'type': 'integer'}}, [1]*5+['bad'], [1]*6),
    ({'type': 'object', 'required': ['id']}, {}, {'id': 1}),
    ({'type': 'object', 'properties': {'id': {'type': 'integer'}}, 'additionalProperties': False}, {'extra': 1}, {'id': 1}),
    ({'type': 'object', 'additionalProperties': {'type': 'integer'}}, {'x': 'bad'}, {'x': 1}),
    ({'type': 'object', 'minProperties': 1, 'maxProperties': 2}, {}, {'x': 1}),
])
def test_contract_constraints(schema, bad, good):
    assert check_schema(schema, bad)
    assert violates(schema, bad)
    assert check_schema(schema, good) == []
    assert not violates(schema, good)


@pytest.mark.parametrize('config', ['[]', 'concurrency: true', 'rps: fast', 'header: abc',
    'authorized: yesplease', 'fail_on: wrong', 'typo: 1', 'top: -1', 'out: []', 'allow_host: [1]'])
def test_bad_configuration_has_actionable_error(tmp_path, capsys, config):
    path = tmp_path / 'config.yaml'
    path.write_text(config)
    try:
        result = main(['missing.json', '--config', str(path)])
    except SystemExit as error:
        result = error.code
    assert result == 2
    assert capsys.readouterr().err


@pytest.mark.parametrize('content', ['[', '[]', '{}', 'paths: []'])
def test_bad_spec_returns_error_without_traceback(tmp_path, capsys, content):
    path = tmp_path / 'spec.yaml'
    path.write_text(content)
    assert main([str(path), '--list']) == 2
    error = capsys.readouterr().err
    assert 'sentinelapi:' in error and 'Traceback' not in error


@pytest.mark.parametrize('args', [ ['--login-url', '/login', '--login-body', '[1]'],
    ['--login-url', '/login', '--login-body', '{'], ['--header', 'broken'],
    ['--asgi', 'invalid'], ['--login-body', '{}'] ])
def test_invalid_cli_input_returns_actionable_error(tmp_path, capsys, args):
    path = tmp_path / 'spec.json'
    path.write_text('{"paths": {}}')
    assert main([str(path), '--base-url', 'http://localhost', *args]) == 2
    assert capsys.readouterr().err


def test_cli_defaults_can_be_overridden_and_nested_reports_written(tmp_path):
    spec = tmp_path / 'spec.json'
    spec.write_text('{"paths": {}}')
    cfg = tmp_path / 'config.yaml'
    cfg.write_text('concurrency: 5\nmax_requests: 10\n')
    assert main([str(spec), '--config', str(cfg), '--max-requests', '0', '--asgi',
        'demo_api:app', '--out', str(tmp_path / 'nested' / 'out')]) == 0


def test_login_cookies_are_removed_from_anonymous_json_probe():
    seen = []
    def handler(request):
        seen.append(request)
        if request.url.path == '/login':
            return httpx.Response(200, json={'access_token': 'secret'}, headers={'set-cookie': 'session=secret; Path=/'})
        assert request.headers.get('content-type') == 'application/json'
        assert json.loads(request.content) == [1]
        authenticated = request.headers.get('authorization') or request.headers.get('cookie')
        return httpx.Response(200 if authenticated else 401, json={})
    ep = Endpoint('POST', '/private', secured=True,
        body_schema={'type': 'array', 'minItems': 1, 'items': {'type': 'integer'}})
    fz = Fuzzer([ep], transport=httpx.MockTransport(handler), max_requests=3,
        login={'url': '/login', 'body': {}})
    assert not asyncio.run(fz.run())
    assert len(seen) == 3 and 'cookie' in seen[1].headers
    assert 'cookie' not in seen[2].headers and 'authorization' not in seen[2].headers


@pytest.mark.parametrize('response', [None, [1, 1, 1, 1, 1, 'bad']])
def test_response_contract_checks_null_and_late_array_items(response):
    from sentinelapi.spec import Param
    ep = Endpoint('GET', '/x', params=[Param('q', 'query', {'type': 'string'})],
        responses={'default': {'type': 'array', 'items': {'type': 'integer'}}})
    fz = Fuzzer([ep], transport=httpx.MockTransport(
        lambda request: httpx.Response(200, content=json.dumps(response), headers={'content-type': 'application/json'})))
    findings = asyncio.run(fz.run())
    assert any(f.kind == 'SCHEMA_VIOLATION' for f in findings)


@pytest.mark.parametrize('spec', [ {'paths': {'/x': []}},
    {'paths': {'/x': {'get': []}}}, {'paths': {'/x': {'get': {'parameters': [1]}}}},
    {'paths': {'/x': {'get': {'responses': []}}}},
    {'paths': {'/x': {'get': {'security': True}}}} ])
def test_malformed_operation_structure_has_clear_error(tmp_path, spec):
    path = tmp_path / 'spec.json'
    path.write_text(json.dumps(spec))
    assert main([str(path), '--list']) == 2


def test_missing_files_and_unwritable_report_destination(tmp_path, capsys):
    assert main([str(tmp_path / 'absent.json'), '--list']) == 2
    spec = tmp_path / 'spec.json'
    spec.write_text('{"paths": {}}')
    destination = tmp_path / 'file'
    destination.write_text('existing')
    assert main([str(spec), '--asgi', 'demo_api:app', '--out', str(destination)]) == 2
    assert destination.read_text() == 'existing'
    assert 'Traceback' not in capsys.readouterr().err
