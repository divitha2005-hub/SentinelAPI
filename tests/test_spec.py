from sentinelapi.spec import parse_endpoints


def test_escaped_reference_tokens_and_decode_order():
    spec = {'components': {'schemas': {
        'a/b~c': {'type': 'integer'},
        'literal~1': {'type': 'string'},
    }}, 'paths': {'/x': {'get': {'responses': {
        '200': {'content': {'application/json': {'schema': {
            '$ref': '#/components/schemas/a~1b~0c'}}}},
        '201': {'content': {'application/json': {'schema': {
            '$ref': '#/components/schemas/literal~01'}}}},
    }}}}}
    ep = parse_endpoints(spec)[0]
    assert ep.responses == {'200': {'type': 'integer'}, '201': {'type': 'string'}}


def test_operation_parameter_override_preserves_other_locations_and_operations():
    shared = [
        {'name': 'id', 'in': 'query', 'schema': {'type': 'string'}},
        {'name': 'id', 'in': 'header', 'schema': {'type': 'string'}},
    ]
    spec = {'components': {'parameters': {'Id': {
        'name': 'id', 'in': 'query', 'required': True,
        'schema': {'type': 'integer', 'minimum': 1}}}},
        'paths': {'/x': {'parameters': shared,
            'get': {'parameters': [{'$ref': '#/components/parameters/Id'}]},
            'post': {}}}}
    eps = {e.method: e for e in parse_endpoints(spec)}
    assert len(eps['GET'].params) == 2
    query, header = eps['GET'].params
    assert query.schema == {'type': 'integer', 'minimum': 1}
    assert query.required and header.location == 'header'
    assert eps['POST'].params[0].schema == {'type': 'string'}
    assert shared[0]['schema'] == {'type': 'string'}


def test_swagger_response_references_and_schema_less_responses():
    spec = {'swagger': '2.0', 'definitions': {'Result': {
        'type': 'object', 'required': ['id'],
        'properties': {'id': {'type': 'integer'}}}},
        'responses': {'Result': {'description': 'ok',
            'schema': {'$ref': '#/definitions/Result'}}},
        'paths': {'/x': {'get': {'responses': {
            200: {'$ref': '#/responses/Result'},
            204: {'description': 'empty'},
        }}}}}
    ep = parse_endpoints(spec)[0]
    assert ep.responses['200'] == spec['definitions']['Result']
    assert ep.responses['204'] == {}
