"""Real local dashboard integration and access-control checks."""
import json

from fastapi.testclient import TestClient
from sentinelapi.web import app, reports


def client():
    return TestClient(app, base_url='http://localhost')


def test_dashboard_serves_complete_local_ui():
    with client() as c:
        response = c.get('/')
        assert response.status_code == 200
        assert 'Configure a scan' in response.text
        assert 'Scan findings' in response.text
        assert "frame-ancestors 'none'" in response.headers['content-security-policy']


def test_demo_scan_and_every_report_download():
    with client() as c:
        response = c.post('/api/scan', json={'mode': 'demo', 'max_requests': 150, 'rps': 100})
        assert response.status_code == 200
        data = response.json()
        assert data['requests'] <= 150
        assert data['coverage']['endpoint_coverage_pct'] == 100
        assert {'SQL_INJECTION', 'XSS_REFLECTION', 'PATH_TRAVERSAL'} <= {f['kind'] for f in data['findings']}
        for format in ('html', 'md', 'json', 'sarif'):
            report = c.get(f"/api/reports/{data['id']}/{format}")
            assert report.status_code == 200 and report.content
            assert 'attachment;' in report.headers['content-disposition']
            if format in ('json', 'sarif'):
                json.loads(report.content)


def test_ui_zero_budget_and_validation_errors():
    with client() as c:
        response = c.post('/api/scan', json={'max_requests': 0})
        assert response.status_code == 200 and response.json()['requests'] == 0
        assert response.json()['truncated']
        for options in ({'max_requests': -1}, {'rps': 0}, {'max_requests': 2001}):
            assert c.post('/api/scan', json=options).status_code == 422
        for options in ({'mode': 'unknown'}, {'mode': 'live'},
            {'mode': 'live', 'spec_text': '{}'},
            {'mode': 'live', 'spec_text': 'paths: {}', 'base_url': 'http://8.8.8.8'}):
            assert c.post('/api/scan', json=options).status_code == 400
        assert c.get('/api/reports/missing/html').status_code == 404


def test_ui_rejects_foreign_origins_and_host_headers():
    with client() as c:
        assert c.post('/api/scan', json={}, headers={'origin': 'https://other.example'}).status_code == 403
        assert c.get('/', headers={'host': 'other.example'}).status_code == 403
        assert c.post('/api/scan', json={'max_requests': 0}, headers={'origin': 'http://localhost'}).status_code == 200
