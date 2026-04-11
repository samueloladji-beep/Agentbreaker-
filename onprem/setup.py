#!/usr/bin/env python3
"""
Vaultak On-Premises Setup Script
Run after docker-compose up -d to initialize your instance.
Usage: docker-compose exec backend python setup.py
"""
import os, requests

API_BASE  = "http://localhost:8000"
ADMIN_KEY = os.environ.get("ADMIN_KEY", "")

def setup():
    print("\nVaultak On-Premises Setup\n")
    org_name = input("Organization name: ").strip() or "My Company"
    slug     = input("Slug (no spaces): ").strip() or "my-company"

    r = requests.post(f"{API_BASE}/admin/orgs",
        headers={"x-admin-key": ADMIN_KEY},
        json={"name": org_name, "slug": slug})
    org = r.json()

    r = requests.post(f"{API_BASE}/admin/orgs/{org['id']}/keys",
        headers={"x-admin-key": ADMIN_KEY}, params={"name": "default"})
    key = r.json()

    print(f"\nOrganization: {org['name']}")
    print(f"API Key:      {key['api_key']}")
    print(f"\nSave this key — it will not be shown again.")
    print(f"Dashboard:    http://localhost:3000\n")

if __name__ == "__main__":
    setup()
