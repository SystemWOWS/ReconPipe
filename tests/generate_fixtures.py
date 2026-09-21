#!/usr/bin/env python3
"""Generate tests/fixtures/patterns.yaml with known-good / known-junk samples."""
from __future__ import annotations

import base64
import json
import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import reconpipe as r  # noqa: E402


def b64url(obj) -> str:
    raw = json.dumps(obj, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def main() -> None:
    c: dict = {}
    c["google_api"] = {
        "good": ["AIza" + "A" * 35],
        "junk": ["AIzaShort", "AIza" + "!" * 35, "notgoogle"],
    }
    c["google_oauth"] = {
        "good": ["ya29." + "a" * 20],
        "junk": ["ya29.short", "ya28.aaaaaaaaaaaaaaaaaaaa"],
    }
    c["aws_access_key"] = {
        "good": ["AKIAIOSFODNN7EXAMPLE", "ASIAIOSFODNN7EXAMPLE"],
        "junk": ["AKIASHORT", "BKIAIOSFODNN7EXAMPLE", "akiaiosfodnn7example"],
    }
    c["aws_secret"] = {
        "good": [
            "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "aws_secret_key='wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'",
        ],
        "junk": ["password=hello", "aws_key=short", "not related text"],
    }
    c["aws_session_token"] = {
        "good": ["aws_session_token=" + "A" * 100, "X-Amz-Security-Token: " + "B" * 120],
        "junk": ["aws_session_token=short", "session=hello"],
    }
    c["github_pat"] = {
        "good": ["ghp_" + "a" * 36],
        "junk": ["ghp_short", "gho_" + "a" * 36],
    }
    c["github_fine_pat"] = {
        "good": ["github_pat_" + "A" * 22 + "_" + "B" * 59],
        "junk": ["github_pat_short", "ghp_" + "a" * 36],
    }
    c["github_oauth"] = {"good": ["gho_" + "x" * 36], "junk": ["ghp_" + "x" * 36]}
    c["github_app"] = {
        "good": ["ghu_" + "x" * 36, "ghs_" + "y" * 36],
        "junk": ["ghx_" + "x" * 36],
    }
    c["gitlab_pat"] = {
        "good": ["glpat-" + "x" * 20],
        "junk": ["glpat-short", "ghp_xxx"],
    }
    c["stripe_live"] = {
        "good": ["sk_live_" + "a" * 24],
        "junk": ["sk_test_" + "a" * 24, "rk_live_" + "a" * 24],
    }
    c["stripe_test"] = {
        "good": ["sk_test_" + "a" * 24],
        "junk": ["sk_live_" + "a" * 24],
    }
    c["stripe_restricted"] = {
        "good": ["rk_live_" + "a" * 24, "rk_test_" + "b" * 30],
        "junk": ["sk_live_" + "a" * 24],
    }
    c["stripe_publishable"] = {
        "good": ["pk_live_" + "a" * 24],
        "junk": ["sk_live_" + "a" * 24],
    }
    c["openai_key"] = {
        "good": [
            "sk-proj-" + "a" * 20 + "-" + "b" * 20,
            "sk-svcacct-" + "d" * 24,
            "sk-" + "e" * 20 + "T3BlbkFJ" + "f" * 20,
        ],
        "junk": ["sk-proj-short", "sk_live_xxx", "sk-ant-api03-" + "c" * 24],
    }
    c["anthropic_key"] = {
        "good": [
            "sk-ant-api03-" + "c" * 20,
            "sk-ant-admin01-" + "d" * 20,
        ],
        "junk": ["sk-ant-api03-short", "sk-proj-" + "a" * 20],
    }
    c["sendgrid"] = {
        "good": ["SG." + "a" * 22 + "." + "b" * 43],
        "junk": ["SG.short.short"],
    }
    c["mailgun"] = {"good": ["key-" + "a" * 32], "junk": ["key-short"]}
    c["twilio_sid"] = {
        "good": ["AC" + "a" * 32],
        "junk": ["AC" + "a" * 10, "SK" + "a" * 32],
    }
    c["twilio_token"] = {
        "good": ["SK" + "a" * 32],
        "junk": ["SK" + "z" * 32, "AC" + "a" * 32],
    }
    c["slack_token"] = {
        "good": ["xoxb-1234567890-abcdefghij"],
        "junk": ["xoxb-short", "xoxz-1234567890-abcdefghij"],
    }
    c["slack_webhook"] = {
        "good": [
            "https://hooks.slack.com/services/T01ABC/B01DEF/abcdefghijklmnopqrstuvwx"
        ],
        "junk": [
            "https://hooks.slack.com/services/nope",
            "https://example.com/hooks",
        ],
    }
    c["firebase_url"] = {
        "good": ["my-app-123.firebaseio.com"],
        "junk": ["firebaseio.com", "my.firebase.com"],
    }
    c["firebase_key"] = {
        "good": ["AAAA" + "a" * 7 + ":" + "b" * 140],
        "junk": ["AAAA:short"],
    }
    c["digitalocean_pat"] = {
        "good": ["dop_v1_" + "a" * 64],
        "junk": ["dop_v1_" + "a" * 32, "dop_v1_" + "g" * 64],
    }
    c["npm_token"] = {"good": ["npm_" + "A" * 36], "junk": ["npm_short"]}
    c["pypi_token"] = {
        "good": ["pypi-AgEIcHlwaS5vcmc" + "x" * 50],
        "junk": ["pypi-AgEIcHlwaS5vcmcshort"],
    }
    c["private_key_pem"] = {
        "good": [
            "-----BEGIN RSA PRIVATE KEY-----",
            "-----BEGIN PRIVATE KEY-----",
            "-----BEGIN OPENSSH PRIVATE KEY-----",
        ],
        "junk": ["-----BEGIN CERTIFICATE-----", "BEGIN PRIVATE KEY"],
    }
    c["uuid_candidate"] = {
        "good": ["550e8400-e29b-41d4-a716-446655440000"],
        "junk": ["550e8400-e29b-61d4-a716-446655440000", "not-a-uuid"],
    }
    hdr = b64url({"alg": "HS256", "typ": "JWT"})
    payload = b64url({"sub": "1", "exp": 9999999999})
    c["jwt"] = {
        "good": [f"{hdr}.{payload}.sigsignature1"],
        "junk": ["eyJhbGciOiJIUzI1NiJ9", "not.a.jwt"],
    }
    c["shopify_token"] = {
        "good": ["shpat_" + "a" * 32],
        "junk": ["shpat_short", "shpss_" + "a" * 32],
    }
    c["shopify_secret"] = {
        "good": ["shpss_" + "a" * 32],
        "junk": ["shpat_" + "a" * 32],
    }
    c["mailchimp"] = {
        "good": ["a" * 32 + "-us1", "b" * 32 + "-us12"],
        "junk": ["a" * 32 + "-eu1", "short-us1"],
    }
    c["discord_token"] = {
        "good": ["M" + "a" * 24 + "." + "b" * 6 + "." + "c" * 27],
        "junk": ["X" + "a" * 24 + "." + "b" * 6 + "." + "c" * 27, "notdiscord"],
    }
    c["discord_webhook"] = {
        "good": [
            "https://discord.com/api/webhooks/123456789012345678/"
            "abcdefghijklmnopqrstuvwxyzABCDEFG"
        ],
        "junk": [
            "https://discord.com/api/webhooks/abc/token",
            "https://example.com/api/webhooks/1/t",
        ],
    }
    c["telegram_bot"] = {
        "good": ["1234567890:" + "A" * 35],
        "junk": ["12:short", "abcdefghij:" + "a" * 35],
    }
    mb = b64url({"u": "alice", "pad": "xxxxxxxxxx"})
    c["mapbox_token"] = {
        "good": [f"pk.{mb}"],
        "junk": ["pk.shorttoken", "pk_live_" + "a" * 24],
    }
    c["generic_secret"] = {
        "good": [
            'api_key = "AbCdEfGhIjKlMnOp1234"',
            'secret: "Qx9!mK2pL8vN4wR7"',
        ],
        "junk": [
            'api_key = "short"',
            "hello world",
            "no assignment here AbCdEfGhIjKlMnOp1234",
        ],
    }
    c["cloudflare_api"] = {
        "good": ["cfpat-" + "A" * 40, "CF_API_TOKEN=" + "B" * 40],
        "junk": ["cfpat-short", "not-a-token"],
    }
    c["azure_sas"] = {
        "good": [
            "sv=2021-08-06&ss=b&srt=sco&sp=r&se=2099-12-31T00:00:00Z&sig=abcdefghijklmnopqrstuv",
        ],
        "junk": ["sv=2021&sig=short", "not-a-sas"],
    }
    c["huggingface_token"] = {
        "good": ["hf_" + "a" * 34],
        "junk": ["hf_short", "sk-hf-nope"],
    }
    c["notion_token"] = {
        "good": ["secret_" + "a" * 43, "ntn_" + "b" * 40],
        "junk": ["secret_short", "ntn_short"],
    }
    c["grafana_token"] = {
        "good": ["glsa_" + "a" * 32 + "_deadbeef"],
        "junk": ["glsa_short", "glsa_" + "a" * 10],
    }
    c["hashicorp_vault"] = {
        "good": ["hvs." + "A" * 24, "hvb." + "B" * 30],
        "junk": ["hvs.short", "s.notvault"],
    }
    c["datadog_api_key"] = {
        "good": ["dd_api_key=" + "a" * 32, "DATADOG=" + "b" * 32],
        "junk": ["dd_api_key=short", "hello=" + "a" * 32],
    }
    gcp_blob = (
        '{"type":"service_account","project_id":"demo",'
        '"private_key":"-----BEGIN PRIVATE KEY-----\\nMII\\n-----END PRIVATE KEY-----\\n",'
        '"client_email":"foo@demo.iam.gserviceaccount.com"}'
    )
    c["gcp_service_acct"] = {
        "good": [gcp_blob],
        "junk": ['{"type":"user","private_key":"-----BEGIN PRIVATE KEY-----"}', "not-json"],
    }
    c["linear_api_key"] = {
        "good": ["lin_api_" + "a" * 40],
        "junk": ["lin_api_short", "lin_api_" + "a" * 10],
    }
    c["supabase_service"] = {
        "good": [
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwiZXhwIjo5OTk5OTk5OTk5fQ.sigsignature1"
        ],
        "junk": ["eyJhbGciOiJIUzI1NiJ9", "not.a.jwt"],
    }
    c["railway_token"] = {"good": ["railway_" + "a" * 32], "junk": ["railway_short"]}
    c["render_api"] = {"good": ["rnd_" + "a" * 24], "junk": ["rnd_short"]}
    c["flyio_token"] = {"good": ["fo1_" + "a" * 40], "junk": ["fo1_short"]}
    c["planetscale_token"] = {"good": ["pscale_tkn_" + "a" * 32], "junk": ["pscale_tkn_short"]}
    c["neon_api"] = {"good": ["neon_" + "a" * 32], "junk": ["neon_short"]}
    c["buildkite_token"] = {"good": ["bkua_" + "a" * 40], "junk": ["bkua_short"]}
    c["sentry_auth"] = {"good": ["sntrys_" + "a" * 64], "junk": ["sntrys_short"]}
    c["newrelic_api"] = {"good": ["NRAK-" + "A" * 27], "junk": ["NRAK-SHORT"]}
    c["replicate_api"] = {"good": ["r8_" + "a" * 40], "junk": ["r8_short"]}
    c["doppler_token"] = {"good": ["dp.pt." + "a" * 40], "junk": ["dp.pt.short"]}
    c["pulumi_token"] = {"good": ["pul-" + "a" * 40], "junk": ["pul-short"]}
    c["contentful_cma"] = {"good": ["CFPAT-" + "a" * 43], "junk": ["CFPAT-short"]}
    c["clickup_api"] = {"good": ["pk_1_" + "A" * 32], "junk": ["pk_1_SHORT"]}
    c["posthog_api"] = {"good": ["phc_" + "a" * 32], "junk": ["phc_short"]}
    c["mongodb_srv"] = {
        "good": ["mongodb+srv://user:pass@cluster0.mongodb.net"],
        "junk": ["mongodb://localhost"],
    }
    c["postgres_uri"] = {
        "good": ["postgres://u:p@host/db"],
        "junk": ["postgres://localhost/db"],
    }
    c["vercel_token"] = {
        "good": ["VERCEL_TOKEN=" + "A" * 24],
        "junk": ["A" * 24],
    }

    jwt_ok = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwiZXhwIjo5OTk5OTk5OTk5fQ.sigsignature1"
    extra = {
        "netlify_pat": {"good": ["NETLIFY_TOKEN=" + "a" * 43], "junk": ["a" * 43]},
        "supabase_anon": {"good": [jwt_ok], "junk": ["eyJhbGciOiJIUzI1NiJ9"]},
        "upstash_token": {"good": ["UPSTASH_TOKEN=AX" + "a" * 36], "junk": ["AX" + "a" * 36]},
        "circleci_token": {"good": ["circleci_" + "a" * 40, "CIRCLE_TOKEN=" + "b" * 40], "junk": ["circleci_short"]},
        "travis_token": {"good": ["travis_token=" + "a" * 22], "junk": ["travis_token=short"]},
        "jenkins_token": {"good": ["jenkins_token=" + "a" * 32], "junk": ["jenkins_token=ab"]},
        "drone_token": {"good": ["drone_token=" + "a" * 32], "junk": ["drone_token=short"]},
        "codefresh_token": {"good": ["codefresh_token=" + "a" * 40], "junk": ["codefresh_token=short"]},
        "teamcity_token": {"good": ["teamcity_token=" + "a" * 20], "junk": ["teamcity_token=ab"]},
        "bitbucket_app_password": {"good": ["ATBB" + "a" * 32], "junk": ["ATBBSHORT"]},
        "sentry_dsn": {"good": ["https://" + "a" * 32 + "@o.ingest.sentry.io/1"], "junk": ["https://x@sentry.io/1"]},
        "newrelic_license": {"good": ["a" * 40 + "NRAL"], "junk": ["abcdNRAL"]},
        "newrelic_insert": {"good": ["NRII-" + "a" * 32], "junk": ["NRII-short"]},
        "splunk_hec": {"good": ["splunk_hec=" + "a" * 8 + "-" * 4 + "b" * 24], "junk": ["splunk_hec=short"]},
        "elastic_api": {"good": ["elastic_api=" + "a" * 40], "junk": ["elastic_api=short"]},
        "logdna_key": {"good": ["logdna_key=" + "a" * 32], "junk": ["logdna_key=ab"]},
        "loggly_token": {"good": ["loggly_token=" + "a" * 8 + "-" + "b" * 27], "junk": ["loggly_token=x"]},
        "papertrail_token": {"good": ["papertrail_token=" + "a" * 32], "junk": ["papertrail_token=x"]},
        "rollbar_token": {"good": ["rollbar_token=" + "a" * 32], "junk": ["rollbar_token=x"]},
        "bugsnag_api": {"good": ["bugsnag_api=" + "a" * 32], "junk": ["bugsnag_api=x"]},
        "honeybadger_api": {"good": ["honeybadger_api=" + "a" * 20], "junk": ["honeybadger_api=x"]},
        "teams_webhook": {
            "good": ["https://outlook.webhook.office.com/webhookb2/" + "a" * 8],
            "junk": ["https://example.com/webhook"],
        },
        "vonage_api": {"good": ["vonage_api=" + "a" * 8], "junk": ["vonage_api=ab"]},
        "messagebird_key": {"good": ["messagebird_key=" + "a" * 25], "junk": ["messagebird_key=x"]},
        "postmark_token": {"good": ["postmark_token=" + "a" * 8 + "-" + "b" * 27], "junk": ["postmark_token=x"]},
        "mailjet_api": {"good": ["mailjet_api=" + "a" * 32], "junk": ["mailjet_api=x"]},
        "sparkpost_api": {"good": ["sparkpost_api=" + "a" * 40], "junk": ["sparkpost_api=x"]},
        "intercom_token": {"good": ["intercom_token=" + "a" * 40], "junk": ["intercom_token=x"]},
        "hubspot_api": {
            "good": [
                "pat-na1-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                "pat-eu1-11111111-2222-3333-4444-555555555555",
            ],
            "junk": ["pat-na1-short", "pat-n1-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"],
        },
        "zendesk_token": {"good": ["zendesk_token=" + "a" * 40], "junk": ["zendesk_token=x"]},
        "freshdesk_api": {"good": ["freshdesk_api=" + "a" * 20], "junk": ["freshdesk_api=x"]},
        "square_access": {"good": ["sq0atp-" + "a" * 22], "junk": ["sq0atp-short"]},
        "square_application": {"good": ["sq0idp-" + "a" * 22], "junk": ["sq0idp-short"]},
        "paypal_client_id": {"good": ["paypal_client_id=A" + "a" * 79], "junk": ["A" + "a" * 79]},
        "paypal_secret": {"good": ["paypal_secret=E" + "a" * 79], "junk": ["E" + "a" * 79]},
        "braintree_token": {"good": ["braintree_token=" + "a" * 32], "junk": ["braintree_token=x"]},
        "adyen_api": {"good": ["AQE" + "a" * 40], "junk": ["AQEshort"]},
        "mollie_api": {"good": ["mollie_api=live_" + "a" * 30], "junk": ["live_short"]},
        "klarna_api": {"good": ["klarna_api=" + "a" * 40], "junk": ["klarna_api=x"]},
        "woocommerce_key": {"good": ["ck_" + "a" * 40], "junk": ["ck_short"]},
        "woocommerce_secret": {"good": ["cs_" + "a" * 40], "junk": ["cs_short"]},
        "bigcommerce_token": {"good": ["bigcommerce_token=" + "a" * 64], "junk": ["bigcommerce_token=x"]},
        "algolia_api": {"good": ["algolia_api_key=" + "a" * 32], "junk": ["algolia_api_key=x"]},
        "algolia_admin": {"good": ["algolia_admin_key=" + "a" * 32], "junk": ["algolia_admin_key=x"]},
        "meilisearch_key": {"good": ["meili_master=" + "a" * 40], "junk": ["meili_master=x"]},
        "typesense_api": {"good": ["typesense_api=" + "a" * 32], "junk": ["typesense_api=x"]},
        "mixpanel_token": {"good": ["mixpanel_token=" + "a" * 32], "junk": ["mixpanel_token=x"]},
        "mixpanel_secret": {"good": ["mixpanel_secret=" + "a" * 32], "junk": ["mixpanel_secret=x"]},
        "amplitude_api": {"good": ["amplitude_api=" + "a" * 32], "junk": ["amplitude_api=x"]},
        "segment_write": {"good": ["segment_write=" + "A" * 32], "junk": ["segment_write=x"]},
        "heap_app_id": {"good": ["heap_app_id=123456789"], "junk": ["heap_app_id=12"]},
        "plausible_api": {"good": ["plausible_api=" + "a" * 40], "junk": ["plausible_api=x"]},
        "cohere_api": {"good": ["cohere_api=" + "a" * 40], "junk": ["cohere_api=x"]},
        "stability_api": {"good": ["stability_api=sk-" + "a" * 48], "junk": ["sk-" + "a" * 48]},
        "together_api": {"good": ["together_api=" + "a" * 64], "junk": ["together_api=x"]},
        "anyscale_api": {"good": ["anyscale_api=" + "a" * 40], "junk": ["anyscale_api=x"]},
        "pinecone_api": {"good": ["pinecone_api=" + "a" * 8 + "-" + "b" * 27], "junk": ["pinecone_api=x"]},
        "weaviate_api": {"good": ["weaviate_api=" + "a" * 50], "junk": ["weaviate_api=x"]},
        "qdrant_api": {"good": ["qdrant_api=" + "a" * 32], "junk": ["qdrant_api=x"]},
        "elevenlabs_api": {"good": ["eleven_labs_api=" + "a" * 32], "junk": ["eleven_labs_api=x"]},
        "deepgram_api": {"good": ["deepgram_api=" + "a" * 40], "junk": ["deepgram_api=x"]},
        "assemblyai_api": {"good": ["assemblyai_api=" + "a" * 32], "junk": ["assemblyai_api=x"]},
        "infisical_token": {"good": ["infisical_token=" + "a" * 40], "junk": ["infisical_token=x"]},
        "onepassword_connect": {"good": ["1password=" + jwt_ok], "junk": [jwt_ok]},
        "conjur_api": {"good": ["conjur_api=" + "a" * 40], "junk": ["conjur_api=x"]},
        "akeyless_token": {"good": ["akeyless_token=" + "a" * 100], "junk": ["akeyless_token=x"]},
        "terraform_cloud": {"good": ["atlasv1" + "a" * 44], "junk": ["atlasv1short"]},
        "spacelift_api": {"good": ["spacelift_api=" + "a" * 40], "junk": ["spacelift_api=x"]},
        "mysql_uri": {"good": ["mysql://u:p@host/db"], "junk": ["mysql://localhost/db"]},
        "redis_uri": {"good": ["redis://:p@host"], "junk": ["redis://localhost"]},
        "fauna_secret": {"good": ["fn" + "a" * 40], "junk": ["fnshort"]},
        "cockroachdb_api": {"good": ["cockroach_api=" + "a" * 40], "junk": ["cockroach_api=x"]},
        "airtable_api": {"good": ["airtable_api=pat" + "a" * 14], "junk": ["pat" + "a" * 14]},
        "notion_database": {"good": ["notion_database_id=" + "a" * 32], "junk": ["a" * 32]},
        "contentful_cda": {"good": ["contentful_cda=" + "a" * 43], "junk": ["contentful_cda=x"]},
        "sanity_token": {"good": ["sanity_token=sk" + "a" * 40], "junk": ["sk" + "a" * 40]},
        "strapi_token": {"good": ["strapi_token=" + "a" * 64], "junk": ["strapi_token=x"]},
        "azure_client_secret": {"good": ["azure_client_secret=" + "a" * 34], "junk": ["azure_client_secret=x"]},
        "azure_storage_key": {"good": ["account_key=" + "a" * 86], "junk": ["account_key=short"]},
        "azure_cosmos_key": {"good": ["cosmos_key=" + "a" * 86], "junk": ["cosmos_key=x"]},
        "azure_devops_pat": {"good": ["azure_devops_pat=" + "a" * 52], "junk": ["azure_devops_pat=x"]},
        "aws_mws_auth": {"good": ["amzn.mws." + "a" * 8 + "-" * 4 + "b" * 24], "junk": ["amzn.mws.short"]},
        "oci_api_key": {"good": ["ocid1.tenancy.oc1.." + "a" * 60], "junk": ["ocid1.tenancy.oc1..short"]},
        "linode_pat": {"good": ["linode_pat=" + "a" * 64], "junk": ["linode_pat=x"]},
        "vultr_api": {"good": ["vultr_api=" + "A" * 36], "junk": ["vultr_api=x"]},
        "hetzner_api": {"good": ["hetzner_api=" + "a" * 64], "junk": ["hetzner_api=x"]},
        "scaleway_secret": {"good": ["scaleway_secret=" + "a" * 8 + "-" + "b" * 27], "junk": ["scaleway_secret=x"]},
        "pagerduty_api": {"good": ["pagerduty_api=" + "a" * 20], "junk": ["pagerduty_api=x"]},
        "opsgenie_api": {"good": ["opsgenie_api=" + "a" * 8 + "-" + "b" * 27], "junk": ["opsgenie_api=x"]},
        "atlassian_api": {"good": ["atlassian_token=" + "a" * 20], "junk": ["atlassian_token=x"]},
        "jira_token": {"good": ["jira_token=" + "a" * 24], "junk": ["jira_token=x"]},
        "confluence_token": {"good": ["confluence_token=" + "a" * 24], "junk": ["confluence_token=x"]},
        "asana_pat": {"good": ["1/" + "1" * 16 + ":" + "a" * 32], "junk": ["1/123:short"]},
        "monday_api": {"good": ["monday_api=" + jwt_ok], "junk": [jwt_ok]},
        "trello_api": {"good": ["trello_api=" + "a" * 32], "junk": ["trello_api=x"]},
        "okta_api": {"good": ["okta_api=00" + "a" * 40], "junk": ["00" + "a" * 40]},
        "auth0_token": {"good": ["auth0_secret=" + "a" * 32], "junk": ["auth0_secret=x"]},
        "clerk_secret": {"good": ["clerk_secret=sk_test_" + "a" * 27], "junk": ["sk_test_" + "a" * 27]},
        "supertokens_key": {"good": ["supertokens_api=" + "a" * 40], "junk": ["supertokens_api=x"]},
        "launchdarkly_sdk": {"good": ["sdk-" + "a" * 8 + "-" * 4 + "b" * 24], "junk": ["sdk-short"]},
        "launchdarkly_api": {"good": ["api-" + "a" * 8 + "-" * 4 + "b" * 24], "junk": ["api-short"]},
        "split_api": {"good": ["split_api=" + "a" * 50], "junk": ["split_api=x"]},
        "statsig_secret": {"good": ["statsig_secret=secret-" + "a" * 32], "junk": ["secret-" + "a" * 32]},
        "unleash_token": {"good": ["unleash_token=" + "a" * 30], "junk": ["unleash_token=x"]},
        "groq_api": {"good": ["gsk_" + "A" * 20], "junk": ["gsk_short"]},
        "xai_api": {"good": ["xai-" + "A" * 20], "junk": ["xai-short"]},
        "perplexity_api": {"good": ["pplx-" + "A" * 20], "junk": ["pplx-short"]},
        "fireworks_api": {"good": ["fw_" + "A" * 24], "junk": ["fw_short"]},
        "slack_app_token": {"good": ["xapp-1-" + "A" * 20], "junk": ["xapp-1-short"]},
        "figma_token": {"good": ["figd_" + "A" * 40], "junk": ["figd_short"]},
        "databricks_token": {"good": ["dapi" + "a" * 32], "junk": ["dapi" + "a" * 8]},
        "postman_api": {"good": ["PMAK-" + "a" * 24 + "-" + "b" * 34], "junk": ["PMAK-short"]},
        "sonar_token": {"good": ["squ_" + "a" * 40], "junk": ["squ_short"]},
        "cloudinary_url": {
            "good": ["cloudinary://abc:secretpass@demo-cloud"],
            "junk": ["cloudinary://nopath"],
        },
        "razorpay_key": {"good": ["rzp_live_" + "A" * 14], "junk": ["rzp_live_short"]},
        "flutterwave_secret": {"good": ["FLWSECK-" + "A" * 10], "junk": ["FLWSECK-ab"]},
        "n8n_api": {"good": ["n8n_api_" + "A" * 20], "junk": ["n8n_api_short"]},
    }
    # uuid-like hex-with-dashes: 8-4-4-4-12 = 36 including dashes
    uuidish = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    extra["splunk_hec"]["good"] = ["splunk_hec=" + uuidish]
    extra["loggly_token"]["good"] = ["loggly_token=" + uuidish]
    extra["postmark_token"]["good"] = ["postmark_token=" + uuidish]
    extra["pinecone_api"]["good"] = ["pinecone_api=" + uuidish]
    extra["scaleway_secret"]["good"] = ["scaleway_secret=" + uuidish]
    extra["opsgenie_api"]["good"] = ["opsgenie_api=" + uuidish]
    extra["launchdarkly_sdk"]["good"] = ["sdk-" + uuidish]
    extra["launchdarkly_api"]["good"] = ["api-" + uuidish]
    extra["aws_mws_auth"]["good"] = ["amzn.mws." + uuidish]
    extra["newrelic_insert"]["good"] = ["NRII-" + "a" * 32]
    c.update(extra)

    errors = []
    for t, samples in c.items():
        pat = r.PATTERNS.get(t)
        if not pat:
            errors.append(f"missing pattern {t}")
            continue
        rx = re.compile(pat)
        for g in samples["good"]:
            if not rx.search(g):
                errors.append(f"FN {t}: {g[:70]!r}")
            if t == "mapbox_token" and not r.is_mapbox_token(
                rx.search(g).group(0) if rx.search(g) else g
            ):
                errors.append(f"mapbox JSON fail {t}: {g[:50]!r}")
        for j in samples["junk"]:
            if rx.search(j):
                errors.append(f"FP {t}: {j[:70]!r}")

    if errors:
        print("ERRORS", len(errors))
        for e in errors:
            print(e)
        sys.exit(1)

    out = ROOT / "tests" / "fixtures" / "patterns.yaml"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        yaml.dump({"patterns": c}, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )
    print(f"wrote {out} types={len(c)}")


if __name__ == "__main__":
    main()
