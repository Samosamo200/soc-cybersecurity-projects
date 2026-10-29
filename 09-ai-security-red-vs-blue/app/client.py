"""Azure OpenAI client using Entra ID (no API keys)."""

import os

from azure.identity import DefaultAzureCredential, get_bearer_token_provider
from dotenv import load_dotenv
from openai import OpenAI


def get_settings():
    load_dotenv()
    endpoint = os.environ.get("AZURE_OPENAI_ENDPOINT")
    deployment = os.environ.get("AZURE_OPENAI_DEPLOYMENT", "gpt-5-mini")
    if not endpoint:
        raise SystemExit("AZURE_OPENAI_ENDPOINT is missing. Copy .env.example to .env and fill it in.")
    return endpoint.rstrip("/"), deployment


def make_client(endpoint):
    # Token from `az login` (or a managed identity when deployed). Requires the
    # "Cognitive Services OpenAI User" role on the Foundry resource.
    token_provider = get_bearer_token_provider(
        DefaultAzureCredential(), "https://cognitiveservices.azure.com/.default"
    )
    return OpenAI(base_url=f"{endpoint}/openai/v1/", api_key=token_provider)
