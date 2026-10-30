"""Azure clients using Entra ID (no API keys): Azure OpenAI and Prompt Shields."""

import os

import requests
from azure.identity import DefaultAzureCredential, get_bearer_token_provider
from dotenv import load_dotenv
from openai import OpenAI

SCOPE = "https://cognitiveservices.azure.com/.default"
PROMPT_SHIELDS_API_VERSION = "2024-09-01"

_credential = None


def get_credential():
    # Token from `az login` (or a managed identity when deployed)
    global _credential
    if _credential is None:
        _credential = DefaultAzureCredential()
    return _credential


def get_settings():
    load_dotenv()
    endpoint = os.environ.get("AZURE_OPENAI_ENDPOINT")
    deployment = os.environ.get("AZURE_OPENAI_DEPLOYMENT", "gpt-5-mini")
    if not endpoint:
        raise SystemExit("AZURE_OPENAI_ENDPOINT is missing. Copy .env.example to .env and fill it in.")
    return endpoint.rstrip("/"), deployment


def make_client(endpoint):
    # Requires the "Cognitive Services OpenAI User" role on the Foundry resource
    token_provider = get_bearer_token_provider(get_credential(), SCOPE)
    return OpenAI(base_url=f"{endpoint}/openai/v1/", api_key=token_provider)


def make_shield(endpoint):
    """Return a Prompt Shields check: (user_prompt, documents) -> (prompt_attack, [doc_attack, ...]).

    Prompt Shields is part of Azure AI Content Safety, served by the same Foundry resource.
    Requires the "Cognitive Services User" role on the Foundry resource.
    """
    shield_endpoint = os.environ.get("AZURE_CONTENT_SAFETY_ENDPOINT") or endpoint.replace(
        ".openai.azure.com", ".cognitiveservices.azure.com"
    )
    url = f"{shield_endpoint.rstrip('/')}/contentsafety/text:shieldPrompt?api-version={PROMPT_SHIELDS_API_VERSION}"

    def shield(user_prompt, documents):
        token = get_credential().get_token(SCOPE).token
        response = requests.post(
            url,
            json={"userPrompt": user_prompt, "documents": documents},
            headers={"Authorization": f"Bearer {token}"},
            timeout=30,
        )
        if response.status_code in (401, 403):
            raise SystemExit(
                f"Prompt Shields access denied (HTTP {response.status_code}). Give your account the "
                f"'Cognitive Services User' role on the Foundry resource.\n{response.text}"
            )
        response.raise_for_status()
        data = response.json()
        prompt_attack = data["userPromptAnalysis"]["attackDetected"]
        doc_attacks = [doc["attackDetected"] for doc in data.get("documentsAnalysis", [])]
        return prompt_attack, doc_attacks

    return shield
