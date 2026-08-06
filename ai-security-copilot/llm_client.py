"""
Provider-agnostic LLM client for the security report generator.

Previously agent.py imported `mistralai` directly at module scope and
hardcoded the model name, so a customer wanting to use Claude (or any
other model) instead of Mistral had to fork the code. `ask_llm()` is now
the only entry point agent.py calls; the provider is selected via
config.LLM_PROVIDER (env var LLM_PROVIDER=mistral|anthropic).

Adding a new provider means adding one `_ask_<provider>` function and a
branch in `ask_llm` - agent.py and its prompt-building logic never change.
"""

from typing import Optional

import config

DEFAULT_SYSTEM_PROMPT = (
    "You are a Senior Application Security and Post Quantum Cryptography "
    "Security Engineer. Generate enterprise security migration assessments "
    "using provided evidence only."
)


def ask_llm(prompt: str, system_prompt: Optional[str] = None) -> str:
    """Send `prompt` to the configured LLM provider and return the text response."""
    system_prompt = system_prompt or DEFAULT_SYSTEM_PROMPT
    provider = config.LLM_PROVIDER

    if provider == "mistral":
        return _ask_mistral(prompt, system_prompt)
    elif provider == "anthropic":
        return _ask_anthropic(prompt, system_prompt)
    else:
        raise ValueError(
            f"Unsupported LLM_PROVIDER '{provider}'. Supported values: "
            "'mistral', 'anthropic'. Set the LLM_PROVIDER environment variable."
        )


def _ask_mistral(prompt: str, system_prompt: str) -> str:
    try:
        from mistralai import Mistral
    except ImportError as e:
        raise ImportError(
            "Could not import 'Mistral' from 'mistralai'. "
            "Please ensure 'mistralai>=1.0.0' is installed correctly."
        ) from e

    api_key = config.MISTRAL_API_KEY
    if not api_key:
        raise ValueError(
            "Environment variable MISTRAL_API_KEY is not set "
            "(required when LLM_PROVIDER=mistral)."
        )

    client = Mistral(api_key=api_key)

    response = client.chat.complete(
        model=config.MISTRAL_MODEL,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt},
        ],
    )

    return response.choices[0].message.content


def _ask_anthropic(prompt: str, system_prompt: str) -> str:
    try:
        import anthropic
    except ImportError as e:
        raise ImportError(
            "Could not import 'anthropic'. Run 'pip install anthropic' to use "
            "LLM_PROVIDER=anthropic."
        ) from e

    api_key = config.ANTHROPIC_API_KEY
    if not api_key:
        raise ValueError(
            "Environment variable ANTHROPIC_API_KEY is not set "
            "(required when LLM_PROVIDER=anthropic)."
        )

    client = anthropic.Anthropic(api_key=api_key)

    response = client.messages.create(
        model=config.ANTHROPIC_MODEL,
        max_tokens=config.LLM_MAX_TOKENS,
        system=system_prompt,
        messages=[{"role": "user", "content": prompt}],
    )

    return "".join(
        block.text for block in response.content if getattr(block, "type", "") == "text"
    )
