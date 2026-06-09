"""Provider-flexible LLM factory.

Every agent gets its model from here. Switch the whole team between
OpenAI and Claude by changing LLM_PROVIDER in .env — no code changes.
"""

from __future__ import annotations

from langchain_core.language_models.chat_models import BaseChatModel

from redhive.config import settings


def get_llm(temperature: float = 0.0) -> BaseChatModel:
    """Return the chat model for the configured provider.

    OpenAI is the default; set LLM_PROVIDER=claude to use Anthropic.
    """
    provider = settings.llm_provider.lower()

    if provider == "openai":
        from langchain_openai import ChatOpenAI

        return ChatOpenAI(
            model=settings.openai_model,
            api_key=settings.openai_api_key,
            temperature=temperature,
        )

    if provider in ("claude", "anthropic"):
        from langchain_anthropic import ChatAnthropic

        return ChatAnthropic(
            model=settings.anthropic_model,
            api_key=settings.anthropic_api_key,
            temperature=temperature,
        )

    raise ValueError(
        f"Unknown LLM_PROVIDER {provider!r}. Use 'openai' or 'claude'."
    )
