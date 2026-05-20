from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any


DEFAULT_BASE_URL = "https://api.openai.com/v1"
DEFAULT_MODEL = "gpt-5-nano"
DEFAULT_TIMEOUT_SECONDS = 120

SPENT_USD = 0.0
INPUT_PER_MILLION = 0.05 # input cost in USD per 1 million tokens for gpt-5-nano
OUTPUT_PER_MILLION = 0.4  # output cost in USD per 1 million tokens for gpt-5-nano


class LLMError(RuntimeError):
    """Raised when the course LLM API cannot return usable text."""


def query_llm(
    prompt: str,
    *,
    instructions: str | None = None,
    max_output_tokens: int = 512,
    reasoning_effort: str = "minimal",
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
) -> str:
    """Query the course-supported LLM API and return the response text.

    Student analyzers should use this function for all LLM calls. In local
    development it talks to OpenAI by default. In grading, the environment
    points the same API at the course proxy.
    """

    if not prompt:
        raise ValueError("prompt must not be empty")
    if max_output_tokens < 1:
        raise ValueError("max_output_tokens must be positive")

    payload: dict[str, Any] = {
        "model": os.environ.get("OPENAI_MODEL", DEFAULT_MODEL),
        "input": prompt,
        "max_output_tokens": max_output_tokens,
        "reasoning": {
            "effort": reasoning_effort
        },
        "store": False,
    }
    if instructions:
        payload["instructions"] = instructions

    response = _post_json(_responses_url(), payload, timeout_seconds)

    __log_cost_estimate(response)
    return _extract_text(response)


def _responses_url() -> str:
    base_url = os.environ.get("OPENAI_BASE_URL", DEFAULT_BASE_URL).rstrip("/")
    return f"{base_url}/responses"


def _post_json(url: str, payload: dict[str, Any], timeout_seconds: int) -> dict[str, Any]:
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        raise LLMError("OPENAI_API_KEY is not set")

    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        headers={
            "authorization": f"Bearer {api_key}",
            "content-type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        error_body = exc.read().decode("utf-8", errors="replace")
        raise LLMError(f"LLM request failed with HTTP {exc.code}: {error_body}") from exc
    except urllib.error.URLError as exc:
        raise LLMError(f"LLM request failed: {exc.reason}") from exc
    except json.JSONDecodeError as exc:
        raise LLMError(f"LLM response was not valid JSON: {exc}") from exc


def _extract_text(response: dict[str, Any]) -> str:
    output_text = response.get("output_text")
    if isinstance(output_text, str) and output_text:
        return output_text

    chunks: list[str] = []
    for item in response.get("output", []):
        if not isinstance(item, dict):
            continue
        for content in item.get("content", []):
            if isinstance(content, dict) and content.get("type") == "output_text":
                text = content.get("text")
                if isinstance(text, str):
                    chunks.append(text)

    if chunks:
        return "".join(chunks)
    raise LLMError("LLM response did not contain output text")


def __log_cost_estimate(response: dict[str, Any]) -> None:
    usage = response.get("usage", {})
    cost = __estimate_cost(usage)
    global SPENT_USD
    SPENT_USD += cost
    print(f"Estimated cost of this LLM call: ${cost:.6f}. Total spent so far: ${SPENT_USD:.6f}.")

def __estimate_cost(usage: dict[str, Any]) -> float:
    input_tokens = usage.get("input_tokens", usage.get("prompt_tokens", 0)) or 0
    output_tokens = usage.get("output_tokens", usage.get("completion_tokens", 0)) or 0
    print(f"LLM usage - input tokens: {input_tokens}, output tokens: {output_tokens}")
    return (input_tokens / 1_000_000) * INPUT_PER_MILLION + (
        output_tokens / 1_000_000
    ) * OUTPUT_PER_MILLION