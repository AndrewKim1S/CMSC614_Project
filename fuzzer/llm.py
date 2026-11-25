"""Minimal client for an OpenAI-compatible chat endpoint (the vLLM server on Nexus).

Standard library only, so it runs inside the shared image without pip installs.
"""
import json
import time
import urllib.error
import urllib.request


class DeadlineReached(Exception):
    """The run's time budget ran out while waiting for the LLM."""


def strip_reasoning(text):
    # With thinking enabled the Qwen chat template opens <think> in the prompt,
    # so the completion contains the reasoning followed by a bare </think>.
    if "</think>" in text:
        text = text.rsplit("</think>", 1)[1]
    return text.strip()


class LLM:
    def __init__(self, base_url, model, temperature=0.7, max_tokens=4096,
                 thinking=False, timeout=600, seed=None):
        self.url = base_url.rstrip("/") + "/chat/completions"
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.thinking = thinking
        self.timeout = timeout
        self.seed = seed
        self.calls = 0
        self.prompt_tokens = 0
        self.completion_tokens = 0

    def chat(self, messages, max_tokens=None, deadline=None):
        """deadline: time.monotonic() value after which waiting is pointless (the
        run's time budget). Each attempt waits at most until then; past it,
        DeadlineReached is raised instead of retrying."""
        body = {
            "model": self.model,
            "messages": messages,
            "temperature": self.temperature,
            "max_tokens": max_tokens or self.max_tokens,
            "chat_template_kwargs": {"enable_thinking": self.thinking},
        }
        if self.seed is not None:
            body["seed"] = self.seed + self.calls
        req = urllib.request.Request(self.url, json.dumps(body).encode(),
                                     {"Content-Type": "application/json"})
        start = time.monotonic()
        for attempt in range(4):
            timeout = self.timeout
            if deadline is not None:
                timeout = deadline - time.monotonic()
                if timeout <= 0:
                    raise DeadlineReached()
            try:
                with urllib.request.urlopen(req, timeout=timeout) as r:
                    resp = json.load(r)
                break
            except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
                if deadline is not None and time.monotonic() >= deadline - 1:
                    raise DeadlineReached() from e
                if attempt == 3:
                    raise
                time.sleep(5 * 2 ** attempt)
        choice = resp["choices"][0]
        usage = resp.get("usage") or {}
        self.calls += 1
        self.prompt_tokens += usage.get("prompt_tokens", 0)
        self.completion_tokens += usage.get("completion_tokens", 0)
        text = strip_reasoning(choice["message"].get("content") or "")
        meta = {
            "latency": round(time.monotonic() - start, 2),
            "prompt_tokens": usage.get("prompt_tokens"),
            "completion_tokens": usage.get("completion_tokens"),
            "finish_reason": choice.get("finish_reason"),
        }
        return text, meta
