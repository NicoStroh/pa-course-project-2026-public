# LLM Policy

## Development

Using LLMs as part of the analyzer is optional.  
Submitted analyzers must make LLM calls through the course API in
`analyzer.llm`. Do not call provider SDKs or HTTP endpoints directly from the
rest of your analyzer.

Use `query_llm`:

```python
from analyzer.llm import query_llm

answer = query_llm(
    "Summarize the security-relevant behavior of this function.",
    instructions="You are helping analyze Python code for vulnerabilities.",
)
```

By default, this implementation calls OpenAI `gpt-5-nano` and uses `minimal` reasoning effort.  
You can override the reasoning effort by passing a different value for the `reasoning_effort` parameter.  
The implementation reads these environment variables:

- `OPENAI_API_KEY`
- `OPENAI_BASE_URL`, defaulting to `https://api.openai.com/v1`
- `OPENAI_MODEL`, defaulting to `gpt-5-nano`

During local development, set `OPENAI_API_KEY` to your own development key. You can create your own key at https://platform.openai.com.  
You can create a `.env` file in the `student/` directory with the line `OPENAI_API_KEY=sk-...`.
Then it will be automatically loaded into the container when you run `make` commands from the `student/` directory.
Be careful not to commit your API key to version control or to include it in your submission.  
You may also point `OPENAI_BASE_URL` at a compatible local endpoint.  
Keep your analyzer code using `query_llm` either way.

## Grading

During grading:

- LLM calls must go through `analyzer.llm.query_llm`.
- The grader points `query_llm` at the course proxy with environment variables.
- The only allowed model is `gpt-5-nano`.
- Student containers do not receive the teacher API key directly.
- Outbound network access is blocked. The container
  runs on an internal Docker network where the only intended reachable service
  is the local course proxy.
- The budget is `$0.01` per hidden vulnerability (each target can have 1 or more vulnerabilities of any vulnerability type).
 (so e.g. for a target with 3 vulnerabilities, the budget for analyzing that target is $0.03).
- The proxy records full prompt and response transcripts, usage metadata,
  timestamps, request ids, and rejection reasons.

Approaches that bypass `query_llm`, depend on another provider, use another
model, or rely on provider-specific response formats may fail during grading.
