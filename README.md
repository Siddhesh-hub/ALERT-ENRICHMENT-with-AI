# AI Alert Enrichment Lambda

An AWS Lambda function that enriches incoming security alerts with Google Gemini and returns a structured, analyst-friendly response.

This project is intentionally lightweight right now: the repository is centered around a single `lambda_function.py` so it is easy to read, demo, and extend.

## What It Does

The Lambda accepts a raw alert payload, sends it to Gemini for contextual enrichment, and returns:

- severity assessment
- likely impact
- recommended response actions
- related attack or anomaly patterns
- execution telemetry such as model used, retries, duration, and token usage when available

## Why This Project Is Useful

Security alerts are often noisy, short, and hard to triage quickly. This Lambda adds an AI-generated first layer of context so analysts, demo viewers, or downstream automations get something more actionable than a bare event message.

## Lambda Features

- Single-file Lambda implementation for easy review and deployment
- Gemini model fallback strategy across multiple candidate models
- Automatic retry handling for busy or rate-limited models
- JSON-only enrichment flow for structured downstream usage
- Clean local terminal output for demos and development
- Execution log block with model used
- Execution log block with model version
- Execution log block with response ID
- Execution log block with duration and retry attempts
- Execution log block with token usage when returned by the API
- Graceful failure responses with error details
- Local `.env` loading for quick development

## Input Example

```json
{
  "alert": {
    "id": "alert-001",
    "message": "Suspicious login detected",
    "timestamp": "2026-04-21T12:00:00Z"
  }
}
```

## Output Highlights

The Lambda returns a JSON body with:

- `enriched_alert`
- `execution_log`
- `message`

The `execution_log` is especially useful for debugging and demos because it shows which model answered, how long the request took, and whether retries happened before success.

## Repo Structure

```text
.
|-- lambda_function.py
|-- requirements.txt
|-- Dockerfile
|-- .env.example
|-- README.md
```

## Quick Start

1. Create and activate a virtual environment.
2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Create a local environment file:

```bash
cp .env.example .env
```

PowerShell:

```powershell
Copy-Item .env.example .env
```

4. Add your Google API key to `.env`:

```env
GOOGLE_API_KEY=your_google_ai_api_key_here
```

5. Run the Lambda file locally:

```bash
python lambda_function.py
```

## Deployment Notes

You can deploy this as a standard Python Lambda or package it with the included `Dockerfile`.

Lambda handler:

```text
lambda_function.lambda_handler
```

## Pros

- Very easy to understand because the core logic lives in one file
- Good demo project for AI-assisted SOC or alert triage workflows
- Returns structured enrichment instead of freeform text
- Built-in retry and fallback behavior makes it more resilient during model pressure
- Execution logs make troubleshooting much easier

## Cons

- Single-file structure is great for simplicity, but not ideal once the project grows
- AI output quality depends on prompt design and model availability
- Token and metadata fields may vary depending on Gemini API behavior
- Not yet wired to a real upstream alert source or downstream ticketing/SIEM action
- No persistence, auth layer, or production deployment IaC in the current minimal version

## Screenshots

You can add screenshots here later. A simple pattern is:

```md
## Screenshots

<img width="1772" height="562" alt="image" src="https://github.com/user-attachments/assets/ae92cf55-0e24-4de0-b34a-ff7dfde203da" />
<img width="993" height="432" alt="image" src="https://github.com/user-attachments/assets/73ae3ddc-8e16-4cff-b3fb-613adf398fdd" />
<img width="1456" height="623" alt="image" src="https://github.com/user-attachments/assets/30806e45-057d-4baf-9254-6f19684d6602" />

```

Suggested location:

```text
assets/screenshots/
```

## Good Next Extensions

- Connect an upstream alert source such as CloudWatch, EventBridge, GuardDuty, or a webhook
- Send downstream enriched results to Slack, Jira, ServiceNow, or a SIEM
- Split the code into modules once prompt logic, adapters, and validation grow
- Add infrastructure files for repeatable AWS deployment

## Environment Variable

- `GOOGLE_API_KEY`: required for Gemini API access
