# GuardDuty to Discord Alerts (EventBridge + Lambda)

This project sends **AWS GuardDuty findings** to a **Discord channel** using:

1. GuardDuty (finding source)
2. EventBridge rule (filter + trigger)
3. Lambda function (`lambda_function.py`) (format + send to Discord webhook)

## Files in this repo

- `lambda_function.py`: Lambda handler and Discord payload logic
- `event-bridge-trigger.json`: EventBridge event pattern (only GuardDuty findings with severity >= 7)

## 1) Activate GuardDuty

GuardDuty must be enabled in the AWS account/region where you want detections.

1. Open **AWS Console** -> **GuardDuty**.
2. Select the target region.
3. Click **Get started** / **Enable GuardDuty**.
4. If you use AWS Organizations, optionally configure delegated admin and member accounts.

Tip: If you need this in multiple regions, enable GuardDuty in each region.

## 2) Create the Lambda function

1. Open **AWS Console** -> **Lambda** -> **Create function**.
2. Choose **Author from scratch**.
3. Suggested values:
   - Function name: `guardduty-discord-alerts`
   - Runtime: `Python 3.11` (or newer Python runtime supported by Lambda)
4. For permissions, use or create an execution role with basic CloudWatch Logs permissions (for example, `AWSLambdaBasicExecutionRole`).
5. In the code editor, replace the default code with the content of `lambda_function.py` from this repository.
6. Set handler to:

```text
lambda_function.lambda_handler
```

7. Deploy the function.

## 3) Add Lambda environment variables

In Lambda -> **Configuration** -> **Environment variables**, add:

### Required

- `DISCORD_WEBHOOK_URL` = your Discord webhook URL

### Optional

- `DISCORD_USERNAME` (default: `GuardDuty Security`)
- `DISCORD_AVATAR_URL` (default is a GuardDuty icon URL in code)

### How to obtain `DISCORD_WEBHOOK_URL`

Create a webhook in your Discord server/channel and copy the webhook URL.

For a step by step look a t the [Discord official guide](https://support.discord.com/hc/en-us/articles/228383668-Intro-to-Webhooks)

## 4) Create the EventBridge trigger

Use the event pattern from `event-bridge-trigger.json`.

### Event pattern

```json
{
  "source": ["aws.guardduty"],
  "detail-type": ["GuardDuty Finding"],
  "detail": {
    "severity": [{
      "numeric": [">=", 7]
    }]
  }
}
```
Note: `7` is the minimum severity that will trigger the lambda function. For more information about GuardDuty findings severity look the ][official aws documentation](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_findings-severity.html)

### Console steps

1. Open **Amazon EventBridge** -> **Rules** -> **Create rule**.
2. Name it, for example: `guardduty-high-severity-to-discord`.
3. Event bus: `default`.
4. Rule type: **Rule with an event pattern**.
5. Build method: **Custom pattern (JSON editor)**.
6. Paste the JSON pattern above (or from `event-bridge-trigger.json`).
7. Target type: **AWS service** -> **Lambda function**.
8. Select your Lambda: `guardduty-discord-alerts`.
9. Create rule.

EventBridge usually adds invoke permission on the Lambda target automatically when created from the console.

## 5) Validate end-to-end

1. In GuardDuty, generate a sample finding (or wait for a real finding).
2. Confirm EventBridge rule metrics show invocations.
3. Check Lambda **Monitor** -> **CloudWatch Logs** for execution results.
4. Verify the Discord channel receives the alert embed.

## Notes

- Current EventBridge rule filters only findings with severity `>= 7`.
