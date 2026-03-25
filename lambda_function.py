import json
import os
import urllib.request
import urllib.error

MIN_SEVERITY = float(os.environ.get("MIN_SEVERITY", "7.0"))
DISCORD_WEBHOOK_URL = os.environ["DISCORD_WEBHOOK_URL"]

# Opcional
DISCORD_USERNAME = os.environ.get("DISCORD_USERNAME", "GuardDuty Security")
DISCORD_AVATAR_URL = os.environ.get(
    "DISCORD_AVATAR_URL",
    "https://icon.icepanel.io/AWS/svg/Security-Identity-Compliance/GuardDuty.svg"
).strip()


def lambda_handler(event, context):
    """
    Espera eventos de EventBridge con shape:
    {
      "source": "aws.guardduty",
      "detail-type": "GuardDuty Finding",
      "account": "...",
      "region": "...",
      "detail": { ... finding ... }
    }
    """

    if event.get("source") != "aws.guardduty":
        return {"statusCode": 400, "body": "Evento no es de GuardDuty"}

    if event.get("detail-type") != "GuardDuty Finding":
        return {"statusCode": 400, "body": "detail-type no es GuardDuty Finding"}

    detail = event.get("detail")
    if not isinstance(detail, dict):
        return {"statusCode": 400, "body": "Falta event.detail o no es JSON válido"}

    severity = _to_float(detail.get("severity"))
    if severity is None:
        return {"statusCode": 400, "body": "No se pudo parsear detail.severity"}

    if severity < MIN_SEVERITY:
        return {
            "statusCode": 200,
            "body": f"Ignorado por severity={severity} < {MIN_SEVERITY}"
        }

    account_id = str(detail.get("accountId") or event.get("account") or "unknown-account")
    region = str(detail.get("region") or event.get("region") or "unknown-region")
    finding_id = str(detail.get("id") or "unknown-finding-id")
    finding_type = str(detail.get("type") or "unknown-type")
    title = str(detail.get("title") or "GuardDuty Finding")
    description = str(detail.get("description") or "Sin descripción")

    payload = _build_discord_payload(
        severity=severity,
        account_id=account_id,
        region=region,
        finding_id=finding_id,
        finding_type=finding_type,
        title=title,
        description=description,
        raw_detail=detail,
    )

    try:
        _send_to_discord(payload)
    except Exception as e:
        return {
            "statusCode": 500,
            "body": f"Error enviando a Discord: {str(e)}"
        }

    return {
        "statusCode": 200,
        "severity": severity,
        "finding_id": finding_id,
        "message": "Finding enviado a Discord",
    }


def _build_discord_payload(
    severity,
    account_id,
    region,
    finding_id,
    finding_type,
    title,
    description,
    raw_detail,
):
    resource = raw_detail.get("resource", {}) or {}
    service = raw_detail.get("service", {}) or {}
    action = service.get("action", {}) or {}

    device_name = _extract_device_name(raw_detail)
    device_ip = _extract_ip(raw_detail)
    user_name = _extract_user(raw_detail)
    source = _extract_source(raw_detail)
    timestamp = raw_detail.get("updatedAt") or raw_detail.get("createdAt")

    if severity >= 8.0:
        color = 15158332  # Red
        emoji = "🔴"
        severity_label = "CRITICAL"
    elif severity >= 7.0:
        color = 16098851  # Orange
        emoji = "🟠"
        severity_label = "HIGH"
    elif severity >= 4.0:
        color = 16776960  # Yellow
        emoji = "🟡"
        severity_label = "MEDIUM"
    else:
        color = 3066993   # Green
        emoji = "🟢"
        severity_label = "LOW"

    embed = {
        "title": f"{emoji} Alerta de Seguridad - {severity_label}",
        "description": f"**{_truncate(title or description or 'GuardDuty Finding', 256)}**",
        "color": color,
        "fields": [
            {
                "name": "Finding ID",
                "value": f"`{_truncate(finding_id, 1024)}`",
                "inline": True
            },
            {
                "name": "Severity",
                "value": severity_label,
                "inline": True
            },
            {
                "name": "Resource",
                "value": f"**{_truncate(device_name, 1024)}**",
                "inline": True
            },
            {
                "name": "Device IP",
                "value": f"`{_truncate(device_ip, 1024)}`",
                "inline": True
            }
        ],
        "footer": {
            "text": "AWS GuardDuty"
        }
    }

    if timestamp:
        embed["timestamp"] = timestamp

    embed["fields"].append({
        "name": "Finding type",
        "value": f"`{_truncate(finding_type, 1024)}`",
        "inline": False
    })

    embed["fields"].append({
        "name": "Account",
        "value": f"`{_truncate(account_id, 1024)}`",
        "inline": True
    })

    embed["fields"].append({
        "name": "Region",
        "value": f"`{_truncate(region, 1024)}`",
        "inline": True
    })

    resource_type = resource.get("resourceType")
    if resource_type:
        embed["fields"].append({
            "name": "Resource type",
            "value": f"`{_truncate(resource_type, 1024)}`",
            "inline": True
        })

    if user_name:
        embed["fields"].append({
            "name": "Username",
            "value": f"`{_truncate(user_name, 1024)}`",
            "inline": True
        })

    if source:
        embed["fields"].append({
            "name": "Source",
            "value": f"`{_truncate(source, 1024)}`",
            "inline": True
        })

    if description:
        embed["fields"].append({
            "name": "Description",
            "value": f"```{_truncate(description, 300)}```",
            "inline": False
        })

    return {
        "username": DISCORD_USERNAME,
        **({"avatar_url": DISCORD_AVATAR_URL} if DISCORD_AVATAR_URL else {}),
        "embeds": [embed]
    }

def _extract_device_name(detail):
    resource = detail.get("resource", {}) or {}

    instance = resource.get("instanceDetails", {}) or {}
    if instance.get("instanceId"):
        return instance["instanceId"]

    eks = resource.get("eksClusterDetails", {}) or {}
    if eks.get("name"):
        return eks["name"]

    kubernetes = resource.get("kubernetesDetails", {}) or {}
    k8s_user = kubernetes.get("kubernetesUserDetails", {}) or {}
    if k8s_user.get("username"):
        return k8s_user["username"]

    access_key = resource.get("accessKeyDetails", {}) or {}
    if access_key.get("userName"):
        return access_key["userName"]

    return resource.get("resourceType", "N/A")


def _extract_ip(detail):
    service = detail.get("service", {}) or {}
    action = service.get("action", {}) or {}

    # Network connection
    net = action.get("networkConnectionAction", {}) or {}
    remote = net.get("remoteIpDetails", {}) or {}
    if remote.get("ipAddressV4"):
        return remote["ipAddressV4"]
    if remote.get("ipAddressV6"):
        return remote["ipAddressV6"]

    # DNS request
    dns = action.get("dnsRequestAction", {}) or {}
    if dns.get("domain"):
        return dns["domain"]

    # AWS API call remote IP
    api = action.get("awsApiCallAction", {}) or {}
    if api.get("remoteIpDetails", {}).get("ipAddressV4"):
        return api["remoteIpDetails"]["ipAddressV4"]

    return "N/A"


def _extract_user(detail):
    resource = detail.get("resource", {}) or {}
    access_key = resource.get("accessKeyDetails", {}) or {}

    if access_key.get("userName"):
        return access_key["userName"]

    principal = access_key.get("principalId")
    if principal:
        return principal

    kubernetes = resource.get("kubernetesDetails", {}) or {}
    k8s_user = kubernetes.get("kubernetesUserDetails", {}) or {}
    if k8s_user.get("username"):
        return k8s_user["username"]

    return None


def _extract_source(detail):
    service = detail.get("service", {}) or {}
    action = service.get("action", {}) or {}

    net = action.get("networkConnectionAction", {}) or {}
    remote = net.get("remoteIpDetails", {}) or {}
    organization = remote.get("organization", {}) or {}

    if organization.get("org"):
        return organization["org"]

    dns = action.get("dnsRequestAction", {}) or {}
    if dns.get("domain"):
        return dns["domain"]

    api = action.get("awsApiCallAction", {}) or {}
    if api.get("serviceName"):
        return api["serviceName"]

    return None

def _send_to_discord(payload):
    data = json.dumps(payload).encode("utf-8")

    req = urllib.request.Request(
        DISCORD_WEBHOOK_URL,
        data=data,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "GuardDutyLambda/1.0 (+AWS Lambda; Python urllib)",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            if resp.status not in (200, 204):
                raise RuntimeError(f"Discord respondió con HTTP {resp.status}")
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTPError {e.code}: {body}") from e
    except urllib.error.URLError as e:
        raise RuntimeError(f"URLError: {str(e)}") from e


def _to_float(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _truncate(text, max_len):
    if text is None:
        return ""
    text = str(text)
    if len(text) <= max_len:
        return text
    return text[: max_len - 3] + "..."


def _severity_to_color(severity):
    # Colores en decimal para embeds de Discord
    if severity >= 8.0:
        return 0xFF0000  # rojo
    if severity >= 7.0:
        return 0xFFA500  # naranja
    if severity >= 4.0:
        return 0xFFFF00  # amarillo
    return 0x00BFFF      # azul
