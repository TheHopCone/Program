import requests
import json
import os

OPENAI_API_KEY = "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"

OPENAI_API_URL = "https://api.openai.com/v1/chat/completions"
DEFAULT_MODEL = "gpt-3.5-turbo"  # Або інша модель, наприклад "gpt-4o-mini"


def analyze_log_with_openai(log_json_string: str) -> tuple[str | None, str | None]:
    """
    Відправляє JSON лог на аналіз до OpenAI API (Chat Completions).
    Повертає (текст_аналізу, None) у разі успіху, або (None, текст_помилки) у разі невдачі.
    """
    if not OPENAI_API_KEY:
        return None, "API ключ OpenAI не налаштовано (змінна середовища OPENAI_API_KEY)."

    headers = {
        "Authorization": f"Bearer {OPENAI_API_KEY}",
        "Content-Type": "application/json",
    }

    system_prompt = (
        "Ти – досвідчений аналітик кібербезпеки. Тобі надано JSON лог події, "
        "виявленої системою IDS/IPS. Будь ласка, проаналізуй його та надай: \n"
        "1. Стислий опис виявленої події та її потенційної загрози (1-2 речення).\n"
        "2. Можливий рівень ризику (наприклад, Низький, Середній, Високий, Критичний) на твою думку.\n"
        "3. Рекомендації щодо подальших дій або перевірки (1-3 короткі пункти).\n"
        "Відповідь має бути чіткою, структурованою, лаконічною та українською мовою."
    )

    try:
        json.loads(log_json_string)
    except json.JSONDecodeError:
        return None, "Наданий рядок логу не є валідним JSON."

    user_prompt_content = f"Проаналізуй наступний лог події IDS/IPS:\n```json\n{log_json_string}\n```"

    payload = {
        "model": DEFAULT_MODEL,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt_content}
        ],
        "temperature": 0.3,
        "max_tokens": 350,
        "top_p": 1.0,
        "frequency_penalty": 0.0,
        "presence_penalty": 0.0
    }

    try:
        response = requests.post(OPENAI_API_URL, headers=headers, json=payload, timeout=45)  # Збільшено таймаут
        response.raise_for_status()

        response_data = response.json()

        if response_data.get("choices") and len(response_data["choices"]) > 0:
            message_content = response_data["choices"][0].get("message", {}).get("content")
            if message_content:
                return message_content.strip(), None
            else:
                return None, "Відповідь від OpenAI API не містить тексту аналізу в очікуваному форматі."
        elif response_data.get("error"):
            error_details = response_data["error"].get("message", "Невідома помилка API.")
            return None, f"Помилка OpenAI API: {error_details}"
        else:
            return None, f"Неочікувана структура відповіді від OpenAI API: {response_data}"

    except requests.exceptions.Timeout:
        return None, "Помилка: Час очікування відповіді від OpenAI API минув."
    except requests.exceptions.RequestException as e:
        return None, f"Помилка мережі або запиту до OpenAI API: {e}"
    except json.JSONDecodeError:
        return None, "Помилка: Не вдалося розпарсити відповідь від OpenAI API як JSON."
    except Exception as e:
        return None, f"Неочікувана помилка при взаємодії з OpenAI API: {e}"


if __name__ == '__main__':
    if not OPENAI_API_KEY:
        print("Будь ласка, встановіть змінну середовища OPENAI_API_KEY або вкажіть ключ у файлі.")
    else:
        sample_log = {
            "id": "live_agg_1",
            "count": 5,
            "last_timestamp": "2023-10-27 12:34:56.789",
            "severity": "HIGH",
            "src_ip": "192.168.1.100", "src_port": "54321",
            "dst_ip": "104.26.10.231", "dst_port": "443",
            "protocol": "TCP", "ioc_type": "IP",
            "indicator": "104.26.10.231",
            "feed_source": "URLhaus (abuse.ch)",
            "description": "URLhaus: malware_download (botnet_cc)",
            "reference": "https://urlhaus.abuse.ch/url/12345/"
        }
        sample_log_json_string = json.dumps(sample_log, indent=2)

        print("Відправка тестового логу на аналіз...")
        analysis, error = analyze_log_with_openai(sample_log_json_string)

        if error:
            print(f"\nПомилка аналізу:\n{error}")
        elif analysis:
            print(f"\nРезультат аналізу:\n{analysis}")
        else:
            print("\nНе вдалося отримати ані результат, ані помилку.")
