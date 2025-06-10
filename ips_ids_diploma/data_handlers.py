import requests
import csv
import io
import json
import os
import datetime
from urllib.parse import urlparse
from config import (
    LOG_DIR, SESSION_STATE_FILE, FEED_DIR,
    BAD_IPS_FILE as LOCAL_BAD_IPS_FILE,
    BAD_DOMAINS_FILE as LOCAL_BAD_DOMAINS_FILE,
    BASE_DIR,
)

GENERATED_FEEDS_DIR = os.path.join(FEED_DIR, "generated")
FEEDS_CONFIG_FILE = os.path.join(BASE_DIR, "feeds_config.json")

os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(FEED_DIR, exist_ok=True)
os.makedirs(GENERATED_FEEDS_DIR, exist_ok=True)

SEVERITY_ORDER = {"UNKNOWN": 0, "INFO": 1, "LOW": 2, "MEDIUM": 3, "HIGH": 4, "CRITICAL": 5}
DEFAULT_USER_AGENT = 'SimpleIDS/1.0 (Educational Project)'


def _make_request(url, feed_name):
    log_messages = []
    try:
        headers = {'User-Agent': DEFAULT_USER_AGENT}
        response = requests.get(url, timeout=20, headers=headers)
        response.raise_for_status()
        return response.text, log_messages
    except requests.exceptions.RequestException as e_req:
        log_messages.append(f"ERROR ({feed_name}): Помилка мережі {url}: {e_req}")
    except Exception as e_gen:
        log_messages.append(f"ERROR ({feed_name}): Загальна помилка запиту {url}: {e_gen}")
    return None, log_messages


def _write_indicators_to_csv(filepath, indicators_data, feed_name_for_log):
    fieldnames = ['indicator', 'severity', 'description', 'source_feed', 'reference', 'type']
    try:
        with open(filepath, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for data_row in indicators_data:
                row_to_write = {field: data_row.get(field, '') for field in fieldnames}
                writer.writerow(row_to_write)
        return f"INFO: Дані з '{feed_name_for_log}' збережено у '{os.path.basename(filepath)}'."
    except Exception as e:
        return f"ERROR: Не вдалося зберегти '{feed_name_for_log}' у '{os.path.basename(filepath)}': {e}"


def _get_aggregation_key_for_history(threat_json_data):
    """Формує унікальний ключ для агрегації історичних подій на основі JSON даних."""
    key_tuple = (
        threat_json_data.get("src_ip", "N/A"),
        threat_json_data.get("dst_ip", "N/A"),
        threat_json_data.get("protocol", "N/A"),
        threat_json_data.get("ioc_type", "N/A"),
        threat_json_data.get("indicator", "N/A"),
        threat_json_data.get("feed_source", "N/A"),
    )
    return key_tuple


def parse_csv_online_urlhaus(text_content, feed_config):
    ips_found = []
    domains_found = []
    log_messages = []
    feed_name = feed_config["name"]

    try:
        csv_content = "\n".join([line for line in text_content.splitlines() if not line.strip().startswith('#')])
        csvfile = io.StringIO(csv_content)
        reader = csv.reader(csvfile)

        for row_num, row in enumerate(reader):
            if len(row) < 8: continue
            url_str, status, threat_type, tags, urlhaus_link = row[2], row[3], row[5], row[6], row[7]
            if status != 'online': continue

            desc = f"URLhaus: {threat_type} ({tags if tags else 'N/A'})"
            ref = urlhaus_link

            sev = feed_config.get("default_severity_domain", "HIGH")
            if "banker" in threat_type.lower() or "ransomware" in threat_type.lower() or "rat" in threat_type.lower():
                sev = "CRITICAL"

            try:
                parsed_url = urlparse(url_str)
                hostname = parsed_url.hostname
                if hostname:
                    is_ip_address = False
                    try:
                        parts = hostname.split('.')
                        if len(parts) == 4 and all(0 <= int(p) <= 255 for p in parts):
                            is_ip_address = True
                    except (ValueError, TypeError):
                        pass

                    if is_ip_address:
                        ips_found.append({
                            'indicator': hostname, 'type': 'ip',
                            'severity': feed_config.get("default_severity_ip", "HIGH"),
                            'description': desc, 'source_feed': feed_name, 'reference': ref
                        })
                    else:
                        domains_found.append({
                            'indicator': hostname, 'type': 'domain', 'severity': sev,
                            'description': desc, 'source_feed': feed_name, 'reference': ref
                        })
            except Exception as e_parse:
                log_messages.append(f"WARNING ({feed_name}): Помилка парсингу URL '{url_str}': {e_parse}")

        log_messages.append(
            f"INFO: Оброблено {feed_name}, знайдено {len(ips_found)} IP та {len(domains_found)} доменів.")

    except csv.Error as e_csv:
        log_messages.append(f"ERROR ({feed_name}): Помилка парсингу CSV: {e_csv}")
    except Exception as e_gen:
        log_messages.append(f"ERROR ({feed_name}): Загальна помилка обробки: {e_gen}")

    return ips_found, domains_found, log_messages


FEED_PARSERS = {
    "csv_online_urlhaus": parse_csv_online_urlhaus,
}


def update_local_feed_files():
    all_log_messages = []
    try:
        with open(FEEDS_CONFIG_FILE, 'r', encoding='utf-8') as f_config:
            feeds_configurations = json.load(f_config)
    except Exception as e:
        all_log_messages.append(f"CRITICAL ERROR: Не вдалося завантажити '{FEEDS_CONFIG_FILE}': {e}")
        return all_log_messages

    for feed_conf in feeds_configurations:
        if not feed_conf.get("enabled", False):
            all_log_messages.append(f"INFO: Фід '{feed_conf['name']}' вимкнено.")
            continue

        feed_type = feed_conf.get("type")
        parser_func = FEED_PARSERS.get(feed_type)
        if not parser_func:
            all_log_messages.append(f"WARNING: Немає парсера для типу '{feed_type}' (фід: {feed_conf['name']}).")
            continue

        response_text, req_log_msgs = _make_request(feed_conf["url"], feed_conf["name"])
        all_log_messages.extend(req_log_msgs)
        if not response_text: continue

        ips_data, domains_data, parser_log_msgs = parser_func(response_text, feed_conf)
        all_log_messages.extend(parser_log_msgs)

        if ips_data and feed_conf.get("output_ips_file"):
            filepath_ips = os.path.join(GENERATED_FEEDS_DIR, feed_conf["output_ips_file"])
            log_msg = _write_indicators_to_csv(filepath_ips, ips_data, feed_conf["name"] + " (Витягнуті IP)")
            all_log_messages.append(log_msg)

        if domains_data and feed_conf.get("output_domains_file"):
            filepath_domains = os.path.join(GENERATED_FEEDS_DIR, feed_conf["output_domains_file"])
            log_msg = _write_indicators_to_csv(filepath_domains, domains_data,
                                               feed_conf["name"] + " (Витягнуті Домени)")
            all_log_messages.append(log_msg)

    all_log_messages.append("INFO: Оновлення локальних файлів фідів завершено.")
    return all_log_messages


def load_all_feeds_data():
    all_log_messages = []
    log_update_msgs = update_local_feed_files()
    all_log_messages.extend(log_update_msgs)

    compiled_feeds_data = {}

    try:
        with open(LOCAL_BAD_IPS_FILE, "r", encoding='utf-8') as f:
            for line in f:
                ip = line.strip()
                if ip and not ip.startswith("#") and ip not in compiled_feeds_data:
                    compiled_feeds_data[ip] = {'type': 'ip', 'severity': 'MEDIUM', 'description': 'Локальний список IP',
                                               'source_feed': os.path.basename(LOCAL_BAD_IPS_FILE), 'reference': ''}
            all_log_messages.append(f"INFO: Завантажено IP з '{os.path.basename(LOCAL_BAD_IPS_FILE)}'.")
    except FileNotFoundError:
        all_log_messages.append(f"INFO: Файл '{os.path.basename(LOCAL_BAD_IPS_FILE)}' не знайдено.")
    except Exception as e:
        all_log_messages.append(f"ERROR: Помилка читання '{os.path.basename(LOCAL_BAD_IPS_FILE)}': {e}")

    try:
        with open(LOCAL_BAD_DOMAINS_FILE, "r", encoding='utf-8') as f:
            for line in f:
                domain = line.strip()
                if domain and not domain.startswith("#") and domain not in compiled_feeds_data:
                    compiled_feeds_data[domain] = {'type': 'domain', 'severity': 'MEDIUM',
                                                   'description': 'Локальний список доменів',
                                                   'source_feed': os.path.basename(LOCAL_BAD_DOMAINS_FILE),
                                                   'reference': ''}
            all_log_messages.append(f"INFO: Завантажено домени з '{os.path.basename(LOCAL_BAD_DOMAINS_FILE)}'.")
    except FileNotFoundError:
        all_log_messages.append(f"INFO: Файл '{os.path.basename(LOCAL_BAD_DOMAINS_FILE)}' не знайдено.")
    except Exception as e:
        all_log_messages.append(f"ERROR: Помилка читання '{os.path.basename(LOCAL_BAD_DOMAINS_FILE)}': {e}")

    for filename in os.listdir(GENERATED_FEEDS_DIR):
        if filename.endswith(".csv") and filename.startswith("urlhaus_generated_"):
            filepath = os.path.join(GENERATED_FEEDS_DIR, filename)
            try:
                with open(filepath, 'r', newline='', encoding='utf-8') as csvfile:
                    reader = csv.DictReader(csvfile)
                    for row in reader:
                        indicator = row.get('indicator')
                        if not indicator: continue

                        indicator_type = row.get('type', 'unknown')
                        if indicator_type == 'unknown':
                            if filename.endswith("_ips.csv"):
                                indicator_type = 'ip'
                            elif filename.endswith("_domains.csv"):
                                indicator_type = 'domain'

                        data = {
                            'type': indicator_type,
                            'severity': row.get('severity', 'UNKNOWN'),
                            'description': row.get('description', ''),
                            'source_feed': row.get('source_feed', os.path.basename(filename)),
                            'reference': row.get('reference', '')
                        }

                        existing_entry = compiled_feeds_data.get(indicator)
                        if not existing_entry or \
                                (SEVERITY_ORDER.get(data['severity'], 0) > SEVERITY_ORDER.get(
                                    existing_entry.get('severity', 'UNKNOWN'), 0)):
                            compiled_feeds_data[indicator] = data
                all_log_messages.append(f"INFO: Завантажено дані з '{filename}'.")
            except Exception as e:
                all_log_messages.append(f"ERROR: Помилка читання '{filename}': {e}")

    final_bad_ips_info = {}
    final_bad_domains_info = {}

    for indicator, data in compiled_feeds_data.items():
        if data['type'] == 'ip':
            final_bad_ips_info[indicator] = data
        elif data['type'] == 'domain':
            final_bad_domains_info[indicator] = data

    return final_bad_ips_info, final_bad_domains_info, all_log_messages


def write_alert_to_daily_log(threat_json_data):
    try:
        today_date_str = datetime.date.today().strftime("%Y-%m-%d")
        log_file_path = os.path.join(LOG_DIR, f"alerts_{today_date_str}.log")
        with open(log_file_path, "a", encoding="utf-8") as f_log:
            json.dump(threat_json_data, f_log, ensure_ascii=False)
            f_log.write("\n")
        return None
    except Exception as e:
        return f"ERROR: Помилка запису алерту в лог: {e}"


def load_history_log_for_date_str(date_str):
    log_messages = []
    aggregated_historical_threats = {}
    loaded_threat_details_for_treeview = {}

    historical_aggregated_id_counter = 0

    log_file_path = os.path.join(LOG_DIR, f"alerts_{date_str}.log")

    if os.path.exists(log_file_path):
        try:
            with open(log_file_path, "r", encoding="utf-8") as f_log:
                for line_num, line in enumerate(f_log, 1):
                    line = line.strip()
                    if not line: continue

                    try:
                        threat_json_data = json.loads(line)
                        aggregation_key = _get_aggregation_key_for_history(threat_json_data)
                        current_event_timestamp = threat_json_data.get("timestamp", "N/A")

                        if aggregation_key in aggregated_historical_threats:
                            agg_entry = aggregated_historical_threats[aggregation_key]
                            agg_entry['count'] += 1
                            if current_event_timestamp > agg_entry['last_timestamp']:
                                agg_entry['last_timestamp'] = current_event_timestamp
                                agg_entry['full_json_details'] = threat_json_data
                        else:
                            historical_aggregated_id_counter += 1
                            table_iid = f"hist_agg_{historical_aggregated_id_counter}"

                            aggregated_historical_threats[aggregation_key] = {
                                'count': 1,
                                'last_timestamp': current_event_timestamp,
                                'table_iid': table_iid,
                                'severity': threat_json_data.get("severity", "UNKNOWN"),
                                'src_ip': threat_json_data.get("src_ip", "N/A"),
                                'src_port': threat_json_data.get("src_port", "N/A"),
                                'dst_ip': threat_json_data.get("dst_ip", "N/A"),
                                'dst_port': threat_json_data.get("dst_port", "N/A"),
                                'protocol': threat_json_data.get("protocol", "N/A"),
                                'ioc_type': threat_json_data.get("ioc_type", "N/A"),
                                'indicator': threat_json_data.get("indicator", "N/A"),
                                'feed_source': threat_json_data.get("feed_source", "N/A"),
                                'description': threat_json_data.get("description", "N/A"),
                                'reference': threat_json_data.get("reference", ""),
                                'full_json_details': threat_json_data
                            }

                    except json.JSONDecodeError as je:
                        log_messages.append(
                            f"ERROR (Історія): Помилка парсингу JSON '{os.path.basename(log_file_path)}' (р.{line_num}): {je}.")
                    except Exception as ex_inner:
                        log_messages.append(
                            f"ERROR (Історія): Обробка рядка {line_num} з '{os.path.basename(log_file_path)}': {ex_inner}")

            final_loaded_threats_data = []
            for agg_key, agg_data_entry in aggregated_historical_threats.items():
                display_tuple = (
                    agg_data_entry['table_iid'].split('_')[-1],
                    agg_data_entry['count'],
                    agg_data_entry['last_timestamp'],
                    agg_data_entry['severity'],
                    agg_data_entry['src_ip'],
                    agg_data_entry['src_port'],
                    agg_data_entry['dst_ip'],
                    agg_data_entry['dst_port'],
                    agg_data_entry['protocol'],
                    agg_data_entry['ioc_type'],
                    agg_data_entry['indicator'],
                    agg_data_entry['feed_source'],
                    agg_data_entry['description']
                )
                final_loaded_threats_data.append((agg_data_entry['table_iid'], display_tuple, "Історичний Агрегат"))
                loaded_threat_details_for_treeview[agg_data_entry['table_iid']] = json.dumps(
                    agg_data_entry['full_json_details'], ensure_ascii=False)

            if historical_aggregated_id_counter > 0:
                log_messages.append(
                    f"INFO: Історія за {date_str} завантажена та агрегована. Унікальних груп подій: {historical_aggregated_id_counter}")
            else:
                log_messages.append(f"INFO: Файл історії за {date_str} порожній або не містить коректних JSON записів.")

        except Exception as e_file:
            log_messages.append(
                f"CRITICAL ERROR (Історія): Не вдалося прочитати файл історії '{log_file_path}': {e_file}")
            final_loaded_threats_data = []
            loaded_threat_details_for_treeview = {}
            historical_aggregated_id_counter = 0
    else:
        log_messages.append(f"INFO: Файл історії '{log_file_path}' не знайдено.")
        final_loaded_threats_data = []
        loaded_threat_details_for_treeview = {}
        historical_aggregated_id_counter = 0

    return final_loaded_threats_data, loaded_threat_details_for_treeview, historical_aggregated_id_counter, log_messages


def save_session_state_to_file(session_data_dict):
    try:
        with open(SESSION_STATE_FILE, "w", encoding="utf-8") as f_session:
            json.dump(session_data_dict, f_session, ensure_ascii=False, indent=4)
        return "INFO: Стан сесії збережено."
    except Exception as e:
        return f"ERROR: Помилка збереження сесії: {e}"


def analyze_indicator_with_openai(indicator, ioc_type):
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY",
                               "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")
    HIGH_RISK_KEYWORDS = ["malware distribution", "c&c server", "command and control", "phishing site", "ransomware",
                          "botnet node", "actively malicious", "known attacker", "compromised server",
                          "high confidence threat", "critical risk"]
    MEDIUM_RISK_KEYWORDS = ["suspicious activity", "potential threat", "spam source", "brute-force attacker",
                            "scanning activity", "medium risk"]

    if not OPENAI_API_KEY or "YOUR_API_KEY" in OPENAI_API_KEY:
        return {'description': "OpenAI API ключ не налаштовано.", 'should_block': False,
                'reason': "API Key not configured.", 'error': "API Key not configured."}

    prompt = f"Analyze the security risk of the following IoC (Indicator of Compromise):\nType: {ioc_type}\nIndicator: {indicator}\nIs this indicator known to be malicious or associated with cyber threats like malware, phishing, C&C servers, botnets, ransomware, or other significant security risks? Provide a brief assessment (max 50 words) and conclude with 'Decision: Block' if it's a high-confidence threat that should be blocked, 'Decision: Monitor' for suspicious but not definitively malicious, or 'Decision: Safe' if it appears safe. If blocking, state the primary reason briefly."

    headers = {"Authorization": f"Bearer {OPENAI_API_KEY}", "Content-Type": "application/json"}
    data = {"model": "gpt-3.5-turbo", "messages": [{"role": "user", "content": prompt}], "max_tokens": 100,
            "temperature": 0.3}

    ai_description, block_reason, error_message = "Аналіз ШІ недоступний або сталася помилка.", "Не визначено ШІ.", None
    should_block_auto = False

    try:
        response = requests.post("https://api.openai.com/v1/chat/completions", headers=headers, json=data, timeout=25)
        response.raise_for_status()
        response_json = response.json()
        if response_json.get("choices") and len(response_json["choices"]) > 0:
            ai_description = response_json["choices"][0].get("message", {}).get("content", "").strip()
        else:
            ai_description = "Відповідь від ШІ не містить очікуваних даних.";
            error_message = "No choices in AI response."
        response_lower = ai_description.lower()
        if "decision: block" in response_lower:
            should_block_auto = True
        elif any(keyword in response_lower for keyword in HIGH_RISK_KEYWORDS):
            should_block_auto = True
        if should_block_auto:
            block_reason = "Високий ризик згідно аналізу ШІ."
            if "reason:" in response_lower:
                try:
                    block_reason = ai_description[response_lower.rfind("reason:") + len("reason:"):].split('.')[
                        0].strip()
                except:
                    pass
            elif "decision: block" in response_lower:
                try:
                    block_reason = ai_description[:response_lower.find("decision: block")].strip();
                except:
                    pass
                if not block_reason: block_reason = "Рекомендовано ШІ."
        elif "decision: monitor" in response_lower or any(
                keyword in response_lower for keyword in MEDIUM_RISK_KEYWORDS):
            block_reason = "Підозріла активність, рекомендовано моніторинг."
        elif "decision: safe" in response_lower:
            block_reason = "Визначено як безпечний за аналізом ШІ."
    except requests.exceptions.RequestException as e:
        ai_description = f"Помилка запиту до OpenAI API: {e}";
        error_message = str(e)
    except Exception as e_openai:
        ai_description = f"Неочікувана помилка при роботі з OpenAI API: {e_openai}";
        error_message = str(e_openai)
    return {'description': ai_description, 'should_block': should_block_auto, 'reason': block_reason,
            'error': error_message}


def load_session_state_from_file():
    log_messages = []
    session_data = {}
    if os.path.exists(SESSION_STATE_FILE):
        try:
            with open(SESSION_STATE_FILE, "r", encoding="utf-8") as f_session:
                loaded_json = json.load(f_session)
                if isinstance(loaded_json, dict): session_data = loaded_json
            if session_data and session_data.get("all_threat_data"):
                log_messages.append(f"INFO: Завантажено {len(session_data['all_threat_data'])} записів з сесії.")
            elif session_data:
                log_messages.append(
                    f"INFO: Файл сесії '{os.path.basename(SESSION_STATE_FILE)}' порожній або без 'all_threat_data'.")
            else:
                log_messages.append(f"INFO: Файл сесії '{os.path.basename(SESSION_STATE_FILE)}' порожній/некоректний.")
        except json.JSONDecodeError as je:
            log_messages.append(f"ERROR: Помилка JSON сесії '{os.path.basename(SESSION_STATE_FILE)}': {je}.")
        except Exception as e:
            log_messages.append(f"ERROR: Загальна помилка сесії '{os.path.basename(SESSION_STATE_FILE)}': {e}.")
    else:
        log_messages.append(f"INFO: Файл сесії '{os.path.basename(SESSION_STATE_FILE)}' не знайдено.")
    return session_data, log_messages
