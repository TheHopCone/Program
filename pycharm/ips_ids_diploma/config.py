# --- START OF FILE config.py ---
import os
import sys
import os

def resource_path(relative_path):
    """ Отримати абсолютний шлях до ресурсу, працює для розробки та для PyInstaller/cx_Freeze """
    try:
        # PyInstaller створює тимчасову папку та зберігає шлях у _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        # Для розробки або якщо не зібрано PyInstaller
        base_path = os.path.abspath(os.path.dirname(sys.argv[0])) # Використовуємо шлях до головного скрипта
    return os.path.join(base_path, relative_path)

# Приклад використання в config.py:
# BASE_DIR тепер не потрібен, якщо всі шляхи відносні до resource_path
FEED_DIR_NAME = "feeds"
LOG_DIR_NAME = "logs"
# ...
FEEDS_CONFIG_FILE = resource_path("feeds_config.json")
FEED_DIR = resource_path(FEED_DIR_NAME) # Папка feeds буде поруч з exe
LOG_DIR = resource_path(LOG_DIR_NAME)   # Папка logs буде поруч з exe
# --- Кольорові константи для тем ---
DARK_BACKGROUND = "#242424"
DARK_WIDGET_BG = "#2B2B2B"
DARK_TEXT = "white"
DARK_SELECTED_ROW = "#1F6AA5"
DARK_HEADER_BG = "#303030"

LIGHT_BACKGROUND = "#EBEBEB"
LIGHT_WIDGET_BG = "#FFFFFF"
LIGHT_TEXT = "black"
LIGHT_SELECTED_ROW = "#3470A3"
LIGHT_HEADER_BG = "#DCDCDC"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

FEED_DIR = os.path.join(BASE_DIR, "feeds")
BAD_IPS_FILE = os.path.join(FEED_DIR, "bad_ips.txt") # Для користувацьких IP
BAD_DOMAINS_FILE = os.path.join(FEED_DIR, "bad_domains.txt") # Для користувацьких доменів
LOG_DIR = os.path.join(BASE_DIR, "logs")
SESSION_STATE_FILE = os.path.join(BASE_DIR, "session_state.json")
FEEDS_CONFIG_FILE = os.path.join(BASE_DIR, "feeds_config.json") # Конфігурація зовнішніх фідів

PROTO_MAP = {1: "ICMP", 6: "TCP", 17: "UDP"}

# --- Налаштування таблиці загроз ---
# Ключі тут будуть використовуватися для пошуку "ключ:значення"
# та для доступу до даних у кортежах
THREAT_TABLE_COLS_DISPLAY = {
    "id": "id",                 # ID агрегованої події або історичного запису
    "count": "К-сть",           # Кількість агрегованих подій
    "last_timestamp": "Останній Час", # Час останньої події в агрегації
    "severity": "severity",       # Рівень серйозності
    "src_ip": "src_ip",
    "src_port": "src_port",
    "dst_ip": "dst_ip",
    "dst_port": "dst_port",
    "protocol": "protocol",
    "ioc_type": "ioc_type",      # Тип індикатора (IP, DOMAIN)
    "indicator": "indicator",    # Сам індикатор
    "feed_source": "feed_source",  # Джерело фіда
    "description": "description"   # Опис загрози
}

# Внутрішні імена та ПОРЯДОК стовпців у ttk.Treeview
# Цей порядок ВАЖЛИВИЙ і має відповідати порядку значень у кортежах,
# які передаються в self.threat_table.insert() та self.threat_table.item()
THREAT_TABLE_COLS_INTERNAL = [
    "id",
    "count",
    "last_timestamp",
    "severity",
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "protocol",
    "ioc_type",
    "indicator",
    "feed_source",
    "description"
]

# Ширина колонок у пікселях
COL_WIDTHS = {
    "id": 40,
    "count": 50,
    "last_timestamp": 140,
    "severity": 80,
    "src_ip": 100,
    "src_port": 60,
    "dst_ip": 100,
    "dst_port": 60,
    "protocol": 70,
    "ioc_type": 80,
    "indicator": 120,
    "feed_source": 120, # Може бути довгим, якщо декілька джерел
    "description": 180  # Опис також може бути довгим
}

# Вирівнювання тексту в колонках ('w' - west/ліво, 'center', 'e' - east/право)
COL_ALIGN = {
    "id": "center",
    "count": "center",
    "severity": "center",
    "src_port": "center",
    "dst_port": "center",
    "protocol": "center",
    "ioc_type": "center"
    # Для інших за замовчуванням 'w' (ліворуч)
}
# --- END OF FILE config.py ---