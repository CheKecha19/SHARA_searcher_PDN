# config.py
import os

# Настройки путей
INPUT_FILE = "files.txt"  # Файл с путями
OUTPUT_FILE = "results.csv"  # Результаты
LOG_DIR = "logs"  # Папка для логов
AD_CACHE_FILE = "ad_cache.json"  # Кэш AD запросов

# Настройки обработки
MAX_WORKERS = 15  # Количество потоков
BATCH_SIZE = 50  # Размер пакета для AD запросов

# Настройки AD
AD_ATTRIBUTES = ["name", "sAMAccountName", "mail"]  # Запрашиваемые атрибуты

# Настройки логирования
LOG_LEVEL = "INFO"  # DEBUG, INFO, WARNING, ERROR
LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"