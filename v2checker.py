import os
import re
import json
import logging
import sys
import subprocess
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed
import config
import unicodedata

# Настройка логирования
def setup_logging():
    os.makedirs(config.LOG_DIR, exist_ok=True)
    log_file = os.path.join(config.LOG_DIR, "log.txt")
    
    logger = logging.getLogger()
    logger.setLevel(config.LOG_LEVEL)
    
    # Форматтер
    formatter = logging.Formatter(
        config.LOG_FORMAT,
        datefmt=config.LOG_DATE_FORMAT
    )
    
    # Обработчик файла
    file_handler = logging.FileHandler(log_file, encoding='utf-8')
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    
    # Обработчик консоли
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    return logger

def clean_value(value):
    """Очистка и преобразование значений"""
    if value is None:
        return ""
    
    # Преобразуем в строку
    cleaned = str(value)
    
    # Удаляем управляющие символы (0x00-0x1F) и спецсимволы
    cleaned = ''.join(ch for ch in cleaned if unicodedata.category(ch)[0] != "C")
    cleaned = cleaned.replace('\x00', '').replace('\x01', '').replace('\x02', '')
    
    return cleaned.strip()

# Загрузка и сохранение кэша AD
def load_ad_cache():
    if os.path.exists(config.AD_CACHE_FILE):
        try:
            with open(config.AD_CACHE_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except:
            return {}
    return {}

def save_ad_cache(cache):
    try:
        with open(config.AD_CACHE_FILE, 'w', encoding='utf-8') as f:
            json.dump(cache, f, ensure_ascii=False, indent=2)
    except Exception as e:
        logger.error(f"Ошибка сохранения кэша AD: {str(e)}")

# Получение информации о владельце файла
def get_file_owner_sid(file_path):
    """Получаем SID владельца файла через PowerShell"""
    try:
        # Конвертируем путь в формат, понятный PowerShell
        ps_path = file_path.replace("'", "''")
        
        ps_script = f"""
        $ErrorActionPreference = 'Stop'
        try {{
            $path = '{ps_path}'
            
            if (-not (Test-Path -LiteralPath $path)) {{
                "FILE_NOT_FOUND"
                exit
            }}
            
            $acl = Get-Acl -LiteralPath $path
            $owner = $acl.Owner
            
            if ($owner -match '^S-\\d-\\d+-(\\d+-){{1,14}}\\d+$') {{
                $matches[0]
            }} else {{
                try {{
                    $sid = ([System.Security.Principal.NTAccount]$owner).Translate(
                        [System.Security.Principal.SecurityIdentifier]
                    ).Value
                    $sid
                }} catch {{
                    "ERROR:TRANSLATE"
                }}
            }}
        }} catch {{
            "ERROR:EXCEPTION"
        }}
        """
        
        result = subprocess.run(
            ["powershell", "-Command", ps_script],
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='replace'
        )
        
        return result.stdout.strip()
    except Exception as e:
        return f"ERROR:PYTHON:{str(e)}"

# Пакетное получение информации из AD (исправленная версия)
def get_ad_users_batch(sids, cache):
    """Получаем информацию о пользователях пакетно с использованием цикла и расширенными параметрами"""
    # Фильтруем SID, которые уже есть в кэше
    sids_to_fetch = [sid for sid in sids if sid not in cache]
    if not sids_to_fetch:
        return cache
    
    # Формируем PowerShell скрипт с обработкой каждого SID отдельно
    ps_script = """
    $OutputEncoding = [System.Text.Encoding]::UTF8
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    $ErrorActionPreference = 'Continue'  # Continue при ошибках отдельных SID
    $results = @{}
    """
    
    # Добавляем обработку для каждого SID
    for sid in sids_to_fetch:
        ps_script += f"""
        try {{
            # Пытаемся найти пользователя по SID
            $user = Get-ADObject -Identity '{sid}' -IncludeDeletedObjects -Properties name, sAMAccountName, mail, objectClass -ErrorAction Stop
            
            # Проверяем, является ли объект пользователем
            if ($user.objectClass -contains 'user') {{
                # Если это пользователь, получаем дополнительные свойства
                $user = Get-ADUser -Identity '{sid}' -Properties name, sAMAccountName, mail, Enabled, DistinguishedName -ErrorAction Stop
                
                $results['{sid}'] = @{{
                    name = $user.name
                    sAMAccountName = $user.sAMAccountName
                    mail = $user.mail
                    enabled = $user.Enabled
                    distinguishedName = $user.DistinguishedName
                }}
            }} else {{
                # Для не-пользовательских объектов
                $results['{sid}'] = @{{
                    name = $user.name
                    sAMAccountName = ''
                    mail = ''
                    enabled = $false
                    distinguishedName = $user.DistinguishedName
                    objectClass = $user.objectClass -join ','
                }}
            }}
        }} catch {{
            # Пытаемся найти через SIDHistory
            try {{
                $user = Get-ADUser -Filter "SIDHistory -eq '{sid}'" -Properties name, sAMAccountName, mail, SIDHistory -ErrorAction Stop
                if ($user) {{
                    $results['{sid}'] = @{{
                        name = $user.name
                        sAMAccountName = $user.sAMAccountName
                        mail = $user.mail
                        enabled = $user.Enabled
                        sidHistory = $true
                        distinguishedName = $user.DistinguishedName
                    }}
                }} else {{
                    # Помечаем как не найденного
                    $results['{sid}'] = @{{
                        name = 'NOT_FOUND'
                        sAMAccountName = ''
                        mail = ''
                        enabled = $false
                        distinguishedName = ''
                    }}
                }}
            }} catch {{
                # Помечаем как не найденного
                $results['{sid}'] = @{{
                    name = 'ERROR'
                    sAMAccountName = ''
                    mail = ''
                    enabled = $false
                    distinguishedName = ''
                    error = $_.Exception.Message
                }}
            }}
        }}
        """
    
    ps_script += """
    $results | ConvertTo-Json -Depth 5 -Compress
    """
    
    try:
        result = subprocess.run(
            ["powershell", "-Command", ps_script],
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='replace',
            timeout=300  # Увеличиваем таймаут до 5 минут
        )
        
        # Логирование ошибок
        if result.stderr:
            logger.error(f"Ошибка PowerShell при пакетном запросе: {result.stderr}")
        
        if result.stdout and result.stdout.startswith("{"):
            try:
                ad_data = json.loads(result.stdout)
                found_count = 0
                for sid, user_info in ad_data.items():
                    # Очищаем значения
                    cache[sid] = {
                        "name": clean_value(user_info.get("name", "")),
                        "sAMAccountName": clean_value(user_info.get("sAMAccountName", "")),
                        "mail": clean_value(user_info.get("mail", "")),
                        "enabled": user_info.get("enabled", False),
                        "distinguishedName": user_info.get("distinguishedName", ""),
                        "status": "found"
                    }
                    if user_info.get("name") not in ["NOT_FOUND", "ERROR"]:
                        found_count += 1
                
                logger.info(f"Найдено {found_count} из {len(sids_to_fetch)} пользователей в пакете")
            except json.JSONDecodeError:
                logger.error(f"Ошибка декодирования JSON: {result.stdout}")
        else:
            logger.error(f"Некорректный вывод PowerShell: {result.stdout}")
    except Exception as e:
        logger.error(f"Ошибка Python при пакетном запросе: {str(e)}")
    
    return cache

# Основная функция обработки
def main():
    global logger
    logger = setup_logging()
    logger.info("=" * 80)
    logger.info("Запуск проверки владельцев файлов")
    logger.info("=" * 80)
    
    # Загружаем кэш AD
    ad_cache = load_ad_cache()
    logger.info(f"Загружено {len(ad_cache)} записей из кэша AD")
    
    # Чтение файла с путями
    try:
        with open(config.INPUT_FILE, 'r', encoding='utf-8') as f:
            file_paths = [line.strip() for line in f if line.strip()]
    except Exception as e:
        logger.error(f"Ошибка чтения файла: {str(e)}")
        return
    
    total_files = len(file_paths)
    logger.info(f"Найдено {total_files} файлов для обработки")
    
    # Этап 1: Получение SID для всех файлов
    logger.info("Этап 1/3: Получение SID владельцев файлов...")
    results = []
    sids_to_fetch = set()
    
    with ThreadPoolExecutor(max_workers=config.MAX_WORKERS) as executor:
        futures = {executor.submit(get_file_owner_sid, path): path for path in file_paths}
        
        # Прогресс-бар с динамическим обновлением
        with tqdm(total=total_files, desc="Получение SID", unit="file", 
                 bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]") as pbar:
            for future in as_completed(futures):
                path = futures[future]
                try:
                    sid = future.result()
                    results.append((path, sid))
                    
                    # Собираем SID для запроса в AD
                    if sid.startswith("S-") and not sid.startswith("ERROR"):
                        sids_to_fetch.add(sid)
                except Exception as e:
                    logger.error(f"Ошибка обработки файла {path}: {str(e)}")
                    results.append((path, f"ERROR:FUTURE:{str(e)}"))
                pbar.update(1)
    
    # Этап 2: Получение информации из AD
    logger.info(f"Этап 2/3: Запрос информации для {len(sids_to_fetch)} уникальных SID...")
    
    # Разбиваем на пакеты для обработки
    sid_batches = [list(sids_to_fetch)[i:i + config.BATCH_SIZE] 
                  for i in range(0, len(sids_to_fetch), config.BATCH_SIZE)]
    
    with tqdm(total=len(sid_batches), desc="Запрос AD", unit="batch") as pbar:
        for batch in sid_batches:
            ad_cache = get_ad_users_batch(batch, ad_cache)
            pbar.update(1)
    
    # Сохраняем кэш AD
    save_ad_cache(ad_cache)
    logger.info(f"Сохранено {len(ad_cache)} записей в кэше AD")
    
    # Этап 3: Формирование результатов
    logger.info("Этап 3/3: Формирование отчета...")
    output_lines = ["File;SID;Name;SamAccountName;EmailAddress"]
    
    with tqdm(total=total_files, desc="Формирование отчета", unit="file") as pbar:
        for path, sid in results:
            user_info = ad_cache.get(sid, {})
            
            # Формируем строку результата
            line = f"{path};{sid};"
            line += f"{user_info.get('name', '')};"
            line += f"{user_info.get('sAMAccountName', '')};"
            line += f"{user_info.get('mail', '')}"
            
            output_lines.append(line)
            pbar.update(1)
    
    # Сохранение результатов
    try:
        with open(config.OUTPUT_FILE, 'w', encoding='utf-8-sig') as f:
            f.write("\n".join(output_lines))
        logger.info(f"Результаты сохранены в {config.OUTPUT_FILE}")
    except Exception as e:
        logger.error(f"Ошибка сохранения результатов: {str(e)}")
    
    logger.info("=" * 80)
    logger.info("Обработка завершена!")
    logger.info("=" * 80)

if __name__ == "__main__":
    main()