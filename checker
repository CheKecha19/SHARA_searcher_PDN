import subprocess
import os
import re

def get_owner_sid_ps(file_path):
    # Экранируем специальные символы для PowerShell
    safe_path = re.sub(r'([\'"$`])', r'`\1', file_path)
    
    ps_script = f"""
    $ErrorActionPreference = 'Stop'
    try {{
        $path = '{safe_path}'
        
        # Проверяем существование файла
        if (-not (Test-Path -LiteralPath $path)) {{
            "FILE NOT FOUND"
            exit
        }}
        
        $acl = Get-Acl -LiteralPath $path
        $owner = $acl.Owner
        
        # Если владелец уже в формате SID
        if ($owner -match '^S-\d-\d+-(\d+-){{1,14}}\d+$') {{
            $matches[0]
        }} else {{
            # Конвертируем имя в SID
            $ntAccount = New-Object System.Security.Principal.NTAccount($owner)
            $sid = $ntAccount.Translate([System.Security.Principal.SecurityIdentifier])
            $sid.Value
        }}
    }} catch {{
        "ERROR: $($_.Exception.Message)"
    }}
    """
    
    result = subprocess.run(
        ["powershell", "-Command", ps_script],
        capture_output=True,
        text=True,
        encoding='utf-8'
    )
    return result.stdout.strip()

def main():
    input_file = r"<<PATH>>\files.txt"
    output_file = r"<<PATH>>\results.txt"
    
    with open(input_file, 'r', encoding='utf-8') as f:
        file_paths = [line.strip() for line in f if line.strip()]
    
    results = []
    total = len(file_paths)
    
    for i, path in enumerate(file_paths, 1):
        print(f"Обработка {i}/{total}: {path}")
        sid = get_owner_sid_ps(path)
        results.append(f"{path}; {sid}")
        print(f"  -> {sid}")
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("\n".join(results))
    print(f"\nРезультаты сохранены в {output_file}")

if __name__ == "__main__":
    main()
