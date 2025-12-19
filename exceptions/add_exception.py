#!/usr/bin/env python3
"""
add_exception.py - добавляет исключение
"""
import sys
import json
import hashlib
import yaml

BASE_DIR = "/opt/wazuh-exceptions"

def main():
    if len(sys.argv) != 3:
        sys.exit(1)
    
    rule_id = sys.argv[1]
    alert_json = sys.argv[2]
    
    try:
        # 1. Загружаем конфиг
        with open(f"{BASE_DIR}/rules/{rule_id}.yaml") as f:
            config = yaml.safe_load(f)
        
        # 2. Парсим и извлекаем
        alert = json.loads(alert_json)
        fields = {}
        
        for field_name in config['field_order']:
            path = config['extract_rules'].get(field_name, f"data.{field_name}")
            
            # Ищем вложенное значение
            keys = path.split('.')
            val = alert
            for key in keys:
                if isinstance(val, dict):
                    val = val.get(key)
                else:
                    val = None
                    break
            
            fields[field_name] = val or ''
        
        # 3. Создаем хэш
        hash_str = '|'.join(str(fields[f]) for f in config['field_order'])
        hash_value = hashlib.md5(hash_str.encode()).hexdigest()
        
        # 4. Сохраняем
        hash_file = f"{BASE_DIR}/exceptions/{rule_id}.json"
        
        try:
            with open(hash_file) as f:
                hashes = json.load(f)
        except:
            hashes = []
        
        if hash_value not in hashes:
            hashes.append(hash_value)
            with open(hash_file, 'w') as f:
                json.dump(hashes, f, indent=2)
        
        sys.exit(0)
        
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()