#!/bin/bash
# deploy.sh - деплой интеграции исключений в контейнер Wazuh
# Расположение: /home/user/integrations_wazuh/custom-exceptions/

CONTAINER="single-node-wazuh.manager-1"
SCRIPT_NAME="custom-exceptions"
INTEGRATIONS_DIR="/var/ossec/integrations"
CONFIGS_DIR="/var/ossec/etc/custom-exceptions"

echo "=== Деплой интеграции custom-exceptions ==="
echo "Контейнер: $CONTAINER"
echo

echo "Создаем структуру директорий..."
docker exec $CONTAINER bash -c "
    mkdir -p $INTEGRATIONS_DIR
    mkdir -p $CONFIGS_DIR/{rules,exceptions}
    chmod 755 $CONFIGS_DIR $CONFIGS_DIR/rules $CONFIGS_DIR/exceptions
"

echo "Копируем скрипт интеграции..."
docker cp checker1.py $CONTAINER:$INTEGRATIONS_DIR/$SCRIPT_NAME.py

echo "Копируем конфиги правил..."
if [ -d "rules" ] && [ "$(ls -A rules 2>/dev/null)" ]; then
    docker cp rules/ $CONTAINER:$CONFIGS_DIR/
    echo "   Правил скопировано: $(ls rules/*.yaml 2>/dev/null | wc -l)"
else
    echo "   Папка rules пуста или отсутствует"
fi

echo "Копируем исключения..."
if [ -d "exceptions" ] && [ "$(ls -A exceptions 2>/dev/null)" ]; then
    docker cp exceptions/ $CONTAINER:$CONFIGS_DIR/
    echo "   Исключений скопировано: $(ls exceptions/*.json 2>/dev/null | wc -l)"
else
    echo "   Папка exceptions пуста или отсутствует"
fi

echo "Настраиваем права..."
docker exec $CONTAINER bash -c "
    cp /var/ossec/integrations/shuffle /var/ossec/integrations/$SCRIPT_NAME
    chmod 750 $INTEGRATIONS_DIR/$SCRIPT_NAME*
    chown root:wazuh $INTEGRATIONS_DIR/$SCRIPT_NAME*
        
    chown -R root:wazuh $CONFIGS_DIR/rules/
    find $CONFIGS_DIR/rules/ -type f -exec chmod 640 {} \;
    
    chown -R wazuh:wazuh $CONFIGS_DIR/exceptions/
    find $CONFIGS_DIR/exceptions/ -type f -exec chmod 660 {} \;
"

echo "Проверяем деплой..."
docker exec $CONTAINER bash -c "
    echo 'Скрипт интеграции:'
    ls -la $INTEGRATIONS_DIR/$SCRIPT_NAME.py
    echo
    echo 'Конфиги:'
    ls -la $CONFIGS_DIR/rules/
    echo
    echo 'Папка исключений:'
    ls -la $CONFIGS_DIR/exceptions/
"

echo
echo "Деплой завершен!"
echo "Скрипт: $INTEGRATIONS_DIR/$SCRIPT_NAME.py"
echo "Конфиги: $CONFIGS_DIR/"