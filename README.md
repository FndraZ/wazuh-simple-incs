# Wazuh simple incidents

Here are some integrations and rules for my thesis

Цель работы: построить мониторинг опенсорс средствами.

Для этого выбраны:
1. Wazuh - SIEM
2. MISP - TI platform
3. FIR - IRP

Текущая версия проекта создана для комбинации этих инструментов в виде Docker-контейнеров на одном сервере.

Деплой в Docker-контейнер Wazuh
```bash
git clone https://github.com/FndraZ/wazuh-simple-incs.git
cd wazuh-simple-incs
bash deploy.sh --first-run # если запуск впервые
bash deploy.sh # если требуется обновить скрипты или конфиги
```

Это скопирует интеграции в нужные директории. Кроме этого, нужно еще настроить вызов интеграций и правила.

Далее необходимо создать новые категории в FIR:
- Create and delete task within 24h
- User was created/enabled
- RAT activity from outside
- RAT activity to outside
- Recon tools
- Critical user was disabled
- Critical user was deleted

Далее схемы взаимодействия:
1. IOC из MISP перегружаются в Wazuh CDB периодически
2. Wazuh отправляет алерты в FIR