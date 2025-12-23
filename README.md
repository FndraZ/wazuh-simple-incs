# Wazuh simple incidents

Here are some integrations and rules for my thesis

Цель работы: построить мониторинг опенсорс средствами.

Для этого выбраны:
1. Wazuh - SIEM
2. MISP - TI platform
3. FIR - IRP

Далее схемы взаимодействия:
1. IOC из MISP перегружаются в Wazuh CDB периодически
2. Wazuh отправляет алерты в FIR