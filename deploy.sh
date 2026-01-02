#!/bin/bash
# deploy.sh - custom integrations deployment for Wazuh container

CONTAINER="single-node-wazuh.manager-1"
INTEGRATIONS_DIR="/var/ossec/integrations"
CONFIGS_DIR="/var/ossec/etc/custom-exceptions"
SOURCE_INTEGRATIONS_DIR="custom-integrations"
SOURCE_RULES_DIR="rules"

FIRST_RUN=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --first-run)
            FIRST_RUN=true
            shift
            ;;
        --help)
            echo "Usage: $0 [options]"
            echo "Options:"
            echo "  --first-run    First run (create directories and copy shuffle template)"
            echo "  --help         Show this help"
            exit 0
            ;;
        *)
            echo "Unknown argument: $1"
            echo "Use $0 --help for usage information"
            exit 1
            ;;
    esac
done

echo "=== Checking container ==="
if ! docker ps --format '{{.Names}}' | grep -q "^$CONTAINER$"; then
    echo "Error: Container '$CONTAINER' not found or not running"
    echo "Please ensure the container is running"
    exit 1
fi
echo "Container '$CONTAINER' is running"
echo

echo "=== Deploying custom integrations ==="
echo "Container: $CONTAINER"
echo "Source integrations: $SOURCE_INTEGRATIONS_DIR"
echo "Source rules: $SOURCE_RULES_DIR"
[ "$FIRST_RUN" = true ] && echo "Mode: First run" || echo "Mode: Update"
echo

if [ ! -d "$SOURCE_INTEGRATIONS_DIR" ]; then
    echo "Error: Source directory '$SOURCE_INTEGRATIONS_DIR' not found"
    exit 1
fi

if [ ! -d "$SOURCE_RULES_DIR" ]; then
    echo "Warning: Source rules directory '$SOURCE_RULES_DIR' not found"
fi

if [ "$FIRST_RUN" = true ]; then
    echo "=== First run setup ==="
    
    echo "1. Creating directory structure..."
    docker exec $CONTAINER bash -c "
        mkdir -p $CONFIGS_DIR
        mkdir -p $INTEGRATIONS_DIR
        
        chmod 755 $INTEGRATIONS_DIR
        chmod 750 $CONFIGS_DIR
        chown root:wazuh $CONFIGS_DIR
        
        echo '   Directories created'
    "
    
    echo "2. Copying shuffle template for integrations..."
    # Автоматически находим все custom-*.py файлы
    CUSTOM_SCRIPT_FILES=$(find "$SOURCE_INTEGRATIONS_DIR" -name "custom-*.py" -type f)

    if [ -n "$CUSTOM_SCRIPT_FILES" ]; then
        for SCRIPT_FILE in $CUSTOM_SCRIPT_FILES; do
            INTEGRATION_NAME=$(basename "$SCRIPT_FILE" .py)
            echo "   Processing: $INTEGRATION_NAME"
            
            docker exec $CONTAINER bash -c "
                cp /var/ossec/integrations/shuffle $INTEGRATIONS_DIR/$INTEGRATION_NAME 2>/dev/null || echo '   Warning: Failed to copy shuffle'
                echo '   Copied shuffle -> $INTEGRATION_NAME'
            "
        done
        echo "   Total shuffle copies created: $(echo "$CUSTOM_SCRIPT_FILES" | wc -l)"
    else
        echo "   Warning: No custom-*.py files found for shuffle template"
    fi
    echo

else
    echo "Skipping first run setup (not first run)"
    echo
fi

echo "=== Copying Python scripts ==="

if [ -f "$SOURCE_INTEGRATIONS_DIR/common_functions.py" ]; then
    echo "1. Copying common_functions.py..."
    docker cp "$SOURCE_INTEGRATIONS_DIR/common_functions.py" $CONTAINER:$INTEGRATIONS_DIR/common_functions.py
    echo "   Copied: common_functions.py"
else
    echo "   Error: common_functions.py not found - this file is required!"
    exit 1
fi

echo "2. Copying integration scripts..."
# Автоматически находим все custom-*.py файлы
CUSTOM_SCRIPT_FILES=$(find "$SOURCE_INTEGRATIONS_DIR" -name "custom-*.py" -type f)

if [ -n "$CUSTOM_SCRIPT_FILES" ]; then
    for SCRIPT_FILE in $CUSTOM_SCRIPT_FILES; do
        FILE_NAME=$(basename "$SCRIPT_FILE")
        echo "   Processing: $FILE_NAME"
        docker cp "$SCRIPT_FILE" $CONTAINER:$INTEGRATIONS_DIR/$FILE_NAME
        echo "   Copied: $FILE_NAME"
    done
    echo "   Total custom scripts copied: $(echo "$CUSTOM_SCRIPT_FILES" | wc -l)"
else
    echo "   Warning: No custom-*.py files found"
fi

echo "=== Copying configurations ==="

if [ -d "$SOURCE_RULES_DIR" ] && [ "$(ls -A $SOURCE_RULES_DIR 2>/dev/null)" ]; then
    echo "1. Copying rule configs..."
    
    docker exec $CONTAINER bash -c "mkdir -p $CONFIGS_DIR/rules"
    docker cp "$SOURCE_RULES_DIR/." $CONTAINER:$CONFIGS_DIR/rules/
    
    RULE_COUNT=$(find "$SOURCE_RULES_DIR" -type f -name "*.yaml" 2>/dev/null | wc -l)
    TOTAL_COUNT=$(find "$SOURCE_RULES_DIR" -type f 2>/dev/null | wc -l)
    
    echo "   Copied: $TOTAL_COUNT files ($RULE_COUNT YAML) to $CONFIGS_DIR/rules/"
else
    echo "   Rules directory is empty or missing, skipping"
fi

echo "=== Setting permissions ==="

docker exec $CONTAINER bash -c "
    echo '1. Setting script permissions...'
    
    if [ -f '$INTEGRATIONS_DIR/common_functions.py' ]; then
        chmod 750 $INTEGRATIONS_DIR/common_functions.py
        chown root:wazuh $INTEGRATIONS_DIR/common_functions.py
        echo '   common_functions.py permissions set'
    fi
    
    echo '   Fixing permissions for all custom integration files...'
    
    find $INTEGRATIONS_DIR -name 'custom-*.py' -type f -exec chmod 750 {} \;
    find $INTEGRATIONS_DIR -name 'custom-*.py' -type f -exec chown root:wazuh {} \;
    echo '   All custom-*.py files fixed (750, root:wazuh)'
    
    find $INTEGRATIONS_DIR -name 'custom-*' -type f ! -name '*.py' -exec chmod 750 {} \;
    find $INTEGRATIONS_DIR -name 'custom-*' -type f ! -name '*.py' -exec chown root:wazuh {} \;
    echo '   All custom-* executables fixed (750, root:wazuh)'
    
    echo '   All script permissions set'
    
    echo
    echo '2. Setting config permissions...'
    
    if [ -d '$CONFIGS_DIR' ]; then
        chmod 750 $CONFIGS_DIR
        chown root:wazuh $CONFIGS_DIR
        echo '   Main config directory permissions set'
        
        if [ -d '$CONFIGS_DIR/rules' ]; then
            chmod 750 $CONFIGS_DIR/rules
            chown root:wazuh $CONFIGS_DIR/rules
            
            find $CONFIGS_DIR/rules -type f -exec chmod 640 {} \;
            find $CONFIGS_DIR/rules -type f -exec chown root:wazuh {} \;
            echo '   Rules directory permissions set (directory: 750, files: 640)'
        fi
        
        if [ -d '$CONFIGS_DIR/exceptions' ]; then
            chmod 750 $CONFIGS_DIR/exceptions
            chown wazuh:wazuh $CONFIGS_DIR/exceptions
            
            find $CONFIGS_DIR/exceptions -type f -exec chmod 660 {} \;
            find $CONFIGS_DIR/exceptions -type f -exec chown wazuh:wazuh {} \;
            echo '   Exceptions directory permissions set (directory: 750, files: 660)'
        fi
    fi
"

echo
echo "=== Deployment Verification ==="

docker exec $CONTAINER bash -c "
    echo '1. Integration scripts status:'
    echo '   common_functions.py:'
    if [ -f '$INTEGRATIONS_DIR/common_functions.py' ]; then
        ls -la $INTEGRATIONS_DIR/common_functions.py
    else
        echo '      NOT FOUND!'
    fi
    
    echo
    echo '   Custom integrations:'
    CUSTOM_FILES=\$(find $INTEGRATIONS_DIR -name 'custom-*.py' -type f 2>/dev/null)
    if [ -n \"\$CUSTOM_FILES\" ]; then
        for FILE in \$CUSTOM_FILES; do
            FILE_NAME=\$(basename \$FILE)
            echo -n \"   \$FILE_NAME: \"
            ls -la \$FILE | awk '{\$1=\$2=\$3=\$4=\$5=\$6=\$7=\$8=\"\"; print \$0}' | sed 's/^ *//'
        done
        echo \"   Total custom scripts: \$(echo \"\$CUSTOM_FILES\" | wc -l)\"
    else
        echo '   No custom integration files found'
    fi
    
    echo
    echo '2. Configuration files status:'
    if [ -d '$CONFIGS_DIR' ]; then
        echo '   Main directory:'
        ls -lad $CONFIGS_DIR
        
        echo
        echo '   Rules directory:'
        if [ -d '$CONFIGS_DIR/rules' ]; then
            ls -lad $CONFIGS_DIR/rules
            echo
            echo '   Rules files count:'
            find $CONFIGS_DIR/rules -type f | wc -l | awk '{print \"      Total: \" \$1}'
            find $CONFIGS_DIR/rules -type f -name '*.yaml' | wc -l | awk '{print \"      YAML files: \" \$1}'
            
            echo
            echo '   First 5 rules files:'
            find $CONFIGS_DIR/rules -type f | head -5 | while read file; do
                ls -la \$file | awk '{\$1=\$2=\$3=\$4=\$5=\$6=\$7=\$8=\"\"; print \"      \" \$0}' | sed 's/^ *//'
            done
        else
            echo '   Rules directory not found!'
        fi
    else
        echo '   Config directory not found!'
    fi
"

echo
echo "=== Deployment completed successfully! ==="
echo "Integration scripts: $INTEGRATIONS_DIR/"
echo "Configuration files: $CONFIGS_DIR/"
echo "Mode: $([ "$FIRST_RUN" = true ] && echo "first run" || echo "update")"
echo
echo "Next steps:"
if [ "$FIRST_RUN" = true ]; then
    echo "1. Restart Wazuh manager to load new integrations"
    echo "2. Configure rules in Wazuh dashboard"
else
    echo "1. Integration scripts updated - restart may not be required"
    echo "2. Check if rule changes require Wazuh restart"
fi