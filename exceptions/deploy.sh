#!/bin/bash
# deploy.sh - custom exceptions integration deployment for Wazuh container
# /custom-exceptions/

CONTAINER="single-node-wazuh.manager-1"
SCRIPT_NAME="custom-fir_with_excl"
INTEGRATIONS_DIR="/var/ossec/integrations"
CONFIGS_DIR="/var/ossec/etc/custom-exceptions"

FIRST_RUN=false
SILENT=false
FORCE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --first-run)
            FIRST_RUN=true
            shift
            ;;
        --silent)
            SILENT=true
            shift
            ;;
        --force)
            FORCE=true
            shift
            ;;
        --help)
            echo "Usage: $0 [options]"
            echo "Options:"
            echo "  --first-run    First run (create directories and copy shuffle template)"
            echo "  --silent       Silent mode (skip deployment verification)"
            echo "  --force        Force execution (ignore checks)"
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

if [ "$FORCE" = false ]; then
    if ! docker ps --format '{{.Names}}' | grep -q "^$CONTAINER$"; then
        echo "Error: Container '$CONTAINER' not found or not running"
        echo "Use --force to ignore this check"
        exit 1
    fi
fi

echo "=== Deploying $SCRIPT_NAME integration ==="
echo "Container: $CONTAINER"
[ "$FIRST_RUN" = true ] && echo "Mode: First run"
[ "$SILENT" = true ] && echo "Mode: Silent"
[ "$FORCE" = true ] && echo "Mode: Forced"
echo

if [ "$FIRST_RUN" = true ]; then
    echo "Creating directory structure..."
    docker exec $CONTAINER bash -c "
        mkdir -p $INTEGRATIONS_DIR
        mkdir -p $CONFIGS_DIR/{rules,exceptions}
        chmod 755 $CONFIGS_DIR $CONFIGS_DIR/rules $CONFIGS_DIR/exceptions
        echo 'Directories created'
    "
else
    echo "Skipping directory creation (not first run)"
fi

echo "Copying integration script..."
if [ -f "$SCRIPT_NAME.py" ]; then
    docker cp $SCRIPT_NAME.py $CONTAINER:$INTEGRATIONS_DIR/$SCRIPT_NAME.py
    echo "   Script copied: $SCRIPT_NAME.py -> $INTEGRATIONS_DIR/$SCRIPT_NAME.py"
else
    echo "   Error: File $SCRIPT_NAME.py not found"
    exit 1
fi

echo "Copying rule configs..."
if [ -d "rules" ] && [ "$(ls -A rules 2>/dev/null)" ]; then
    if [ "$FIRST_RUN" = false ]; then
        docker exec $CONTAINER bash -c "mkdir -p $CONFIGS_DIR/rules"
    fi
    
    docker cp rules/. $CONTAINER:$CONFIGS_DIR/rules/
    RULE_COUNT=$(ls rules/*.yaml 2>/dev/null | wc -l)
    echo "   Rules copied: $RULE_COUNT"
else
    echo "   Rules directory is empty or missing, skipping"
fi

echo "Copying exceptions..."
if [ -d "exceptions" ] && [ "$(ls -A exceptions 2>/dev/null)" ]; then
    if [ "$FIRST_RUN" = false ]; then
        docker exec $CONTAINER bash -c "mkdir -p $CONFIGS_DIR/exceptions"
    fi
    
    docker cp exceptions/. $CONTAINER:$CONFIGS_DIR/exceptions/
    EXCEPTION_COUNT=$(ls exceptions/*.json 2>/dev/null | wc -l)
    echo "   Exceptions copied: $EXCEPTION_COUNT"
else
    echo "   Exceptions directory is empty or missing, skipping"
fi

echo "Setting permissions..."
if [ "$FIRST_RUN" = true ]; then
    echo "   Configuring for first run..."
    docker exec $CONTAINER bash -c "
        # Copy shuffle template for integration (if exists)
        if [ -f '/var/ossec/integrations/shuffle' ]; then
            cp /var/ossec/integrations/shuffle /var/ossec/integrations/$SCRIPT_NAME
            echo '   Shuffle template copied'
        fi
        
        # Script permissions
        chmod 750 $INTEGRATIONS_DIR/$SCRIPT_NAME*
        chown root:wazuh $INTEGRATIONS_DIR/$SCRIPT_NAME*
        echo '   Script permissions set'
        
        # Rule permissions (only if directory exists and is not empty)
        if [ -d '$CONFIGS_DIR/rules/' ] && [ -n \"\$(ls -A '$CONFIGS_DIR/rules/' 2>/dev/null)\" ]; then
            chown -R root:wazuh $CONFIGS_DIR/rules/
            find $CONFIGS_DIR/rules/ -type f -exec chmod 640 {} \;
            echo '   Rule permissions set'
        fi
        
        # Exception permissions (only if directory exists and is not empty)
        if [ -d '$CONFIGS_DIR/exceptions/' ] && [ -n \"\$(ls -A '$CONFIGS_DIR/exceptions/' 2>/dev/null)\" ]; then
            chown -R wazuh:wazuh $CONFIGS_DIR/exceptions/
            find $CONFIGS_DIR/exceptions/ -type f -exec chmod 660 {} \;
            echo '   Exception permissions set'
        fi
    "
else
    echo "   Updating file permissions..."
    docker exec $CONTAINER bash -c "
        # Integration script permissions
        chmod 750 $INTEGRATIONS_DIR/$SCRIPT_NAME.py
        chown root:wazuh $INTEGRATIONS_DIR/$SCRIPT_NAME.py
        
        # Rule permissions (if directory exists)
        if [ -d '$CONFIGS_DIR/rules/' ]; then
            find $CONFIGS_DIR/rules/ -type f -exec chmod 640 {} \;
            chown -R root:wazuh $CONFIGS_DIR/rules/
        fi
        
        # Exception permissions (if directory exists)
        if [ -d '$CONFIGS_DIR/exceptions/' ]; then
            find $CONFIGS_DIR/exceptions/ -type f -exec chmod 660 {} \;
            chown -R wazuh:wazuh $CONFIGS_DIR/exceptions/
        fi
    "
fi

if [ "$SILENT" = false ]; then
    echo "Verifying deployment..."
    docker exec $CONTAINER bash -c "
        echo '=== Deployment Verification ==='
        echo
        echo '1. Integration script:'
        ls -la $INTEGRATIONS_DIR/$SCRIPT_NAME* 2>/dev/null || echo '   Not found'
        echo
        echo '2. Config directory:'
        ls -lad $CONFIGS_DIR/ 2>/dev/null || echo '   Not found'
        echo
        echo '3. Rule configs:'
        if [ -d '$CONFIGS_DIR/rules/' ]; then
            ls -la $CONFIGS_DIR/rules/ 2>/dev/null | head -10
            echo '   Total files:' \$(ls -1 '$CONFIGS_DIR/rules/' 2>/dev/null | wc -l)
        else
            echo '   Directory does not exist'
        fi
        echo
        echo '4. Exceptions directory:'
        if [ -d '$CONFIGS_DIR/exceptions/' ]; then
            ls -la $CONFIGS_DIR/exceptions/ 2>/dev/null | head -10
            echo '   Total files:' \$(ls -1 '$CONFIGS_DIR/exceptions/' 2>/dev/null | wc -l)
        else
            echo '   Directory does not exist'
        fi
    "
fi

echo
echo "=== Deployment completed! ==="
echo "Script: $INTEGRATIONS_DIR/$SCRIPT_NAME.py"
echo "Configs: $CONFIGS_DIR/"
echo "Mode: $([ "$FIRST_RUN" = true ] && echo "first run" || echo "update")"