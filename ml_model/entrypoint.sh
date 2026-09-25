#!/bin/bash
# ml_model/entrypoint.sh (محدث)
set -e

# محاولة اكتشاف الانترفيس تلقائياً
if [ -z "$IFACE" ]; then
    IFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
fi

if [ -z "$IFACE" ]; then
    echo "[entrypoint] ERROR: Cannot detect network interface"
    echo "[entrypoint] Please set IFACE environment variable"
    exit 1
fi

echo "========================================="
echo " ML Anomaly Detector"
echo "========================================="
echo " Interface : $IFACE"
echo " Model     : $MODEL_PATH"
echo " Scaler    : $SCALER_PATH"
echo " Alerts    : $ALERT_LOG_PATH"
echo "========================================="
echo ""

export IFACE
exec python3 detector.py