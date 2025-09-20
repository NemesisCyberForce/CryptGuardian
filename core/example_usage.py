# Beispiel-Verwendung

blockchain = SmartBlockchain()

# Alert-Handler registrieren
def alert_handler(alert):
    print(f"[{alert['severity']}] {alert['message']}")
    # Hier könnte eine Benachrichtigung per E-Mail/Slack/etc. erfolgen

blockchain.guardian.register_alert_handler(alert_handler)

try:
    # Normale Blöcke hinzufügen
    blockchain.add_block("Normale Transaktion #1")
    blockchain.add_block("Normale Transaktion #2")
    
    # Verdächtigen Block hinzufügen
    blockchain.add_block("Verdächtige Transaktion mit ungewöhnlichem Muster")
    
except SecurityException as e:
    print(f"Sicherheitsverstoß erkannt: {e}")
