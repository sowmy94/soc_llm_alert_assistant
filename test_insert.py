from database import insert_alert

def test_insert_alert():
    alert_data = {
        "timestamp": "2024-06-01T12:00:00Z",
        "alert_source": "test_source",
        "event_type": "test_event",
        "user": "test_user",
        "host": "test_host"
    }
    alert_id = insert_alert(alert_data)
    print(f"Alert inserted with ID: {alert_id}")

test_insert_alert()

