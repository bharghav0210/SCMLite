from kafka import KafkaProducer, errors
import json
import time
import random
import os

KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")

# Connect to Kafka with retry logic
while True:
    try:
        producer = KafkaProducer(
            bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
            value_serializer=lambda v: json.dumps(v).encode('utf-8')
        )
        print("Connected to Kafka broker.")
        break
    except errors.NoBrokersAvailable:
        print("Kafka broker not available, retrying in 5 seconds...")
        time.sleep(5)

route = ['Newyork,USA', 'Chennai, India', 'Bengaluru, India', 'London,UK']

while True:
    routefrom = random.choice(route)
    routeto = random.choice(route)
    if routefrom != routeto:
        data = {
            "Battery_Level": round(random.uniform(2.0, 5.0), 2),
            "Device_ID": random.randint(1150, 1158),
            "First_Sensor_temperature": round(random.uniform(10, 40.0), 1),
            "Route_From": routefrom,
            "Route_To": routeto
        }
        producer.send('sensor_data', data)
        print(f"Sent to Kafka: {data}")
        time.sleep(10)
