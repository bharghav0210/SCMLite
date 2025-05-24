from kafka import KafkaConsumer,errors
from pymongo import MongoClient
import json
import os,time
from dotenv import load_dotenv

# Load environment variables
load_dotenv()
KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
# MongoDB connection URI from .env
MONGO_URI = os.getenv("MONGO_URI", "mongodb+srv://bhargavmadhiraju123:Bharghav123@cluster0.p6h7hjw.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0") 
# Connect to MongoDB
while True:
    try:
        client = MongoClient(MONGO_URI, tls=True, tlsAllowInvalidCertificates=True)
        db = client['projectfast']
        collection = db['sensor_data_collection']
        print("Connected to MongoDB.")
        break
    except Exception as e:
        print(f"MongoDB connection failed: {e}, retrying in 5 seconds...")
        time.sleep(5)

# Connect to Kafka with retry logic
while True:
    try:
        consumer = KafkaConsumer(
            'sensor_data',
            bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
            value_deserializer=lambda m: json.loads(m.decode('utf-8')),
            auto_offset_reset='earliest',
            enable_auto_commit=True,
            group_id='sensor_consumer_group'
        )
        print("Connected to Kafka broker.")
        break
    except errors.NoBrokersAvailable:
        print("Kafka broker not available, retrying in 5 seconds...")
        time.sleep(5)

print("Consumer started. Waiting for messages...")

# Consume Kafka messages and insert into MongoDB
for message in consumer:
    data = message.value
    print(f"Received from Kafka: {data}")
    try:
        collection.insert_one(data)
        print("Inserted into MongoDB.\n")
    except Exception as e:
        print(f"MongoDB insert error: {e}")
       