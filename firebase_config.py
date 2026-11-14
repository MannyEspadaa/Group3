import firebase_admin
from firebase_admin import credentials, firestore

cred = credentials.Certificate("universalpowerwashing-cc259-firebase-adminsdk-fbsvc-18276693ca.json")

firebase_admin.initialize_app(cred)

db = firestore.client()
