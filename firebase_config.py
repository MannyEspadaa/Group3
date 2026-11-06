import firebase_admin
from firebase_admin import credentials, firestore

cred = credentials.Certificate("universalpowerwashing-cc259-firebase-adminsdk-fbsvc-7c30996bee.json")

firebase_admin.initialize_app(cred)

db = firestore.client()