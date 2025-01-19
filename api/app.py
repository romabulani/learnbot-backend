import os
import bcrypt
from datetime import datetime, timedelta
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, Depends
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import google.generativeai as genai
from motor.motor_asyncio import AsyncIOMotorClient
from jose import JWTError, jwt
from dotenv import load_dotenv
import json
import uuid
from fastapi.logger import logger 
from bson import ObjectId
import gdown
import base64
from tempfile import NamedTemporaryFile


load_dotenv()

# Load environment variables
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
MONGO_URI = os.getenv("MONGO_URI")
DB_NAME = os.getenv("DB_NAME")

creds_base64 = os.getenv("ENCODED_CREDS")
if creds_base64:
    creds_data = json.loads(base64.b64decode(creds_base64).decode('utf-8'))

    with NamedTemporaryFile(delete=False, suffix=".json") as temp_file:
        temp_file.write(json.dumps(creds_data).encode())
        os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = temp_file.name
    print(f"Credentials successfully loaded from: {temp_file.name}")
else:
    raise ValueError("Google credentials are not set in environment variables.")

genai.configure(api_key=None)

aimodel = genai.GenerativeModel('gemini-pro')

if not JWT_SECRET_KEY:
    raise ValueError("JWT_SECRET_KEY is not set. Please define it in the environment variables.")

# MongoDB setup
client = AsyncIOMotorClient(MONGO_URI)
db = client[DB_NAME]

# JWT Configuration
ACCESS_TOKEN_EXPIRE_MINUTES = 3600

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

class User(BaseModel):
    username: str
    password: str

class UserResponse(BaseModel):
    username: str
    token: str

class LoginResponse(BaseModel):
    access_token: str
    token_type: str


def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, algorithm="HS256")
    return encoded_jwt


def objectid_to_str(obj):
    """Convert ObjectId to string if it's an instance of ObjectId"""
    if isinstance(obj, ObjectId):
        return str(obj)
    elif isinstance(obj, dict):
        return {k: objectid_to_str(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [objectid_to_str(item) for item in obj]
    return obj


async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=["HS256"])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return username
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

@app.post("/signup", response_model=LoginResponse)
async def signup(form_data: OAuth2PasswordRequestForm = Depends()):
    existing_user = await db.users.find_one({"username": form_data.username})
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already exists")

    hashed_password = bcrypt.hashpw(form_data.password.encode("utf-8"), bcrypt.gensalt())
    await db.users.insert_one({"username": form_data.username, "password": hashed_password.decode()})

    access_token = create_access_token(data={"sub": form_data.username}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    return {"access_token": access_token, "token_type": "bearer"}


@app.post("/login", response_model=LoginResponse)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await db.users.find_one({"username": form_data.username})
    if not user or not bcrypt.checkpw(form_data.password.encode("utf-8"), user["password"]):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    access_token = create_access_token(data={"sub": user["username"]}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    return {"access_token": access_token, "token_type": "bearer"}


def is_javascript_related(message: str) -> bool:
    try:
        response = aimodel.generate_content(
            f"Classify this message as 'js' if it's related to JavaScript, otherwise 'not_js': {message}"
        )
        classification = response.text.strip().lower()
        return classification == "js"
    except Exception as e:
        print(f"Error in AI classification: {e}")
        return False


async def get_or_create_session(username: str):
    session = await db.sessions.find_one({"username": username}).sort("timestamp", 1).limit(1)
    if session:
        return session["session_id"]
    session_id = str(uuid.uuid4())
    await db.sessions.insert_one({"username": username, "session_id": session_id})
    return session_id



@app.websocket("/chat")
async def websocket_endpoint(websocket: WebSocket):
    try:
        # Parse token and session ID from query params
        query_params = websocket.scope.get("query_string", b"").decode("utf-8")
        token = dict(q.split("=") for q in query_params.split("&")).get("token")
        session_id = dict(q.split("=") for q in query_params.split("&")).get("sessionId")

        if not token:
            raise HTTPException(status_code=401, detail="Token missing")

        # Verify token and get username
        payload = verify_token(token)
        username = payload.get("sub")

        if not session_id:
            session_id = await get_or_create_session(username)

        await websocket.accept()

        while True:
            data = await websocket.receive_json()
            user_message = data.get("message", "").strip()

            if not user_message:
                await websocket.send_json({"error": "Message not provided"})
                continue

            # Save user message in the database
            await db.messages.insert_one({
                "sender": "user",
                "message": user_message,
                "session_id": session_id,
                "timestamp": datetime.utcnow()
            })

            # Update session name if not present (using first message)
            session = await db.sessions.find_one({"session_id": session_id})
            if session and not session.get("session_name"):
                session_name = user_message[:20]  # First 20 characters of the message
                await db.sessions.update_one(
                    {"session_id": session_id},
                    {"$set": {"session_name": session_name}}
                )

            # Check if the message is related to JavaScript
            if not is_javascript_related(user_message):
                fallback_message = "Please ask questions related to JavaScript."
                
                # Save the fallback assistant response
                await db.messages.insert_one({
                    "sender": "assistant",
                    "message": fallback_message,
                    "session_id": session_id,
                    "timestamp": datetime.utcnow()
                })

                # Send the fallback response to the client
                await websocket.send_json({"message_chunk": fallback_message})
                await websocket.send_json({"message_complete": True})
                continue

            # Retrieve conversation history for the session
            context = await db.messages.find({"session_id": session_id}).to_list(length=10)  # Limit to last 10 messages
            conversation_history = [
                {"role": "user" if msg["sender"] == "user" else "assistant", "content": msg["message"]}
                for msg in context
            ]

            # Generate a response from the AI model with conversation history
            full_context = "\n".join([f"{msg['role']}: {msg['content']}" for msg in conversation_history])
            prompt = f"Based on the following conversation, respond to the user's last message:\n{full_context}\nUser: {user_message}\nAssistant:"

            respArr = []
            response = aimodel.generate_content(prompt, stream=True)
            for chunk in response:
                respArr.append(chunk.text)
                await websocket.send_json({"message_chunk": chunk.text})

            # End of response, signal completion
            await websocket.send_json({"message_complete": True})

            full_response = "".join(respArr)

            # Save assistant's response to the database
            await db.messages.insert_one({
                "sender": "assistant",
                "message": full_response,
                "session_id": session_id,
                "timestamp": datetime.utcnow()
            })

    except WebSocketDisconnect:
        print("WebSocket disconnected")
    except HTTPException as e:
        await websocket.close(code=1008, reason=str(e))



@app.get("/sessions")
async def get_sessions(token: str = Depends(oauth2_scheme)):
    try:
        payload = verify_token(token)
        username = payload.get("sub")
        print(f"Payload: {payload}, Token: {token}")

        sessions = await db.sessions.find({"username": username}).to_list(length=100)
        print(f"Sessions retrieved: {sessions}")

        if not sessions:
            raise HTTPException(status_code=404, detail="No sessions found for this user")

        sessions_response = [{"session_id": session.get("session_id"), "session_name": session.get("session_name")} for session in sessions if "session_id" in session]

        return {"sessions": sessions_response}

    except HTTPException as e:
        raise e
    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")


@app.post("/sessions")
async def create_session(token: str = Depends(oauth2_scheme)):
    try:
        payload = verify_token(token)
        username = payload.get("sub")

        if not username:
            raise HTTPException(status_code=400, detail="Invalid token payload: missing username")

        session_id = str(uuid.uuid4())

        await db.sessions.insert_one({"username": username, "session_id": session_id})
        logger.info(f"Session created for user: {username}, session ID: {session_id}")

        return {"session_id": session_id}

    except HTTPException as e:
        logger.error(f"HTTPException in POST /sessions: {e.detail}")
        raise e

    except Exception as e:
        logger.exception("Unexpected error while creating a session")
        raise HTTPException(status_code=500, detail="Internal server error")



@app.get("/messages")
async def get_messages(session_id: str, limit: int = 100, token: str = Depends(oauth2_scheme)):
    try:
        payload = verify_token(token)
        username = payload.get("sub")

        session = await db.sessions.find_one({"session_id": session_id, "username": username})
        if not session:
            raise HTTPException(status_code=404, detail="Session not found or does not belong to the user")

        messages = (
            await db.messages.find({"session_id": session_id})
            .sort("timestamp", 1)  # Sort by timestamp in ascending order
            .limit(limit)
            .to_list(length=limit)
        )
        if not messages:
            return {"messages":[]}

        return {"messages": objectid_to_str(messages)}

    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))



def verify_token(token: str):
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=["HS256"])
        return payload
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")


@app.get("/")
async def root():
    return {"message": "Welcome to the AI Teacher for JavaScript!"}
