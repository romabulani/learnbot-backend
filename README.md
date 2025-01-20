# JavaScript AI Teacher - Backend

## Overview

This backend serves as the API for the LearnBot application. It allows users to interact with an AI teacher that is an expert in JavaScript. The backend is responsible for handling user authentication, storing chat sessions, managing context, and interfacing with an AI model (Google GenAI) to generate responses for the user.

This backend uses **FastAPI** for the web framework, **WebSocket** for real-time communication, and **MongoDB** for data storage.

---

## Features

- **User Authentication** (Sign-up & Login)
- **Real-Time Chat** using WebSocket
- **Session Management** (Keep track of each user’s session)
- **Message History** (Save and retrieve past messages and sessions)
- **Contextual Memory** (Remembers past conversations for more relevant responses)
- **Google GenAI Integration** (Used for generating AI responses)
- **Database** (MongoDB to store user data, messages, and sessions)

---

## API Endpoints

- **POST /signup**  
- **POST /login**  
- **GET /sessions**
- **POST /sessions**
- **GET /messages**

---

## WebSocket Endpoint
The WebSocket connection allows real-time communication between the user and the JavaScript AI teacher. It maintains context during the conversation.

---

## Database
This backend uses MongoDB to store the following:

- User data: Username, hashed password.
- Session data: User's chat sessions.
- Messages: Messages exchanged between the user and the AI.

--- 
### Installation and Setup

- Clone the repository
    ```
    git clone https://github.com/romabulani/learnbot-backend
    cd learnbot-backend
    ```
- Create a virtual environment:
    ```
    python3 -m venv venv
    source venv/bin/activate  # For Linux/Mac
    venv\Scripts\activate     # For Windows
    ```
- Install dependencies:
    ```
    pip install -r requirements.txt
    ```
- Configure MongoDB:

    Set up a MongoDB instance (locally or use a cloud provider like MongoDB Atlas).
    Update the connection string and other creds in the .env file.
- Start the FastAPI app:
    ```
    uvicorn main:app --reload
    ```

---
## Deployment

This backend is deployed on the Render.com Free Tier, which may sometimes experience downtime due to traffic limitations. Please note that during peak periods or when free-tier resource limits are reached, the service may be temporarily unavailable.

You can view the live deployment [here](https://learnbot-backend.onrender.com/)

---

## License
This project is licensed under the MIT License.
