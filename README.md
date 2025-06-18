# 🚀 Real-Time Chat Application 💬

[![Flask](https://img.shields.io/badge/Flask-000000?style=for-the-badge&logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![Socket.IO](https://img.shields.io/badge/Socket.IO-010101?style=for-the-badge&logo=socket.io&logoColor=white)](https://socket.io/)
[![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![JavaScript](https://img.shields.io/badge/JavaScript-F7DF1E?style=for-the-badge&logo=javascript&logoColor=black)](https://developer.mozilla.org/en-US/docs/Web/JavaScript)
[![HTML5](https://img.shields.io/badge/HTML5-E34F26?style=for-the-badge&logo=html5&logoColor=white)](https://developer.mozilla.org/en-US/docs/Web/Guide/HTML/HTML5)
[![CSS3](https://img.shields.io/badge/CSS3-1572B6?style=for-the-badge&logo=css3&logoColor=white)](https://developer.mozilla.org/en-US/docs/Web/CSS)

Welcome to the Real-Time Chat Application! This project is a dynamic and interactive chat platform built with Python, Flask, and Socket.IO, allowing users to communicate seamlessly in real-time.

## ✨ Features

*   **Real-Time Messaging:** Instant message delivery and updates using WebSockets.
*   **User Authentication:** Secure registration and login system.
*   **User Profiles:** Customizable user profiles with names and profile pictures.
*   **Profile Photo Uploads:** Users can upload their profile pictures, hosted via ImgBB.
*   **Online Status:** See which users are currently online or offline.
*   **Last Seen:** Track when users were last active.
*   **Direct Messaging:** Engage in private conversations with other users.
*   **Message Read Status:** Know when your messages have been read by the recipient.
*   **Delete Messages:** Users can delete their own messages.
*   **Clear Chat:** Option to clear entire chat history with a user.
*   **User Search:** Easily find and connect with other users.
*   **Chat Media Uploads:** Share images (PNG, JPG, GIF, WebP, HEIC/HEIF), audio (MP3, WAV, OGG, M4A), video (MP4, WebM, MOV, AVI), documents (PDF, DOC/X, TXT, XLS/X, PPT/X), and archives (ZIP, RAR) directly in chats. Media is stored locally.
*   **WebRTC Voice Call Signaling:** Server-side signaling support for 1-on-1 WebRTC voice calls (client-side WebRTC implementation required for full call functionality).
*   **JSON Data Backup:** Automatic backup of `users.json` and `messages.json` before each save operation to prevent accidental data loss.
*   **Responsive Design:** A clean and user-friendly interface that works on various devices.

## 🛠️ Technologies Used

*   **Backend:**
    *   Python
    *   Flask (for web framework and routing)
    *   Flask-SocketIO (for real-time communication)
    *   Werkzeug (for password hashing and utility functions)
    *   Gevent (as a concurrent networking library for SocketIO)
*   **Frontend:**
    *   HTML5
    *   CSS3
    *   JavaScript (Vanilla JS for client-side interactions)
*   **Data Storage:**
    *   JSON files (for storing user and message data, with automatic backup mechanism)
*   **File Handling:**
    *   Local storage for chat media uploads.
    *   Configurable allowed file extensions for profile pictures (PNG, JPG, JPEG, GIF, WebP, HEIC, HEIF) and chat media.
    *   Maximum file upload size (16MB).
*   **External Services:**
    *   ImgBB (for hosting profile picture uploads)

## ⚙️ Setup and Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/chamika1/chat_app.git
    cd chat_app
    ```

2.  **Create a virtual environment (recommended):**
    ```bash
    python -m venv venv
    ```
    *   On Windows:
        ```bash
        venv\Scripts\activate
        ```
    *   On macOS/Linux:
        ```bash
        source venv/bin/activate
        ```

3.  **Install the dependencies:**
    ```bash
    pip install -r requirements.txt
    ```
    The `requirements.txt` file includes:
    ```
    Flask==2.3.3
    Flask-SocketIO==5.3.6
    python-engineio==4.7.1
    python-socketio==5.9.0
    Werkzeug==2.3.7
    gevent==23.9.1
    gevent-websocket==0.10.1
    requests
    ```

4.  **ImgBB API Key:**
    This application uses ImgBB to host profile pictures. You'll need to get your own API key from [ImgBB](https://api.imgbb.com/).
    Once you have your key, open `app.py` and replace `'YOUR_IMGBB_API_KEY_HERE'` with your actual key:
    ```python
    # ImgBB API Key
    IMGBB_API_KEY = 'API_KEY' # Replace with your key 
    ```
    *(The provided key in the source might be a placeholder or a test key. It's best practice to use your own.)*

## ▶️ How to Run the Application

1.  Ensure you have completed the setup steps above.
2.  Run the Flask application:
    ```bash
    python app.py
    ```
3.  Open your web browser and navigate to:
    ```
    http://localhost:5010
    ```
    (The port was recently updated to 5010. If you encounter issues, double-check the `if __name__ == '__main__':` block in `app.py` for the correct port.)

## 🤝 Contributing

Contributions, issues, and feature requests are welcome! Feel free to check the [issues page](https://github.com/chamika1/chat_app/issues).

## 📝 License

This project is open source. Feel free to use and modify it.

---

Thank you for checking out the Real-Time Chat Application! Connect and chat away! 🎉
