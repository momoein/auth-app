# auth-app 🚀

This is a simple Node.js application for user authentication, featuring a RESTful API and a basic web interface. It's built with Express and uses SQLite for the database, `bcrypt` for password hashing, and `jsonwebtoken` for secure session management via JWTs stored in HTTP-only cookies.

## ✨ Features

- **User Authentication:** Secure sign-up and log-in functionality.
- **Password Hashing:** Passwords are securely hashed with `bcrypt`.
- **JWT-based Sessions:** Uses JSON Web Tokens for stateless authentication.
- **HTTP-only Cookies:** JWTs are stored in secure, HTTP-only cookies to mitigate XSS attacks.
- **CSRF Protection:** Implements `sameSite: "strict"` cookie policy.
- **Basic Rate Limiting:** Protects against brute-force login attempts.
- **In-memory Database:** Uses an in-memory SQLite database for simplicity during development.

---

## 💻 Tech Stack

- **Backend:** Node.js, Express
- **Database:** SQLite3
- **Authentication:** `bcrypt`, `jsonwebtoken`, `express-rate-limit`
- **Testing:** `jest`, `supertest`
- **Frontend:** Plain HTML, CSS, and JavaScript

---

## 🛠️ Installation & Setup

1.  **Clone the repository:**

    ```bash
    git clone <repository-url>
    cd auth-app
    ```

2.  **Install dependencies:**

    ```bash
    npm install
    ```

3.  **Create a `.env` file:**
    Create a `.env` file in the root directory and add the following configuration:
    ```
    PORT=3003
    JWT_SECRET=supersecretkey123
    JWT_EXPIRES_IN=1h
    COOKIE_SECURE=false
    COOKIE_MAX_AGE=3600000 # milliseconds
    ```

---

## 🚀 Running the Application

- **Start in development mode (with nodemon):**

  ```bash
  npm run dev
  ```

  The server will run on `http://localhost:3003`.

- **Start in production mode:**
  ```bash
  npm start
  ```

---

## 📂 Project Structure

```
├── .env
├── .gitignore
├── README.md
├── package-lock.json
├── package.json
├── public/
│   ├── index.html
│   ├── login.html
│   ├── profile.html
│   ├── signup.html
│   └── style.css
└── src/
    ├── app.js       # Main Express application with routes
    ├── app.test.js  # API tests
    ├── db.js        # SQLite database connection and schema
    └── server.js    # Entry point for the server
```
