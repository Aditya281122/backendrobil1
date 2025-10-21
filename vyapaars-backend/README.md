# Vyapaars Backend

This is the backend server for the Vyapaars offline-first Android POS application. It is built with Python and FastAPI, designed to be lightweight, secure, and easy to deploy.

---

## Features

This backend provides the central services required by the Vyapaars mobile app, following a robust, offline-first architecture.

- **Secure User Authentication**: Full registration, phone verification (OTP), and login system using JWT (JSON Web Tokens).
- **User-Wise Offline Sync**: A core `/api/v1/sync/batch` endpoint that allows the Android app to send batches of offline-recorded data (like sales and inventory changes). The data is stored per-user.
- **Idempotent Processing**: Ensures that the same data packet sent multiple times (due to network issues) is only processed once.
- **Remote Product Catalog Management**: The `products.csv` file can be updated via an admin endpoint. The app can then download the latest version, allowing for remote management of the product list.
- **Remote Feature Flags**: A system to remotely enable or disable features in the Android app without requiring an app update.
- **Protected Endpoints**: All data-sensitive endpoints are protected and require a valid user authentication token.

---

## Local Setup & Development

Follow these steps to run the backend server on your local machine for development and testing.

### 1. Prerequisites

- [Python 3.8+](https://www.python.org/downloads/)
- `pip` (Python package installer)

### 2. Create a Virtual Environment

It is highly recommended to use a virtual environment to manage project dependencies.

```bash
# Navigate to the vyapaars-backend directory
cd vyapaars-backend

# Create a virtual environment
python -m venv venv

# Activate the virtual environment
# On Windows:
.\venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate
```

### 3. Install Dependencies

Install all the required Python libraries from the `requirements.txt` file.

```bash
pip install -r requirements.txt
```

### 4. Run the Server

With the dependencies installed, you can start the development server.

```bash
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

- `--host 0.0.0.0`: Makes the server accessible on your local network (e.g., from your physical Android device).
- `--reload`: The server will automatically restart when you make changes to the code.

Your backend is now running at `http://localhost:8000`.

---

## Deployment to Render

This project is pre-configured for easy deployment on [Render](https://render.com/).

### Step 1: Push to GitHub

Make sure your `vyapaars-backend` folder is part of a GitHub repository and that you have pushed all the files (`main.py`, `requirements.txt`, `README.md`).

### Step 2: Create a New Web Service on Render

1.  Log in to your Render dashboard.
2.  Click **New +** and select **Web Service**.
3.  Connect your GitHub account and select your repository.
4.  On the settings page, fill in the following:

    - **Name**: `vyapaars-backend` (or your preferred name).
    - **Root Directory**: `vyapaars-backend` (if your repo has other folders).
    - **Environment**: `Python 3`
    - **Region**: Choose a region close to you.
    - **Build Command**: `pip install -r requirements.txt`
    - **Start Command**: `uvicorn main:app --host 0.0.0.0 --port $PORT`

    *Note: Render automatically sets the `$PORT` environment variable, so using it in the start command is essential.*

### Step 3: Add Environment Variables

For security, you should set a unique `SECRET_KEY` for your production environment.

1.  In your service settings on Render, go to the **Environment** tab.
2.  Click **Add Environment Variable**.
3.  Set the following:
    - **Key**: `SECRET_KEY`
    - **Value**: `your_super_secret_and_long_random_string_here`

    *(Generate a strong, random string for this value).* 

### Step 4: Deploy

Click **Create Web Service**. Render will automatically pull your code from GitHub, build it, and deploy it. Your backend will be live at the URL provided by Render (e.g., `https://vyapaars-backend.onrender.com`).

---

## API Endpoints Overview

- `GET /`: Health check.
- `POST /api/v1/register`: User registration.
- `POST /api/v1/verify`: Verify phone number with OTP.
- `POST /api/v1/login`: Log in to get a JWT token.
- `POST /api/v1/sync/batch`: (Protected) Sync offline data from the app.
- `GET /api/v1/assets/products/meta`: (Protected) Get metadata for the products CSV.
- `GET /api/v1/assets/products.csv`: (Protected) Download the products CSV.
- `GET /api/v1/config/flags`: (Protected) Get feature flags for the app.

### Admin Endpoints (For Manual Use)

- `POST /api/v1/admin/assets/upload/products`: Upload a new `products.csv`.
- `PUT /api/v1/admin/config/flags`: Update the feature flags.
