# 🧠 VivArt API – Backend for Auction & Social Media Platform

VivArt is a web application backend that combines **auction features**, **social posting**, and **user interaction**, built with **Flask** and **MongoDB**. It also integrates with services like **Azure Blob Storage**, **Google OAuth**, **email OTP**, and more.

---

## 🔩 Features

- ✅ User system: Registration, Login with Google OAuth, Secure password hashing with Bcrypt
- 📸 Posting system for products/images
- ⚠️ Auction system with bid tracking (Note: bidding is currently implemented as standard API calls, not real-time)
- 💬 Commenting, following, and notification system
- 🛒 Shopping cart, address handling, and delivery tracking
- 🏦 Bank data management, payout request system
- 📩 Email-based OTP verification for password reset
- ☁️ Image uploading to Azure Blob Storage

---

## 🔧 Tech Stack

- **Backend:** Flask (Python)
- **Database:** MongoDB Atlas (`pymongo`)
- **Authentication:** Google OAuth 2.0, JWT
- **Password Hashing:** Flask-Bcrypt
- **CORS Handling:** `flask_cors`
- **Media Storage:** Azure Blob Storage
- **Email Service:** `smtplib`, `email.message`
- **OTP System:** 6-digit random code

---

## ⚙️ Notes on Real-time Auction Logic

Currently, the auction bidding functionality works via RESTful API calls without real-time push updates. To implement real-time bidding and live updates, integration with technologies like **WebSocket** (e.g., Flask-SocketIO) is recommended in future development.

---

# 🧠 VivArt Frontend – Auction & Social Media Platform

The frontend repository is available here:  
https://github.com/Porramin-Boonnak/vivart

---
