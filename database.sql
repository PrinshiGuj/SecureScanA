CREATE DATABASE securescana;
USE securescana;

CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role ENUM('admin', 'user') DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE scans (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    target_url VARCHAR(500) NOT NULL,
    target_type ENUM('web', 'mobile', 'network') NOT NULL,
    status ENUM('pending', 'running', 'completed', 'failed') DEFAULT 'pending',
    progress INT DEFAULT 0,
    risk_score FLOAT DEFAULT 0,
    total_vulns INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE vulnerabilities (
    id INT AUTO_INCREMENT PRIMARY KEY,
    scan_id INT,
    name VARCHAR(200) NOT NULL,
    description TEXT,
    severity ENUM('Low', 'Medium', 'High', 'Critical') NOT NULL,
    cvss_score FLOAT,
    category VARCHAR(100),
    proof TEXT,
    recommendation TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);

CREATE TABLE reports (
    id INT AUTO_INCREMENT PRIMARY KEY,
    scan_id INT,
    file_path VARCHAR(500),
    generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);