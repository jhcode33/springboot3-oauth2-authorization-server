# CREATE DATABASE IF NOT EXISTS authorizaion;
# USE authorizaion;

CREATE USER 'auth'@'localhost' IDENTIFIED BY 'auth';
CREATE USER 'auth'@'%' IDENTIFIED BY '1234';

GRANT ALL PRIVILEGES ON *.* TO 'auth'@'localhost';
GRANT ALL PRIVILEGES ON *.* TO 'auth'@'%';

CREATE DATABASE authorization DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;