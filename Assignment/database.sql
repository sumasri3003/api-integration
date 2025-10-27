use version;

CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100),
    password VARCHAR(100) NOT NULL
);

CREATE TABLE user_roles (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50),
    role_name VARCHAR(50),
    FOREIGN KEY (username) REFERENCES users(username)
);

INSERT INTO users (username, email, password)
VALUES 
('suma', 'suma@gmail.com', 'sumapass'),
('shiva', 'shiva@gmail.com', 'shivapass'),
('sairam', 'sairam@gmail.com', 'sairampass' ) ;

INSERT INTO user_roles (username, role_name)
VALUES 
('suma', 'user'),
('shiva', 'user'),
('sairam', 'admin'),
('suma' ,'user'),
('shiva', 'admin');

UPDATE user_roles SET username = 'SAIRAM' WHERE username = 'sairam';
select * from users;
select * from user_roles;
