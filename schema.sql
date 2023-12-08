--CREATE TABLE users (
   -- id INTEGER PRIMARY KEY AUTOINCREMENT,
   -- username TEXT NOT NULL,
    --email TEXT NOT NULL,
  --  password TEXT NOT NULL
--);
--CREATE TABLE password_reset (
    --id INTEGER PRIMARY KEY AUTOINCREMENT,
  --  email TEXT NOT NULL,
    --token TEXT NOT NULL
--);
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    email TEXT NOT NULL,
    password TEXT NOT NULL,
    viewed_topics TEXT,
    test_results TEXT,
    liked_topics TEXT,
       name TEXT, 
        surname TEXT,
       gender TEXT,
    unique_id TEXT NOT NULL,
    remember_token TEXT
);

--PRAGMA foreign_keys=off;

--BEGIN TRANSACTION;

-- Создаем временную таблицу с полем liked_topics
--CREATE TABLE temp_users AS SELECT id, username, email, password, liked_topics FROM users;

-- Удаляем оригинальную таблицу
--DROP TABLE users;

-- Переименовываем временную таблицу обратно в оригинальное имя
--ALTER TABLE temp_users RENAME TO users;

--COMMIT;

--PRAGMA foreign_keys=on;
--PRAGMA table_info(users);