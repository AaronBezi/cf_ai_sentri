const mysql = require('mysql');

function getUserById(userId) {
  // Vulnerable: String concatenation
  const connection = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'password',
    database: 'users'
  });

  const query = "SELECT * FROM users WHERE id = '" + userId + "'";
  connection.query(query, (error, results) => {
    console.log(results);
  });
}

function loginUser(username, password) {
  // Vulnerable: Template literal
  const connection = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'password',
    database: 'users'
  });

  const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
  connection.query(query, (error, results) => {
    console.log(results);
  });
}

async function searchUsers(searchTerm) {
  // Vulnerable: String interpolation
  const query = "SELECT * FROM users WHERE name LIKE '%" + searchTerm + "%'";
  return await db.query(query);
}
