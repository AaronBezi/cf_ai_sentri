// Vulnerable XSS Examples in JavaScript

// 1. innerHTML with user input - VULNERABLE
function displayUserComment(comment) {
  const container = document.getElementById('comments');
  container.innerHTML = comment; // XSS vulnerability
}

// 2. document.write with user input - VULNERABLE
function writeWelcomeMessage(username) {
  document.write('<h1>Welcome, ' + username + '!</h1>'); // XSS vulnerability
}

// 3. eval with user input - VULNERABLE
function executeUserCode(userCode) {
  eval(userCode); // XSS/Code injection vulnerability
}

// 4. jQuery .html() with user input - VULNERABLE
function updateContent(userContent) {
  $('#content-area').html(userContent); // XSS vulnerability
}

// 5. dangerouslySetInnerHTML in React - VULNERABLE
function UserBio({ bio }) {
  return (
    <div dangerouslySetInnerHTML={{ __html: bio }} /> // XSS vulnerability
  );
}

// 6. outerHTML with user input - VULNERABLE
function replaceElement(elementId, userHtml) {
  document.getElementById(elementId).outerHTML = userHtml; // XSS vulnerability
}

// 7. insertAdjacentHTML with user input - VULNERABLE
function appendUserContent(content) {
  const container = document.getElementById('container');
  container.insertAdjacentHTML('beforeend', content); // XSS vulnerability
}

// 8. String concatenation for HTML - VULNERABLE
function createUserCard(name, bio) {
  const html = '<div class="card"><h2>' + name + '</h2><p>' + bio + '</p></div>';
  document.body.innerHTML += html; // XSS vulnerability
}
