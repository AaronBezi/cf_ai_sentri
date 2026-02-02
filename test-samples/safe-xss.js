// Safe XSS-Protected Examples in JavaScript

// 1. textContent instead of innerHTML - SAFE
function displayUserCommentSafe(comment) {
  const container = document.getElementById('comments');
  container.textContent = comment; // Safe - text is escaped
}

// 2. createElement and appendChild - SAFE
function createUserElementSafe(username) {
  const h1 = document.createElement('h1');
  h1.textContent = 'Welcome, ' + username + '!';
  document.body.appendChild(h1); // Safe - uses DOM methods
}

// 3. DOMPurify for sanitization - SAFE
function displaySanitizedContent(userContent) {
  const container = document.getElementById('content-area');
  container.innerHTML = DOMPurify.sanitize(userContent); // Safe - sanitized
}

// 4. jQuery .text() instead of .html() - SAFE
function updateContentSafe(userContent) {
  $('#content-area').text(userContent); // Safe - text is escaped
}

// 5. React with proper escaping - SAFE
function UserBioSafe({ bio }) {
  return (
    <div>{bio}</div> // Safe - React auto-escapes by default
  );
}

// 6. innerText instead of innerHTML - SAFE
function displayMessageSafe(message) {
  document.getElementById('message').innerText = message; // Safe
}

// 7. setAttribute for data - SAFE
function setUserData(element, userData) {
  element.setAttribute('data-user', userData); // Safe for attribute
  element.textContent = userData; // Safe for content
}

// 8. Template literal with encoding - SAFE
function encodeAndDisplay(input) {
  const encoded = encodeURIComponent(input);
  const safe = document.createTextNode(input);
  document.getElementById('output').appendChild(safe); // Safe
}
