from flask import Flask, request, render_template_string
from django.utils.safestring import mark_safe

app = Flask(__name__)

# 1. render_template_string with user input - VULNERABLE
@app.route('/greet')
def greet_user():
    name = request.args.get('name', '')
    template = f"<html><body><h1>Hello, {name}!</h1></body></html>"
    return render_template_string(template)  # XSS vulnerability

# 2. Direct HTML response with user input - VULNERABLE
@app.route('/profile')
def show_profile():
    username = request.args.get('username', '')
    bio = request.args.get('bio', '')
    html = f"<div class='profile'><h2>{username}</h2><p>{bio}</p></div>"
    return html  # XSS vulnerability - unescaped user input

# 3. mark_safe with user input (Django) - VULNERABLE
def render_user_content(user_input):
    return mark_safe(user_input)  # XSS vulnerability

# 4. String formatting in HTML response - VULNERABLE
@app.route('/search')
def search_results():
    query = request.args.get('q', '')
    response = "<html><body><h1>Results for: " + query + "</h1></body></html>"
    return response  # XSS vulnerability

# 5. Template with |safe filter misuse - VULNERABLE
# In template: {{ user_comment | safe }}
def get_unsafe_comment(comment):
    # This would be passed to template with |safe filter
    return comment  # Intended to be used with |safe - VULNERABLE

# 6. JSON response with HTML content - VULNERABLE
@app.route('/api/message')
def api_message():
    message = request.args.get('msg', '')
    return f'{{"html": "<div>{message}</div>"}}'  # XSS in JSON
