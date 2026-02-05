from flask import app, render_template, request
import json
import base64

@app.route('/serialize', methods=['POST'])
def serialize_data():
    username = request.form.get('username', 'guest')
    user = {"username": username, "is_admin": False}
    serialized = base64.b64encode(json.dumps(user).encode()).decode()
    return render_template('result.html', serialized=serialized)


@app.route('/deserialize', methods=['POST'])
def deserialize_data():
    try:
        serialized_data = request.form.get('serialized_data', '')
        decoded_data = base64.b64decode(serialized_data)
        user_data = json.loads(decoded_data)

        username = user_data.get('username', 'guest')
        is_admin = user_data.get('is_admin', False)

        if is_admin:
            message = f"Welcome Admin {username}! Here's the secret admin content: ADMIN_KEY_123"
        else:
            message = f"Welcome {username}. Only admins can see the secret content."

        return render_template('result.html', message=message)
    except Exception as e:
        return render_template('result.html', message=f"Error: {str(e)}")