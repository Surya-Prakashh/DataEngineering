"""
Malware Analysis Dashboard - Main Flask Application Entry Point
Modular registration of Phase 1, Phase 2, and Phase 3 Blueprints.
"""

from flask import Flask, render_template
from phase1 import phase1_bp
from phase2 import phase2_bp
from phase3 import phase3_bp
from phase4 import phase4_bp
from pipeline import pipeline_bp

app = Flask(__name__)
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0

@app.after_request
def add_header(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

# Register Blueprints for Phase 1, Phase 2, Phase 3, Phase 4, and E2E Pipeline
app.register_blueprint(phase1_bp)
app.register_blueprint(phase2_bp)
app.register_blueprint(phase3_bp)
app.register_blueprint(phase4_bp)
app.register_blueprint(pipeline_bp)

@app.route("/")
def index():
    return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=True, port=5000)
